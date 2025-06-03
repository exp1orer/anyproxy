package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// Gateway represents the proxy gateway server
type Gateway struct {
	config         *config.GatewayConfig
	httpServer     *http.Server
	proxies        []GatewayProxy // Support multiple proxies
	upgrader       websocket.Upgrader
	clientsMu      sync.RWMutex
	clients        map[string]*ClientConn
	groups         map[string]map[string]struct{}
	portForwardMgr *PortForwardManager
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewGateway creates a new proxy gateway
func NewGateway(cfg *config.Config) (*Gateway, error) {
	slog.Info("Creating new gateway",
		"listen_addr", cfg.Gateway.ListenAddr,
		"http_proxy_enabled", cfg.Proxy.HTTP.ListenAddr != "",
		"socks5_proxy_enabled", cfg.Proxy.SOCKS5.ListenAddr != "",
		"tls_cert", cfg.Gateway.TLSCert,
		"auth_enabled", cfg.Gateway.AuthUsername != "")

	ctx, cancel := context.WithCancel(context.Background())
	gateway := &Gateway{
		config:         &cfg.Gateway,
		clients:        make(map[string]*ClientConn),
		groups:         make(map[string]map[string]struct{}),
		portForwardMgr: NewPortForwardManager(),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		ctx:    ctx,
		cancel: cancel,
	}
	// Init the default group
	gateway.groups[""] = make(map[string]struct{})
	slog.Debug("Initialized default group for gateway")

	// Create a custom dial function that uses WebSocket connections
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract user context from context if available
		var groupID string
		if userCtx, ok := ctx.Value("user").(*UserContext); ok {
			slog.Debug("Dial function received user context",
				"group_id", userCtx.GroupID,
				"network", network,
				"address", addr)
			groupID = userCtx.GroupID
		} else {
			slog.Debug("Dial function using default group",
				"network", network,
				"address", addr)
		}

		// Get a client from the specified group
		client, err := gateway.getClientByGroup(groupID)
		if err != nil {
			slog.Error("Failed to get client by group for dial",
				"group_id", groupID,
				"network", network,
				"address", addr,
				"error", err)
			return nil, err
		}
		slog.Debug("Successfully selected client for dial",
			"client_id", client.ID,
			"group_id", groupID,
			"network", network,
			"address", addr)
		return client.dialNetwork(network, addr)
	}

	// Create proxy instances based on configuration
	var proxies []GatewayProxy

	// Create HTTP proxy if configured
	if cfg.Proxy.HTTP.ListenAddr != "" {
		slog.Info("Configuring HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
		httpProxy, err := NewHTTPProxyWithAuth(&cfg.Proxy.HTTP, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			slog.Error("Failed to create HTTP proxy",
				"listen_addr", cfg.Proxy.HTTP.ListenAddr,
				"error", err)
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		proxies = append(proxies, httpProxy)
		slog.Info("HTTP proxy configured successfully", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
	}

	// Create SOCKS5 proxy if configured
	if cfg.Proxy.SOCKS5.ListenAddr != "" {
		slog.Info("Configuring SOCKS5 proxy", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
		socks5Proxy, err := NewSOCKS5ProxyWithAuth(&cfg.Proxy.SOCKS5, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			slog.Error("Failed to create SOCKS5 proxy",
				"listen_addr", cfg.Proxy.SOCKS5.ListenAddr,
				"error", err)
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %v", err)
		}
		proxies = append(proxies, socks5Proxy)
		slog.Info("SOCKS5 proxy configured successfully", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
	}

	// Ensure at least one proxy is configured
	if len(proxies) == 0 {
		slog.Error("No proxy configured - at least one proxy type must be enabled",
			"http_addr", cfg.Proxy.HTTP.ListenAddr,
			"socks5_addr", cfg.Proxy.SOCKS5.ListenAddr)
		return nil, fmt.Errorf("no proxy configured: please configure at least one of HTTP or SOCKS5 proxy")
	}

	gateway.proxies = proxies
	slog.Info("Gateway created successfully",
		"proxy_count", len(proxies),
		"listen_addr", cfg.Gateway.ListenAddr)

	return gateway, nil
}

// extractGroupFromUsername extracts group ID from username
// Expected format: username.group-id or just username (uses default group)
func (g *Gateway) extractGroupFromUsername(username string) string {
	slog.Info("extractGroupFromUsername", "username", username)
	// Use dot as delimiter to support UUID group-ids that may contain hyphens
	parts := strings.Split(username, ".")
	if len(parts) >= 2 {
		// Join all parts after the first one as group-id (in case group-id contains dots)
		return strings.Join(parts[1:], ".")
	}
	return "" // Default group
}

// extractBaseUsername extracts the base username (without group-id) from a group-enabled username
// Expected format: username.group-id or just username
// Returns: base username for authentication
func extractBaseUsername(username string) string {
	parts := strings.Split(username, ".")
	if len(parts) >= 1 {
		return parts[0] // Return base username part
	}
	return username // Fallback to original username
}

// Start starts the gateway
func (g *Gateway) Start() error {
	slog.Info("Starting gateway server",
		"listen_addr", g.config.ListenAddr,
		"proxy_count", len(g.proxies))

	startTime := time.Now()

	// Start the HTTP server for WebSocket connections
	slog.Info("Starting WebSocket server for client connections")
	if err := g.startHTTPServer(); err != nil {
		slog.Error("Failed to start WebSocket server",
			"listen_addr", g.config.ListenAddr,
			"error", err)
		return err
	}
	slog.Info("WebSocket server started successfully", "listen_addr", g.config.ListenAddr)

	// Start all proxy servers
	slog.Info("Starting proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		slog.Debug("Starting proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Start(); err != nil {
			slog.Error("Failed to start proxy server",
				"index", i,
				"type", fmt.Sprintf("%T", proxy),
				"error", err)
			// If any proxy fails to start, stop the ones that already started
			slog.Warn("Stopping previously started proxies due to failure", "stopping_count", i)
			for j := 0; j < i; j++ {
				if stopErr := g.proxies[j].Stop(); stopErr != nil {
					slog.Error("Failed to stop proxy during cleanup", "index", j, "error", stopErr)
				}
			}
			return fmt.Errorf("failed to start proxy %d: %v", i, err)
		}
		slog.Debug("Proxy server started successfully", "index", i, "type", fmt.Sprintf("%T", proxy))
	}

	elapsed := time.Since(startTime)
	slog.Info("Gateway started successfully",
		"startup_duration", elapsed,
		"websocket_addr", g.config.ListenAddr,
		"proxy_count", len(g.proxies))

	return nil
}

// startHTTPServer starts the HTTP server for WebSocket connections
func (g *Gateway) startHTTPServer() error {
	slog.Debug("Loading TLS certificates",
		"cert_file", g.config.TLSCert,
		"key_file", g.config.TLSKey)

	// Load TLS certificate and key
	cert, err := tls.LoadX509KeyPair(g.config.TLSCert, g.config.TLSKey)
	if err != nil {
		slog.Error("Failed to load TLS certificate",
			"cert_file", g.config.TLSCert,
			"key_file", g.config.TLSKey,
			"error", err)
		return fmt.Errorf("failed to load TLS certificate: %v", err)
	}
	slog.Debug("TLS certificates loaded successfully")

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	slog.Debug("TLS configuration created", "min_version", "TLS 1.2")

	// Create HTTP server for WebSocket connections
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", g.handleWebSocket)

	g.httpServer = &http.Server{
		Addr:      g.config.ListenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}
	slog.Debug("HTTP server configured for WebSocket connections")

	// Start HTTP server in a separate goroutine
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		slog.Info("Starting HTTPS server for WebSocket connections", "listen_addr", g.config.ListenAddr)
		if err := g.httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			slog.Error("HTTPS server terminated unexpectedly",
				"listen_addr", g.config.ListenAddr,
				"error", err)
			os.Exit(1)
		}
		slog.Info("HTTPS server stopped")
	}()

	return nil
}

// Stop stops the gateway gracefully with context-based coordination
func (g *Gateway) Stop() error {
	slog.Info("Initiating graceful gateway shutdown...")
	stopTime := time.Now()

	// Step 1: Signal all goroutines to stop
	slog.Debug("Signaling all goroutines to stop")
	g.cancel()

	// Step 2: Stop accepting new connections
	slog.Info("Shutting down HTTPS server")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.httpServer.Shutdown(ctx); err != nil {
		slog.Error("Error shutting down HTTPS server", "error", err)
	} else {
		slog.Info("HTTPS server shutdown completed")
	}

	// Step 3: Stop all proxy servers
	slog.Info("Stopping proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		slog.Debug("Stopping proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Stop(); err != nil {
			slog.Error("Error stopping proxy server",
				"index", i,
				"type", fmt.Sprintf("%T", proxy),
				"error", err)
		} else {
			slog.Debug("Proxy server stopped successfully", "index", i)
		}
	}
	slog.Info("All proxy servers stopped")

	// Step 4: Stop port forwarding manager
	slog.Debug("Stopping port forwarding manager")
	g.portForwardMgr.Stop()
	slog.Debug("Port forwarding manager stopped")

	// Step 5: Give clients time to finish processing (context-aware wait)
	slog.Info("Waiting for clients to finish processing...")
	gracefulWait := func(duration time.Duration) bool {
		select {
		case <-g.ctx.Done():
			return false // Already cancelled
		case <-time.After(duration):
			return true // Wait completed
		}
	}
	if gracefulWait(500 * time.Millisecond) {
		slog.Debug("Client processing wait completed")
	} else {
		slog.Debug("Client processing wait skipped - context cancelled")
	}

	// Step 6: Stop all client connections gracefully
	g.clientsMu.RLock()
	clientCount := len(g.clients)
	g.clientsMu.RUnlock()

	if clientCount > 0 {
		slog.Info("Stopping client connections", "client_count", clientCount)
		g.clientsMu.RLock()
		for clientID, client := range g.clients {
			slog.Debug("Stopping client connection", "client_id", clientID)
			client.Stop()
		}
		g.clientsMu.RUnlock()
		slog.Info("All client connections stopped")
	} else {
		slog.Debug("No active client connections to stop")
	}

	// Step 7: Wait for all goroutines to finish
	slog.Debug("Waiting for all goroutines to finish...")
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("All gateway goroutines finished gracefully")
	case <-time.After(8 * time.Second):
		slog.Warn("Timeout waiting for gateway goroutines to finish")
	}

	elapsed := time.Since(stopTime)
	slog.Info("Gateway shutdown completed",
		"shutdown_duration", elapsed,
		"final_client_count", clientCount)

	return nil
}

// handleWebSocket handles WebSocket connections from clients
func (g *Gateway) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		slog.Warn("WebSocket connection rejected: missing client ID",
			"remote_addr", r.RemoteAddr,
			"user_agent", r.Header.Get("User-Agent"))
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}

	// If the group-id is empty, then the client will be add to the default group
	groupID := r.Header.Get("X-Group-ID")
	slog.Debug("WebSocket connection attempt",
		"client_id", clientID,
		"group_id", groupID,
		"remote_addr", r.RemoteAddr)

	// Authenticate client
	username, password, ok := r.BasicAuth()
	if !ok {
		slog.Warn("WebSocket connection rejected: missing authentication",
			"client_id", clientID,
			"remote_addr", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if username != g.config.AuthUsername || password != g.config.AuthPassword {
		slog.Warn("WebSocket connection rejected: invalid credentials",
			"client_id", clientID,
			"username", username,
			"remote_addr", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	slog.Debug("Client authentication successful", "client_id", clientID)

	// Upgrade HTTP connection to WebSocket
	conn, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade WebSocket connection",
			"client_id", clientID,
			"remote_addr", r.RemoteAddr,
			"error", err)
		return
	}
	slog.Debug("WebSocket connection upgraded successfully", "client_id", clientID)

	// Create WebSocket writer
	writeBuf := make(chan interface{}, writeBufSize)
	writer := NewWebSocketWriter(conn, writeBuf)
	writer.Start()
	slog.Debug("WebSocket writer started", "client_id", clientID)

	// Create client context derived from gateway context
	ctx, cancel := context.WithCancel(g.ctx)

	// Create and register client
	client := &ClientConn{
		ID:             clientID,
		GroupID:        groupID,
		Conn:           conn,
		Writer:         writer,
		writeBuf:       writeBuf,
		Conns:          make(map[string]*Conn),
		msgChans:       make(map[string]chan map[string]interface{}),
		ctx:            ctx,
		cancel:         cancel,
		portForwardMgr: g.portForwardMgr,
	}

	g.addClient(client)
	slog.Info("Client connected and registered",
		"client_id", clientID,
		"group_id", groupID,
		"remote_addr", r.RemoteAddr)

	// Handle incoming messages from the client
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			client.Stop()
			g.removeClient(client.ID)
			slog.Info("Client disconnected and cleaned up",
				"client_id", client.ID,
				"group_id", client.GroupID)
		}()
		client.handleMessage()
	}()
}

// addClient adds a client to the gateway
func (g *Gateway) addClient(client *ClientConn) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	// Check if client already exists
	if existingClient, exists := g.clients[client.ID]; exists {
		slog.Warn("Replacing existing client connection",
			"client_id", client.ID,
			"old_group_id", existingClient.GroupID,
			"new_group_id", client.GroupID)
		// Stop the existing client
		existingClient.Stop()
	}

	g.clients[client.ID] = client
	if _, ok := g.groups[client.GroupID]; !ok {
		g.groups[client.GroupID] = make(map[string]struct{})
		slog.Debug("Created new group", "group_id", client.GroupID)
	}
	g.groups[client.GroupID][client.ID] = struct{}{}

	// Log group statistics
	groupSize := len(g.groups[client.GroupID])
	totalClients := len(g.clients)
	slog.Debug("Client added successfully",
		"client_id", client.ID,
		"group_id", client.GroupID,
		"group_size", groupSize,
		"total_clients", totalClients)
}

// removeClient removes a client from the gateway
func (g *Gateway) removeClient(clientID string) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	client, exists := g.clients[clientID]
	if !exists {
		slog.Debug("Attempted to remove non-existent client", "client_id", clientID)
		return
	}

	groupID := client.GroupID

	// Find and remove client from groups
	for gid, clients := range g.groups {
		if _, exists := clients[clientID]; exists {
			delete(clients, clientID)
			slog.Debug("Removed client from group",
				"client_id", clientID,
				"group_id", gid,
				"remaining_in_group", len(clients))
			break
		}
	}

	// Close all port forwarding for this client
	slog.Debug("Closing port forwarding for client", "client_id", clientID)
	g.portForwardMgr.CloseClientPorts(clientID)

	delete(g.clients, clientID)

	// Log removal statistics
	totalClients := len(g.clients)
	groupSize := 0
	if group, exists := g.groups[groupID]; exists {
		groupSize = len(group)
	}

	slog.Info("Client removed successfully",
		"client_id", clientID,
		"group_id", groupID,
		"group_size", groupSize,
		"total_clients", totalClients)
}

// getRandomClient returns a random available client
func (g *Gateway) getRandomClient() (*ClientConn, error) {
	return g.getClientByGroup("")
}

// getClientByGroup returns a random available client from the specified group
func (g *Gateway) getClientByGroup(groupID string) (*ClientConn, error) {
	g.clientsMu.RLock()
	defer g.clientsMu.RUnlock()

	slog.Debug("Selecting client from group",
		"group_id", groupID,
		"total_groups", len(g.groups))

	// Get clients from the specified group
	clientIDs, exists := g.groups[groupID]
	if !exists || len(clientIDs) == 0 {
		slog.Debug("No clients in specified group, trying default group",
			"requested_group", groupID)
		// If no clients in specified group, try default group
		if groupID != "" {
			clientIDs, exists = g.groups[""]
			if !exists || len(clientIDs) == 0 {
				slog.Warn("No clients available in any group",
					"requested_group", groupID,
					"total_groups", len(g.groups))
				return nil, fmt.Errorf("no clients available in group '%s' or default group", groupID)
			}
			slog.Debug("Using client from default group",
				"requested_group", groupID,
				"default_group_size", len(clientIDs))
		} else {
			slog.Warn("No clients available in default group",
				"total_groups", len(g.groups))
			return nil, fmt.Errorf("no clients available in default group")
		}
	}

	// Return the first available client from the group (simple implementation)
	for clientID := range clientIDs {
		if client, exists := g.clients[clientID]; exists {
			slog.Debug("Selected client for connection",
				"client_id", clientID,
				"group_id", client.GroupID,
				"group_size", len(clientIDs))
			return client, nil
		}
	}

	slog.Error("No valid clients found in group despite having client IDs",
		"group_id", groupID,
		"client_ids_count", len(clientIDs))
	return nil, fmt.Errorf("no clients available in group '%s'", groupID)
}

// ------------------------------------------------------------------------------------------------
// -------------------------------------- ClientConn and ProxyConn --------------------------------
// ------------------------------------------------------------------------------------------------

// ClientConn represents a connected proxy client
type ClientConn struct {
	ID             string
	GroupID        string
	Conn           *websocket.Conn
	Writer         *WebSocketWriter
	writeBuf       chan interface{}
	ConnsMu        sync.RWMutex
	Conns          map[string]*Conn
	msgChans       map[string]chan map[string]interface{} // Message channels per connection
	msgChansMu     sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	stopOnce       sync.Once
	wg             sync.WaitGroup
	portForwardMgr *PortForwardManager // Reference to port forwarding manager
}

// Conn represents a proxied connection
type Conn struct {
	ID        string
	LocalConn net.Conn
	Done      chan struct{}
	once      sync.Once
}

// dialNetwork creates a connection and registers it with the client
func (c *ClientConn) dialNetwork(network, addr string) (net.Conn, error) {
	// Generate connection ID
	connID := xid.New().String()
	slog.Debug("Creating new network connection",
		"client_id", c.ID,
		"conn_id", connID,
		"network", network,
		"address", addr)

	// Create a pipe to connect the client and the proxy
	pipe1, pipe2 := net.Pipe()

	// Create proxy connection
	proxyConn := &Conn{
		ID:        connID,
		Done:      make(chan struct{}),
		LocalConn: pipe2,
	}

	// Register the connection
	c.ConnsMu.Lock()
	c.Conns[connID] = proxyConn
	connCount := len(c.Conns)
	c.ConnsMu.Unlock()

	slog.Debug("Connection registered",
		"client_id", c.ID,
		"conn_id", connID,
		"total_connections", connCount)

	// Send connect request to client
	slog.Info("Sending connect request to client",
		"client_id", c.ID,
		"conn_id", connID,
		"network", network,
		"address", addr)
	err := c.Writer.WriteJSON(map[string]interface{}{
		"type":    "connect",
		"id":      connID,
		"network": network,
		"address": addr,
	})
	if err != nil {
		slog.Error("Failed to send connect request",
			"client_id", c.ID,
			"conn_id", connID,
			"address", addr,
			"error", err)
		// Clean up on failure
		c.closeConnection(connID) // will close pipe2
		return nil, fmt.Errorf("failed to send connect request: %v", err)
	}

	slog.Debug("Connect request sent successfully, returning connection wrapper",
		"client_id", c.ID,
		"conn_id", connID)
	// Return the connection wrapper
	return NewConnWrapper(pipe1, network, addr), nil
}

// Stop gracefully stops the client connection
func (c *ClientConn) Stop() {
	c.stopOnce.Do(func() {
		slog.Info("Initiating graceful client stop", "client_id", c.ID)
		stopStartTime := time.Now()

		// Step 1: Signal all goroutines to stop
		slog.Debug("Cancelling client context", "client_id", c.ID)
		c.cancel()

		// Step 2: Get connection count before cleanup
		c.ConnsMu.RLock()
		connectionCount := len(c.Conns)
		c.ConnsMu.RUnlock()

		if connectionCount > 0 {
			slog.Info("Waiting for active connections to finish",
				"client_id", c.ID,
				"connection_count", connectionCount)
		}

		// Give connections time to finish current operations
		gracefulWait := func(duration time.Duration) {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(duration):
				return
			}
		}
		gracefulWait(500 * time.Millisecond)

		// Step 3: Stop WebSocket writer - this will close the WebSocket connection
		if c.Writer != nil {
			slog.Debug("Stopping WebSocket writer", "client_id", c.ID)
			c.Writer.Stop()
			c.Writer = nil
			slog.Debug("WebSocket writer stopped", "client_id", c.ID)
		}

		// Step 4: Clear the connection reference (already closed by writer)
		c.Conn = nil

		// Step 5: Close all proxy connections
		slog.Debug("Closing all proxy connections",
			"client_id", c.ID,
			"connection_count", connectionCount)
		c.ConnsMu.Lock()
		for connID := range c.Conns {
			c.closeConnectionUnsafe(connID)
		}
		c.ConnsMu.Unlock()
		if connectionCount > 0 {
			slog.Debug("All proxy connections closed", "client_id", c.ID)
		}

		// Step 6: Close all message channels
		c.msgChansMu.Lock()
		channelCount := len(c.msgChans)
		for connID, msgChan := range c.msgChans {
			close(msgChan)
			delete(c.msgChans, connID)
		}
		c.msgChansMu.Unlock()
		if channelCount > 0 {
			slog.Debug("Closed message channels",
				"client_id", c.ID,
				"channel_count", channelCount)
		}

		// Step 7: Wait for all goroutines to finish with timeout
		slog.Debug("Waiting for client goroutines to finish", "client_id", c.ID)
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			slog.Debug("All client goroutines finished gracefully", "client_id", c.ID)
		case <-time.After(2 * time.Second):
			slog.Warn("Timeout waiting for client goroutines to finish", "client_id", c.ID)
		}

		elapsed := time.Since(stopStartTime)
		slog.Info("Client stop completed",
			"client_id", c.ID,
			"stop_duration", elapsed,
			"connections_closed", connectionCount,
			"channels_closed", channelCount)
	})
}

// closeConnection closes a connection and cleans up resources
func (c *ClientConn) closeConnection(connID string) {
	// Atomically remove from client's connection map
	c.ConnsMu.Lock()
	proxyConn, exists := c.Conns[connID]
	if exists {
		delete(c.Conns, connID)
	}
	c.ConnsMu.Unlock()

	// Clean up message channel
	c.msgChansMu.Lock()
	if msgChan, exists := c.msgChans[connID]; exists {
		delete(c.msgChans, connID)
		close(msgChan)
	}
	c.msgChansMu.Unlock()

	// Only proceed with cleanup if the connection existed
	if !exists {
		slog.Debug("Connection already removed", "conn_id", connID, "client_id", c.ID)
		return
	}

	// Signal connection to stop (non-blocking, idempotent)
	select {
	case <-proxyConn.Done:
		// Already closed, continue with cleanup
	default:
		close(proxyConn.Done)
	}

	// Close the actual connection (use sync.Once to ensure only closed once)
	proxyConn.once.Do(func() {
		slog.Debug("Closing local connection", "conn_id", proxyConn.ID)
		if err := proxyConn.LocalConn.Close(); err != nil {
			// Don't log close errors as they're expected during shutdown
			slog.Debug("Connection close error (expected during shutdown)", "conn_id", proxyConn.ID, "error", err)
		}
	})

	slog.Debug("Connection closed and cleaned up", "conn_id", proxyConn.ID, "client_id", c.ID)
}

// handlePortForwardRequest handles port forwarding requests from clients
func (c *ClientConn) handlePortForwardRequest(msg map[string]interface{}) {
	// Extract open ports from the message
	openPortsInterface, ok := msg["open_ports"]
	if !ok {
		slog.Error("No open_ports in port_forward_request", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Missing open_ports field")
		return
	}

	// Convert to []config.OpenPort
	openPortsSlice, ok := openPortsInterface.([]interface{})
	if !ok {
		slog.Error("Invalid open_ports format", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Invalid open_ports format")
		return
	}

	var openPorts []config.OpenPort
	for _, portInterface := range openPortsSlice {
		portMap, ok := portInterface.(map[string]interface{})
		if !ok {
			slog.Error("Invalid port configuration format", "client_id", c.ID)
			continue
		}

		// Extract port configuration
		remotePort, ok := portMap["remote_port"].(float64) // JSON numbers are float64
		if !ok {
			slog.Error("Invalid remote_port", "client_id", c.ID)
			continue
		}

		localPort, ok := portMap["local_port"].(float64)
		if !ok {
			slog.Error("Invalid local_port", "client_id", c.ID)
			continue
		}

		localHost, ok := portMap["local_host"].(string)
		if !ok {
			slog.Error("Invalid local_host", "client_id", c.ID)
			continue
		}

		protocol, ok := portMap["protocol"].(string)
		if !ok {
			protocol = "tcp" // Default to TCP
		}

		openPorts = append(openPorts, config.OpenPort{
			RemotePort: int(remotePort),
			LocalPort:  int(localPort),
			LocalHost:  localHost,
			Protocol:   protocol,
		})
	}

	if len(openPorts) == 0 {
		slog.Info("No valid ports to open", "client_id", c.ID)
		c.sendPortForwardResponse(true, "No ports to open")
		return
	}

	// Attempt to open the ports
	err := c.portForwardMgr.OpenPorts(c, openPorts)
	if err != nil {
		slog.Error("Failed to open ports", "client_id", c.ID, "error", err)
		c.sendPortForwardResponse(false, err.Error())
		return
	}

	slog.Info("Successfully opened ports", "client_id", c.ID, "port_count", len(openPorts))
	c.sendPortForwardResponse(true, "Ports opened successfully")
}

// sendPortForwardResponse sends a response to a port forwarding request
func (c *ClientConn) sendPortForwardResponse(success bool, message string) {
	response := map[string]interface{}{
		"type":    "port_forward_response",
		"success": success,
		"message": message,
	}

	if err := c.Writer.WriteJSON(response); err != nil {
		slog.Error("Failed to send port forward response", "client_id", c.ID, "error", err)
	}
}

// handleMessage processes incoming messages with context awareness
func (c *ClientConn) handleMessage() {
	slog.Debug("Starting message handler for client", "client_id", c.ID)
	messageCount := 0

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Message handler stopping due to context cancellation",
				"client_id", c.ID,
				"messages_processed", messageCount)
			return
		default:
		}

		// Read message from client without artificial timeout
		// Let WebSocket handle its own timeout/keepalive mechanisms
		var msg map[string]interface{}
		err := c.Conn.ReadJSON(&msg)
		if err != nil {
			// Check for WebSocket close errors - don't log unexpected close as error
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Error("Unexpected WebSocket close",
					"client_id", c.ID,
					"messages_processed", messageCount,
					"error", err)
			} else if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Info("WebSocket connection closed normally",
					"client_id", c.ID,
					"messages_processed", messageCount)
			} else {
				slog.Error("WebSocket read error",
					"client_id", c.ID,
					"messages_processed", messageCount,
					"error", err)
			}

			// Connection failed, exit
			return
		}

		messageCount++

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from client - missing or invalid type field",
				"client_id", c.ID,
				"message_count", messageCount,
				"message_fields", gatewayGetMessageFields(msg))
			continue
		}

		// Log message processing (but not for high-frequency data messages)
		if msgType != "data" {
			slog.Debug("Processing message",
				"client_id", c.ID,
				"message_type", msgType,
				"message_count", messageCount)
		}

		switch msgType {
		case "connect_response", "data", "close":
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		case "port_forward_request":
			// Handle port forwarding request directly
			slog.Info("Received port forwarding request", "client_id", c.ID)
			c.handlePortForwardRequest(msg)
		default:
			slog.Warn("Unknown message type received",
				"client_id", c.ID,
				"message_type", msgType,
				"message_count", messageCount)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel with context awareness
func (c *ClientConn) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message - missing or wrong type",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// For connect_response messages, create the channel first if needed
	if msgType == "connect_response" {
		slog.Debug("Creating message channel for connect response",
			"client_id", c.ID,
			"conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// Connection doesn't exist, ignore message
		slog.Debug("Ignoring message for non-existent connection",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
		return
	}

	// Send message to connection's channel (non-blocking with context awareness)
	select {
	case msgChan <- msg:
		// Successfully routed, don't log for high-frequency data messages
		if msgType != "data" {
			slog.Debug("Message routed successfully",
				"client_id", c.ID,
				"conn_id", connID,
				"message_type", msgType)
		}
	case <-c.ctx.Done():
		slog.Debug("Message routing cancelled due to context",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
		return
	default:
		slog.Warn("Message channel full for connection",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
	}
}

// createMessageChannel creates a message channel for a connection
func (c *ClientConn) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// Check if channel already exists
	if _, exists := c.msgChans[connID]; exists {
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // Buffer for 100 messages
	c.msgChans[connID] = msgChan

	// Start message processor for this connection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages processes messages for a specific connection in order with context awareness
func (c *ClientConn) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}

			msgType, _ := msg["type"].(string)
			switch msgType {
			case "connect_response":
				c.handleConnectResponseMessage(msg)
			case "data":
				c.handleDataMessage(msg)
			case "close":
				c.handleCloseMessage(msg)
				return // Connection closed, stop processing
			}
		}
	}
}

// handleDataMessage processes data messages from clients
func (c *ClientConn) handleDataMessage(msg map[string]interface{}) {
	// Extract connection ID and data
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in data message",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	// WebSocket JSON messages encode binary data as base64 string
	dataStr, ok := msg["data"].(string)
	if !ok {
		slog.Error("Invalid data format in data message",
			"client_id", c.ID,
			"conn_id", connID,
			"data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data",
			"client_id", c.ID,
			"conn_id", connID,
			"data_length", len(dataStr),
			"error", err)
		return
	}

	// Only log for larger transfers to reduce noise
	if len(data) > 10000 {
		slog.Debug("Gateway received large data chunk",
			"client_id", c.ID,
			"conn_id", connID,
			"bytes", len(data))
	}

	// Get the connection safely
	c.ConnsMu.RLock()
	proxyConn, ok := c.Conns[connID]
	c.ConnsMu.RUnlock()
	if !ok {
		slog.Warn("Data message for unknown connection",
			"client_id", c.ID,
			"conn_id", connID,
			"data_bytes", len(data))
		return
	}

	// Write data to the local connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	proxyConn.LocalConn.SetWriteDeadline(deadline)

	n, err := proxyConn.LocalConn.Write(data)
	if err != nil {
		slog.Error("Failed to write data to local connection",
			"client_id", c.ID,
			"conn_id", connID,
			"data_bytes", len(data),
			"written_bytes", n,
			"error", err)
		c.closeConnection(connID)
		return
	}

	// Only log for larger transfers
	if n > 10000 {
		slog.Debug("Gateway successfully wrote large data chunk to local connection",
			"client_id", c.ID,
			"conn_id", connID,
			"bytes", n)
	}
}

// handleCloseMessage processes close messages from clients
func (c *ClientConn) handleCloseMessage(msg map[string]interface{}) {
	// Extract connection ID
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in close message",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	// Get the connection safely to check if it exists
	c.ConnsMu.RLock()
	_, exists := c.Conns[connID]
	c.ConnsMu.RUnlock()

	if !exists {
		slog.Debug("Close message for non-existent connection",
			"client_id", c.ID,
			"conn_id", connID)
		return
	}

	slog.Info("Received close message from client",
		"client_id", c.ID,
		"conn_id", connID)
	c.closeConnection(connID)
}

// handleConnectResponseMessage processes connect_response messages from clients
func (c *ClientConn) handleConnectResponseMessage(msg map[string]interface{}) {
	// Extract connection ID and success status
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in connect_response message",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	c.ConnsMu.RLock()
	proxyConn, exists := c.Conns[connID]
	c.ConnsMu.RUnlock()

	if !exists {
		slog.Warn("Connect response for non-existent connection",
			"client_id", c.ID,
			"conn_id", connID)
		return
	}

	success, ok := msg["success"].(bool)
	if !ok {
		slog.Error("Invalid success value in connect_response message",
			"client_id", c.ID,
			"conn_id", connID,
			"success_field_type", fmt.Sprintf("%T", msg["success"]))
		return
	}

	if success {
		slog.Info("Connection established successfully",
			"client_id", c.ID,
			"conn_id", connID)
		// Start handling the connection asynchronously
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.handleConnection(proxyConn)
		}()
		return
	}

	// Connection failed - cleanup
	errMsg, _ := msg["error"].(string)
	slog.Error("Connection establishment failed",
		"client_id", c.ID,
		"conn_id", connID,
		"error_message", errMsg)
	c.closeConnection(connID)
}

// handleConnection handles the connection with context awareness
func (c *ClientConn) handleConnection(proxyConn *Conn) {
	connID := proxyConn.ID
	slog.Debug("Starting connection handler",
		"client_id", c.ID,
		"conn_id", connID)

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := 0
	readCount := 0
	startTime := time.Now()

	defer func() {
		elapsed := time.Since(startTime)
		slog.Debug("Connection handler finished",
			"client_id", c.ID,
			"conn_id", connID,
			"total_bytes", totalBytes,
			"read_operations", readCount,
			"duration", elapsed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection handler stopping due to context cancellation",
				"client_id", c.ID,
				"conn_id", connID,
				"total_bytes", totalBytes)
			return
		case <-proxyConn.Done:
			slog.Debug("Connection handler stopping due to connection done signal",
				"client_id", c.ID,
				"conn_id", connID,
				"total_bytes", totalBytes)
			return
		default:
		}

		// Check if the connection is still valid BEFORE setting deadline
		c.ConnsMu.RLock()
		_, connExists := c.Conns[connID]
		c.ConnsMu.RUnlock()

		if !connExists {
			slog.Debug("Connection no longer exists in connection map",
				"client_id", c.ID,
				"conn_id", connID,
				"total_bytes", totalBytes)
			return
		}

		// Set read deadline based on context - use longer timeout for proxy connections
		deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}

		// Set deadline with error handling
		if err := proxyConn.LocalConn.SetReadDeadline(deadline); err != nil {
			// Connection likely closed, exit gracefully
			slog.Debug("Failed to set read deadline, connection likely closed",
				"client_id", c.ID,
				"conn_id", connID,
				"total_bytes", totalBytes)
			return
		}

		n, err := proxyConn.LocalConn.Read(buffer)
		readCount++

		// Remove verbose logging for performance
		if n > 0 {
			totalBytes += n
			// Only log for larger transfers to reduce noise
			if totalBytes%100000 == 0 || n > 10000 {
				slog.Debug("Gateway read data from local connection",
					"client_id", c.ID,
					"conn_id", connID,
					"bytes_this_read", n,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// Encode binary data as base64 string
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			// Send data through WebSocket writer
			writeErr := c.Writer.WriteJSON(map[string]interface{}{
				"type": "data",
				"id":   connID,
				"data": encodedData,
			})
			if writeErr != nil {
				slog.Error("Error writing data to WebSocket",
					"client_id", c.ID,
					"conn_id", connID,
					"data_bytes", n,
					"total_bytes", totalBytes,
					"error", writeErr)
				c.closeConnection(connID)
				return
			}
			// Only log for larger transfers
			if n > 10000 {
				slog.Debug("Gateway successfully sent large data chunk to client",
					"client_id", c.ID,
					"conn_id", connID,
					"bytes", n,
					"total_bytes", totalBytes)
			}
		}

		if err != nil {
			// Check if it's a timeout error and context is still valid
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-c.ctx.Done():
					slog.Debug("Connection handler stopping due to context during timeout",
						"client_id", c.ID,
						"conn_id", connID)
					return
				default:
					continue // Continue on timeout if context is still valid
				}
			}

			// Handle connection closed errors gracefully (don't log as ERROR)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				slog.Debug("Connection closed during read operation",
					"client_id", c.ID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			} else if err != io.EOF {
				slog.Error("Error reading from server connection",
					"client_id", c.ID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount,
					"error", err)
			} else {
				slog.Debug("Connection closed by local side (EOF)",
					"client_id", c.ID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// Notify client about connection close (only if not already closing)
			select {
			case <-proxyConn.Done:
				// Connection already marked as done, don't send close message
				slog.Debug("Connection already marked as done, skipping close message",
					"client_id", c.ID,
					"conn_id", connID)
			default:
				closeErr := c.Writer.WriteJSON(map[string]interface{}{
					"type": "close",
					"id":   connID,
				})
				if closeErr != nil {
					slog.Debug("Error sending close message to client (connection likely already closed)",
						"client_id", c.ID,
						"conn_id", connID,
						"error", closeErr)
				} else {
					slog.Debug("Sent close message to client",
						"client_id", c.ID,
						"conn_id", connID)
				}
			}

			c.closeConnection(connID)
			return
		}
	}
}

// Helper function to get safe message field names for logging
func gatewayGetMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}

// closeConnectionUnsafe closes a connection without acquiring locks (internal use only)
func (c *ClientConn) closeConnectionUnsafe(connID string) {
	proxyConn, exists := c.Conns[connID]
	if !exists {
		slog.Debug("Unsafe close requested for non-existent connection",
			"client_id", c.ID,
			"conn_id", connID)
		return
	}
	delete(c.Conns, connID)

	slog.Debug("Connection removed unsafely from map",
		"client_id", c.ID,
		"conn_id", connID)

	// Signal connection to stop
	select {
	case <-proxyConn.Done:
	default:
		close(proxyConn.Done)
	}

	// Close the actual connection
	proxyConn.once.Do(func() {
		slog.Debug("Closing local connection (unsafe)",
			"client_id", c.ID,
			"conn_id", proxyConn.ID)
		if err := proxyConn.LocalConn.Close(); err != nil {
			slog.Debug("Unsafe connection close completed with error",
				"client_id", c.ID,
				"conn_id", proxyConn.ID,
				"error", err)
		}
	})
}
