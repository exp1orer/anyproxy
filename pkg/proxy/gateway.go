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

	// Create a custom dial function that uses WebSocket connections
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract user context from context if available
		var groupID string
		if userCtx, ok := ctx.Value("user").(*UserContext); ok {
			slog.Info("dialFn get userCtx", "userCtx", userCtx)
			groupID = userCtx.GroupID
		}

		// Get a client from the specified group
		client, err := gateway.getClientByGroup(groupID)
		if err != nil {
			slog.Error("Failed to get client by group", "group_id", groupID, "error", err)
			return nil, err
		}
		return client.dialNetwork(network, addr)
	}

	// Create proxy instances based on configuration
	var proxies []GatewayProxy

	// Create HTTP proxy if configured
	if cfg.Proxy.HTTP.ListenAddr != "" {
		httpProxy, err := NewHTTPProxyWithAuth(&cfg.Proxy.HTTP, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		proxies = append(proxies, httpProxy)
		slog.Info("Created HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
	}

	// Create SOCKS5 proxy if configured
	if cfg.Proxy.SOCKS5.ListenAddr != "" {
		socks5Proxy, err := NewSOCKS5ProxyWithAuth(&cfg.Proxy.SOCKS5, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %v", err)
		}
		proxies = append(proxies, socks5Proxy)
		slog.Info("Created SOCKS5 proxy", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
	}

	// Ensure at least one proxy is configured
	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxy configured: please configure at least one of HTTP or SOCKS5 proxy")
	}

	gateway.proxies = proxies

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
	// Start the HTTP server for WebSocket connections
	if err := g.startHTTPServer(); err != nil {
		return err
	}

	// Start all proxy servers
	for i, proxy := range g.proxies {
		if err := proxy.Start(); err != nil {
			// If any proxy fails to start, stop the ones that already started
			for j := 0; j < i; j++ {
				g.proxies[j].Stop()
			}
			return fmt.Errorf("failed to start proxy %d: %v", i, err)
		}
	}

	return nil
}

// startHTTPServer starts the HTTP server for WebSocket connections
func (g *Gateway) startHTTPServer() error {
	// Load TLS certificate and key
	cert, err := tls.LoadX509KeyPair(g.config.TLSCert, g.config.TLSKey)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create HTTP server for WebSocket connections
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", g.handleWebSocket)

	g.httpServer = &http.Server{
		Addr:      g.config.ListenAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// Start HTTP server in a separate goroutine
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		slog.Info("Starting WebSocket server", "listen_addr", g.config.ListenAddr)
		if err := g.httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()

	return nil
}

// Stop stops the gateway gracefully with context-based coordination
func (g *Gateway) Stop() error {
	slog.Info("Stopping gateway gracefully...")

	// Step 1: Signal all goroutines to stop
	g.cancel()

	// Step 2: Stop accepting new connections
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := g.httpServer.Shutdown(ctx); err != nil {
		slog.Error("Error shutting down HTTP server", "error", err)
	}

	// Step 3: Stop all proxy servers
	for i, proxy := range g.proxies {
		if err := proxy.Stop(); err != nil {
			slog.Error("Error stopping proxy", "index", i, "error", err)
		}
	}

	// Step 4: Stop port forwarding manager
	g.portForwardMgr.Stop()

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
	gracefulWait(500 * time.Millisecond)

	// Step 6: Stop all client connections gracefully
	g.clientsMu.RLock()
	for _, client := range g.clients {
		client.Stop()
	}
	g.clientsMu.RUnlock()

	// Step 7: Wait for all goroutines to finish
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

	return nil
}

// handleWebSocket handles WebSocket connections from clients
func (g *Gateway) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}

	// If the group-id is empty, then the client will be add to the default group
	groupID := r.Header.Get("X-Group-ID")

	// Authenticate client
	username, password, ok := r.BasicAuth()
	if !ok || username != g.config.AuthUsername || password != g.config.AuthPassword {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := g.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("Failed to upgrade WebSocket connection", "error", err)
		return
	}

	// Create WebSocket writer
	writeBuf := make(chan interface{}, writeBufSize)
	writer := NewWebSocketWriter(conn, writeBuf)
	writer.Start()

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
	slog.Info("Client connected", "client_id", clientID, "group_id", groupID)

	// Handle incoming messages from the client
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer func() {
			client.Stop()
			g.removeClient(client.ID)
			slog.Info("Client disconnected", "client_id", client.ID)
		}()
		client.handleMessage()
	}()
}

// addClient adds a client to the gateway
func (g *Gateway) addClient(client *ClientConn) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()
	g.clients[client.ID] = client
	if _, ok := g.groups[client.GroupID]; !ok {
		g.groups[client.GroupID] = make(map[string]struct{})
	}
	g.groups[client.GroupID][client.ID] = struct{}{}
}

// removeClient removes a client from the gateway
func (g *Gateway) removeClient(clientID string) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	// Find and remove client from groups
	for _, clients := range g.groups {
		if _, exists := clients[clientID]; exists {
			delete(clients, clientID)
			break
		}
	}

	// Close all port forwarding for this client
	g.portForwardMgr.CloseClientPorts(clientID)

	delete(g.clients, clientID)
}

// getRandomClient returns a random available client
func (g *Gateway) getRandomClient() (*ClientConn, error) {
	return g.getClientByGroup("")
}

// getClientByGroup returns a random available client from the specified group
func (g *Gateway) getClientByGroup(groupID string) (*ClientConn, error) {
	g.clientsMu.RLock()
	defer g.clientsMu.RUnlock()

	// Get clients from the specified group
	clientIDs, exists := g.groups[groupID]
	if !exists || len(clientIDs) == 0 {
		// If no clients in specified group, try default group
		if groupID != "" {
			clientIDs, exists = g.groups[""]
			if !exists || len(clientIDs) == 0 {
				return nil, fmt.Errorf("no clients available in group '%s' or default group", groupID)
			}
		} else {
			return nil, fmt.Errorf("no clients available in default group")
		}
	}

	// Return the first available client from the group (simple implementation)
	for clientID := range clientIDs {
		if client, exists := g.clients[clientID]; exists {
			return client, nil
		}
	}

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
	c.ConnsMu.Unlock()

	// Send connect request to client
	slog.Info("Sending connect request to client", "clientID", c.ID, "connID", connID, "addr", addr)
	err := c.Writer.WriteJSON(map[string]interface{}{
		"type":    "connect",
		"id":      connID,
		"network": network,
		"address": addr,
	})
	if err != nil {
		// Clean up on failure
		c.closeConnection(connID) // will close pipe2
		return nil, fmt.Errorf("failed to send connect request: %v", err)
	}

	// Return the connection wrapper
	return NewConnWrapper(pipe1, network, addr), nil
}

// Stop gracefully stops the client connection
func (c *ClientConn) Stop() {
	c.stopOnce.Do(func() {
		slog.Info("Stopping client gracefully", "clientID", c.ID)

		// Step 1: Signal all goroutines to stop
		c.cancel()

		// Step 2: Give connections time to finish current operations
		slog.Info("Waiting for active connections to finish", "clientID", c.ID)
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
			c.Writer.Stop()
			c.Writer = nil
		}

		// Step 4: Clear the connection reference (already closed by writer)
		c.Conn = nil

		// Step 5: Close all proxy connections
		c.ConnsMu.Lock()
		for connID := range c.Conns {
			c.closeConnectionUnsafe(connID)
		}
		c.ConnsMu.Unlock()

		// Step 6: Close all message channels
		c.msgChansMu.Lock()
		for connID, msgChan := range c.msgChans {
			close(msgChan)
			delete(c.msgChans, connID)
		}
		c.msgChansMu.Unlock()

		// Step 7: Wait for all goroutines to finish with timeout
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			slog.Info("All client goroutines finished gracefully", "clientID", c.ID)
		case <-time.After(2 * time.Second):
			slog.Warn("Timeout waiting for client goroutines to finish", "clientID", c.ID)
		}
	})
}

// closeConnectionUnsafe closes a connection without acquiring locks (internal use only)
func (c *ClientConn) closeConnectionUnsafe(connID string) {
	proxyConn, exists := c.Conns[connID]
	if !exists {
		return
	}
	delete(c.Conns, connID)

	// Signal connection to stop
	select {
	case <-proxyConn.Done:
	default:
		close(proxyConn.Done)
	}

	// Close the actual connection
	proxyConn.once.Do(func() {
		slog.Debug("Closing local connection", "conn_id", proxyConn.ID)
		proxyConn.LocalConn.Close()
	})
}

// handleMessage processes incoming messages with context awareness
func (c *ClientConn) handleMessage() {
	for {
		select {
		case <-c.ctx.Done():
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
				slog.Error("Unexpected WebSocket close", "error", err, "client_id", c.ID)
			} else if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Info("WebSocket connection closed normally", "client_id", c.ID)
			} else {
				slog.Error("WebSocket read error", "error", err, "client_id", c.ID)
			}

			// Connection failed, exit
			return
		}

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from client", "client_id", c.ID)
			continue
		}

		switch msgType {
		case "connect_response", "data", "close":
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		case "port_forward_request":
			// Handle port forwarding request directly
			c.handlePortForwardRequest(msg)
		default:
			slog.Warn("Unknown message type", "type", msgType, "client_id", c.ID)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel with context awareness
func (c *ClientConn) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message")
		return
	}

	msgType, _ := msg["type"].(string)

	// For connect_response messages, create the channel first if needed
	if msgType == "connect_response" {
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// Connection doesn't exist, ignore message
		return
	}

	// Send message to connection's channel (non-blocking with context awareness)
	select {
	case msgChan <- msg:
	case <-c.ctx.Done():
		return
	default:
		slog.Warn("Message channel full for connection", "conn_id", connID)
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
		slog.Error("Invalid connection ID in data message", "client_id", c.ID)
		return
	}

	// WebSocket JSON messages encode binary data as base64 string
	dataStr, ok := msg["data"].(string)
	if !ok {
		slog.Error("Invalid data in data message", "conn_id", connID, "client_id", c.ID, "data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data", "conn_id", connID, "client_id", c.ID, "error", err)
		return
	}

	// Only log for larger transfers to reduce noise
	if len(data) > 10000 {
		slog.Debug("Gateway received data", "bytes", len(data), "client_id", c.ID, "conn_id", connID)
	}

	// Get the connection safely
	c.ConnsMu.RLock()
	proxyConn, ok := c.Conns[connID]
	c.ConnsMu.RUnlock()
	if !ok {
		slog.Warn("Unknown connection ID when handling data message", "conn_id", connID, "client_id", c.ID)
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
		slog.Error("Failed to write data to local connection", "bytes", len(data), "conn_id", connID, "error", err)
		c.closeConnection(connID)
		return
	}

	// Only log for larger transfers
	if n > 10000 {
		slog.Debug("Gateway successfully wrote data to local connection", "bytes", n, "conn_id", connID)
	}
}

// handleCloseMessage processes close messages from clients
func (c *ClientConn) handleCloseMessage(msg map[string]interface{}) {
	// Extract connection ID
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in close message")
		return
	}

	// Get the connection safely
	c.ConnsMu.RLock()
	_, ok = c.Conns[connID]
	c.ConnsMu.RUnlock()

	if !ok {
		slog.Info("Connection ID not found - may have already been closed", "conn_id", connID, "client_id", c.ID)
		return
	}

	slog.Info("Closing connection", "conn_id", connID, "client_id", c.ID)
	c.closeConnection(connID)
}

// handleConnectResponseMessage processes connect_response messages from clients
func (c *ClientConn) handleConnectResponseMessage(msg map[string]interface{}) {
	// Extract connection ID and success status
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in connect_response message")
		return
	}

	c.ConnsMu.RLock()
	proxyConn, exists := c.Conns[connID]
	c.ConnsMu.RUnlock()

	if !exists {
		slog.Warn("Connection not found", "conn_id", connID, "client_id", c.ID)
		return
	}

	success, ok := msg["success"].(bool)
	if !ok {
		slog.Error("Invalid success value in connect_response message")
		return
	}

	if success {
		slog.Info("Connection established successfully", "conn_id", connID, "client_id", c.ID)
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
	slog.Error("Connection failed", "conn_id", connID, "client_id", c.ID, "error", errMsg)
	c.closeConnection(connID)
}

// handleConnection handles the connection with context awareness
func (c *ClientConn) handleConnection(proxyConn *Conn) {
	connID := proxyConn.ID
	slog.Debug("Starting to handle gateway connection", "conn_id", connID, "client_id", c.ID)

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := 0

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Gateway stopping, exiting connection handler", "conn_id", connID)
			return
		case <-proxyConn.Done:
			slog.Debug("Connection done signal received", "conn_id", connID)
			return
		default:
		}

		// Check if the connection is still valid BEFORE setting deadline
		c.ConnsMu.RLock()
		_, connExists := c.Conns[connID]
		c.ConnsMu.RUnlock()

		if !connExists {
			slog.Debug("Connection no longer exists", "conn_id", connID, "client_id", c.ID)
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
			slog.Debug("Failed to set read deadline, connection likely closed", "conn_id", connID)
			return
		}

		n, err := proxyConn.LocalConn.Read(buffer)
		// Remove verbose logging for performance
		if n > 0 {
			totalBytes += n
			// Only log for larger transfers to reduce noise
			if totalBytes%100000 == 0 || n > 10000 {
				slog.Debug("Gateway read data from local connection", "bytes", n, "conn_id", connID, "total_bytes", totalBytes)
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
				slog.Error("Error writing to WebSocket", "conn_id", connID, "error", writeErr)
				c.closeConnection(connID)
				return
			}
			// Only log for larger transfers
			if n > 10000 {
				slog.Debug("Gateway successfully sent data to client", "bytes", n, "conn_id", connID)
			}
		}

		if err != nil {
			// Check if it's a timeout error and context is still valid
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-c.ctx.Done():
					return
				default:
					continue // Continue on timeout if context is still valid
				}
			}

			// Handle connection closed errors gracefully (don't log as ERROR)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				slog.Debug("Connection closed during read operation", "conn_id", connID, "total_bytes", totalBytes)
			} else if err != io.EOF {
				slog.Error("Error reading from server connection", "conn_id", connID, "error", err, "total_bytes", totalBytes)
			} else {
				slog.Debug("Gateway connection closed by local (EOF)", "conn_id", connID, "total_bytes", totalBytes)
			}

			// Notify client about connection close (only if not already closing)
			select {
			case <-proxyConn.Done:
				// Connection already marked as done, don't send close message
			default:
				closeErr := c.Writer.WriteJSON(map[string]interface{}{
					"type": "close",
					"id":   connID,
				})
				if closeErr != nil {
					slog.Debug("Error sending close message to client (connection likely already closed)", "conn_id", connID)
				}
			}

			c.closeConnection(connID)
			return
		}
	}
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
