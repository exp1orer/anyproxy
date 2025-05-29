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
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/rs/xid"
)

// Gateway represents the proxy gateway server
type Gateway struct {
	config     *config.GatewayConfig
	httpServer *http.Server
	proxies    []GatewayProxy // Support multiple proxies
	upgrader   websocket.Upgrader
	clientsMu  sync.RWMutex
	clients    map[string]*ClientConn
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewGateway creates a new proxy gateway
func NewGateway(cfg *config.Config) (*Gateway, error) {
	gateway := &Gateway{
		config:  &cfg.Gateway,
		clients: make(map[string]*ClientConn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
		stopCh: make(chan struct{}),
	}

	// Create a custom dial function that uses WebSocket connections
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Get a random client
		client, err := gateway.getRandomClient()
		if err != nil {
			return nil, err
		}
		return client.dialNetwork(network, addr)
	}

	// Create proxy instances based on configuration
	var proxies []GatewayProxy

	// Create HTTP proxy if configured
	if cfg.Proxy.HTTP.ListenAddr != "" {
		httpProxy, err := NewHTTPProxy(&cfg.Proxy.HTTP, dialFn)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		proxies = append(proxies, httpProxy)
		slog.Info("Created HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
	}

	// Create SOCKS5 proxy if configured
	if cfg.Proxy.SOCKS5.ListenAddr != "" {
		socks5Proxy, err := NewSOCKS5Proxy(&cfg.Proxy.SOCKS5, dialFn)
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

// Stop stops the gateway gracefully
func (g *Gateway) Stop() error {
	slog.Info("Stopping gateway gracefully...")

	// Step 1: Signal all goroutines to stop
	close(g.stopCh)

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

	// Step 4: Give clients time to finish processing
	slog.Info("Waiting for clients to finish processing...")
	time.Sleep(500 * time.Millisecond)

	// Step 5: Stop all client connections gracefully
	g.clientsMu.RLock()
	for _, client := range g.clients {
		client.Stop()
	}
	g.clientsMu.RUnlock()

	// Step 6: Wait for all goroutines to finish
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

	// Create and register client
	client := &ClientConn{
		ID:       clientID,
		Conn:     conn,
		Writer:   writer,
		writeBuf: writeBuf,
		Conns:    make(map[string]*ProxyConn),
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	g.addClient(client)
	slog.Info("Client connected", "client_id", clientID)

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
}

// removeClient removes a client from the gateway
func (g *Gateway) removeClient(clientID string) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()
	delete(g.clients, clientID)
}

// getRandomClient returns a random available client
func (g *Gateway) getRandomClient() (*ClientConn, error) {
	g.clientsMu.RLock()
	defer g.clientsMu.RUnlock()

	if len(g.clients) == 0 {
		return nil, fmt.Errorf("no clients available")
	}

	// Return the first available client (simple implementation)
	for _, client := range g.clients {
		return client, nil
	}

	return nil, fmt.Errorf("no clients available")
}

// ------------------------------------------------------------------------------------------------
// -------------------------------------- ClientConn and ProxyConn --------------------------------
// ------------------------------------------------------------------------------------------------

// ClientConn represents a connected proxy client
type ClientConn struct {
	ID         string
	Conn       *websocket.Conn
	Writer     *WebSocketWriter
	writeBuf   chan interface{}
	ConnsMu    sync.RWMutex
	Conns      map[string]*ProxyConn
	msgChans   map[string]chan map[string]interface{} // Message channels per connection
	msgChansMu sync.RWMutex
	stopOnce   sync.Once
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// ProxyConn represents a proxied connection
type ProxyConn struct {
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
	proxyConn := &ProxyConn{
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

// Stop stops the client and cleans up resources gracefully
func (c *ClientConn) Stop() {
	c.stopOnce.Do(func() {
		slog.Info("Stopping client gracefully", "clientID", c.ID)

		// Step 1: Signal all goroutines to stop accepting new work
		close(c.stopCh)

		// Step 2: Give existing connections time to finish current operations
		slog.Info("Waiting for active connections to finish", "clientID", c.ID)
		time.Sleep(300 * time.Millisecond)

		// Step 3: Close write buffer to signal writer to stop
		close(c.writeBuf)

		// Step 4: Give writer time to drain remaining messages
		time.Sleep(200 * time.Millisecond)

		// Step 5: Stop writer
		c.Writer.Stop()

		// Step 6: Close WebSocket connection
		c.Conn.Close()

		// Step 7: Close all proxy connections using existing logic
		c.ConnsMu.RLock()
		connIDs := make([]string, 0, len(c.Conns))
		for connID := range c.Conns {
			connIDs = append(connIDs, connID)
		}
		c.ConnsMu.RUnlock()

		// Close connections one by one using existing closeConnection method
		for _, connID := range connIDs {
			c.closeConnection(connID)
		}

		// Step 8: Wait for all goroutines to finish with timeout
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

func (c *ClientConn) handleMessage() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Read message from client
		var msg map[string]interface{}
		if err := c.Conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				slog.Error("WebSocket error", "error", err)
			}
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
		default:
			slog.Warn("Unknown message type", "type", msgType)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel
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

	// Send message to connection's channel (non-blocking)
	select {
	case msgChan <- msg:
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

// processConnectionMessages processes messages for a specific connection in order
func (c *ClientConn) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
	for {
		select {
		case <-c.stopCh:
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

	// Write data to the local connection
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

func (c *ClientConn) handleConnection(proxyConn *ProxyConn) {
	connID := proxyConn.ID
	slog.Debug("Starting to handle gateway connection", "conn_id", connID, "client_id", c.ID)

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer
	totalBytes := 0

	for {
		select {
		case <-c.stopCh:
			slog.Debug("Gateway stopping, exiting connection handler", "conn_id", connID)
			return
		case <-proxyConn.Done:
			slog.Debug("Connection done signal received", "conn_id", connID)
			return
		default:
		}

		// Check if the connection is still valid
		c.ConnsMu.RLock()
		_, connExists := c.Conns[connID]
		c.ConnsMu.RUnlock()

		if !connExists {
			slog.Debug("Connection no longer exists", "conn_id", connID, "client_id", c.ID)
			return
		}

		// Set reasonable read timeout for shutdown response
		proxyConn.LocalConn.SetReadDeadline(time.Now().Add(5 * time.Second))

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
			// Check if it's a timeout error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Reduce timeout logging noise
				continue
			}

			if err != io.EOF {
				slog.Error("Error reading from server connection", "conn_id", connID, "error", err, "total_bytes", totalBytes)
			} else {
				slog.Debug("Gateway connection closed by local (EOF)", "conn_id", connID, "total_bytes", totalBytes)
			}

			// Notify client about connection close
			closeErr := c.Writer.WriteJSON(map[string]interface{}{
				"type": "close",
				"id":   connID,
			})
			if closeErr != nil {
				slog.Error("Error sending close message to client", "conn_id", connID, "error", closeErr)
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
	delete(c.Conns, connID)
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

	slog.Debug("Connection closed and cleaned up", "conn_id", proxyConn.ID, "client_id", c.ID)
}
