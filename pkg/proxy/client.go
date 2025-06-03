package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
)

const (
	writeBufSize = 1000
)

// Client represents the proxy client
type Client struct {
	config     *config.ClientConfig
	wsConn     *websocket.Conn
	writer     *WebSocketWriter
	writeBuf   chan interface{}
	connsMu    sync.RWMutex
	conns      map[string]net.Conn
	msgChans   map[string]chan map[string]interface{} // Message channels per connection
	msgChansMu sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewClient creates a new proxy client
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		config:   cfg,
		conns:    make(map[string]net.Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
		writeBuf: make(chan interface{}, writeBufSize),
	}, nil
}

// Start starts the client with automatic reconnection
func (c *Client) Start() error {
	// Start the main connection loop with reconnection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectionLoop()
	}()

	return nil
}

// Stop stops the client gracefully
func (c *Client) Stop() error {
	slog.Info("Stopping client gracefully...")

	// Step 1: Signal all goroutines to stop accepting new work
	c.cancel()

	// Step 2: Give existing connections time to finish current operations
	slog.Info("Waiting for active connections to finish...")
	gracefulWait := func(duration time.Duration) bool {
		select {
		case <-c.ctx.Done():
			return false // Already cancelled
		case <-time.After(duration):
			return true // Wait completed
		}
	}
	gracefulWait(500 * time.Millisecond)

	// Step 3: Stop WebSocket writer - this will close the WebSocket connection
	if c.writer != nil {
		c.writer.Stop()
	}

	// Step 4: Close all remaining connections
	c.closeAllConnections()

	// Step 5: Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("All client goroutines finished gracefully")
	case <-time.After(3 * time.Second):
		slog.Warn("Timeout waiting for client goroutines to finish")
	}

	return nil
}

// connectionLoop handles connection and reconnection logic with context-aware backoff
func (c *Client) connectionLoop() {
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Attempt to connect
		if err := c.connect(); err != nil {
			slog.Error("Failed to connect to gateway", "error", err, "retrying_in", backoff)

			// Context-aware wait before retry
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Reset backoff on successful connection
		backoff = 1 * time.Second
		slog.Info("Successfully connected to gateway")

		// Handle messages until connection fails or context is cancelled
		c.handleMessages()

		// Check if we're stopping
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Connection lost, cleanup and retry
		slog.Info("Connection to gateway lost, cleaning up and retrying...")
		c.cleanup()
	}
}

// cleanup cleans up resources after connection loss
func (c *Client) cleanup() {
	// Stop writer first - this will close the WebSocket connection
	// and stop using writeBuf
	if c.writer != nil {
		c.writer.Stop()
		c.writer = nil
	}

	// Clear the connection reference (already closed by writer)
	c.wsConn = nil

	// Close all connections
	c.closeAllConnections()

	// Close write buffer and recreate for next connection (only if not stopping)
	if c.writeBuf != nil {
		close(c.writeBuf)
		c.writeBuf = nil
	}

	select {
	case <-c.ctx.Done():
		// Don't recreate if we're stopping
	default:
		c.writeBuf = make(chan interface{}, writeBufSize)
	}
}

// closeAllConnections closes all active connections
func (c *Client) closeAllConnections() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = make(map[string]net.Conn)
}

// connect establishes a WebSocket connection to the gateway
func (c *Client) connect() error {
	// Create TLS configuration
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		return err
	}

	// Parse the gateway URL
	gatewayURL := url.URL{
		Scheme: "wss",
		Host:   c.config.GatewayAddr,
		Path:   "/ws",
	}

	// Set up headers
	headers := http.Header{}
	headers.Set("X-Client-ID", c.generateClientID())
	headers.Set("X-Group-ID", c.config.GroupID)
	slog.Info("Connecting to gateway", "url", gatewayURL.String(), "headers", headers)

	// Use Basic Auth for authentication
	auth := base64.StdEncoding.EncodeToString(
		[]byte(c.config.AuthUsername + ":" + c.config.AuthPassword),
	)
	headers.Set("Authorization", "Basic "+auth)

	// Create WebSocket dialer with context
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}

	// Connect to WebSocket
	conn, _, err := dialer.Dial(gatewayURL.String(), headers)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	c.wsConn = conn

	// Create and start WebSocket writer
	c.writer = NewWebSocketWriter(conn, c.writeBuf)
	c.writer.Start()

	// Send port forwarding request if configured
	if err := c.sendPortForwardingRequest(); err != nil {
		slog.Error("Failed to send port forwarding request", "error", err)
		// Continue anyway, port forwarding is optional
	}

	return nil
}

func (c *Client) generateClientID() string {
	return fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
}

// createTLSConfig creates a TLS configuration for the client
func (c *Client) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: strings.Split(c.config.GatewayAddr, ":")[0],
	}

	// If a certificate file is provided, load it
	if c.config.GatewayTLSCert != "" {
		caCert, err := os.ReadFile(c.config.GatewayTLSCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read gateway TLS certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// handleMessages processes incoming messages from the gateway with context awareness
func (c *Client) handleMessages() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Read message from gateway without artificial timeout
		// Let WebSocket handle its own timeout/keepalive mechanisms
		var msg map[string]interface{}
		err := c.wsConn.ReadJSON(&msg)
		if err != nil {
			// Check for WebSocket close errors
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Info("WebSocket connection closed", "error", err)
			} else {
				slog.Error("WebSocket read error", "error", err)
			}

			// Connection failed, exit to trigger reconnection
			return
		}

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from gateway")
			continue
		}

		switch msgType {
		case "connect", "data", "close":
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		case "port_forward_response":
			// Handle port forwarding response directly
			c.handlePortForwardResponse(msg)
		default:
			slog.Warn("Unknown message type", "type", msgType)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel
func (c *Client) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message")
		return
	}

	msgType, _ := msg["type"].(string)

	// For connect messages, create the channel first
	if msgType == "connect" {
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
		slog.Warn("Message channel full for connection, dropping message", "conn_id", connID)
	}
}

// createMessageChannel creates a message channel for a connection
func (c *Client) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

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
func (c *Client) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
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
			case "connect":
				c.handleConnectMessage(msg)
			case "data":
				c.handleDataMessage(msg)
			case "close":
				c.handleCloseMessage(msg)
				return // Connection closed, stop processing
			}
		}
	}
}

// handleConnectMessage processes a connect message from the gateway
func (c *Client) handleConnectMessage(msg map[string]interface{}) {
	// Extract connection information
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in connect message")
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		slog.Error("Invalid network in connect message")
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		slog.Error("Invalid address in connect message")
		return
	}

	slog.Info("Handling connect request", "conn_id", connID, "network", network, "address", address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		slog.Warn("Connection denied (forbidden host)", "address", address)
		c.sendConnectResponse(connID, false, "Host is forbidden")
		return
	}

	// Establish connection to the target with context
	var d net.Dialer
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		slog.Error("Failed to connect", "address", address, "error", err)
		c.sendConnectResponse(connID, false, err.Error())
		return
	}

	slog.Info("Successfully connected", "address", address, "conn_id", connID)

	// Register the connection
	c.connsMu.Lock()
	c.conns[connID] = conn
	c.connsMu.Unlock()

	// Send success response
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		slog.Error("Error sending connect_response", "conn_id", connID, "error", err)
		c.cleanupConnection(connID)
		return
	}

	// Start handling the connection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleConnection(connID)
	}()
}

// sendConnectResponse sends a connection response to the gateway
func (c *Client) sendConnectResponse(connID string, success bool, errorMsg string) error {
	response := map[string]interface{}{
		"type":    "connect_response",
		"id":      connID,
		"success": success,
	}

	if !success && errorMsg != "" {
		response["error"] = errorMsg
	}

	return c.writer.WriteJSON(response)
}

// handleConnection reads from the target connection and sends data to gateway with context awareness
func (c *Client) handleConnection(connID string) {
	slog.Debug("Starting to handle connection", "conn_id", connID)

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		slog.Warn("Unknown connection ID", "conn_id", connID)
		return
	}

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer to match gateway

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Client stopping, exiting connection handler", "conn_id", connID)
			return
		default:
		}

		// Set read deadline based on context - use longer timeout for proxy connections
		deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		conn.SetReadDeadline(deadline)

		n, err := conn.Read(buffer)
		if n > 0 {
			// Encode binary data as base64 string
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			writeErr := c.writer.WriteJSON(map[string]interface{}{
				"type": "data",
				"id":   connID,
				"data": encodedData,
			})
			if writeErr != nil {
				slog.Error("Error writing data to WebSocket", "conn_id", connID, "error", writeErr)
				c.cleanupConnection(connID)
				return
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if timeout is due to context cancellation
				select {
				case <-c.ctx.Done():
					return
				default:
					continue // Continue on timeout if context is still valid
				}
			}

			if err != io.EOF {
				slog.Error("Failed to read from connection", "conn_id", connID, "error", err)
			}

			// Send close message to gateway
			c.writer.WriteJSON(map[string]interface{}{
				"type": "close",
				"id":   connID,
			})

			c.cleanupConnection(connID)
			return
		}
	}
}

// isConnectionAllowed checks if a connection to the given address is allowed
func (c *Client) isConnectionAllowed(address string) bool {
	host := address
	if idx := strings.LastIndex(address, ":"); idx > 0 {
		host = address[:idx]
	}

	for _, forbidden := range c.config.ForbiddenHosts {
		re := regexp.MustCompile(forbidden)
		if re.MatchString(host) {
			return false
		}

		if strings.HasSuffix(host, forbidden) {
			return false
		}
	}

	if len(c.config.AllowedHosts) == 0 {
		return true
	}

	for _, allowed := range c.config.AllowedHosts {
		re := regexp.MustCompile(allowed)
		if re.MatchString(host) {
			return true
		}

		if strings.HasSuffix(host, allowed) {
			return true
		}
	}

	return false
}

// handleDataMessage processes a data message from the gateway
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// Extract message information
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in data message")
		return
	}

	dataStr, ok := msg["data"].(string)
	if !ok {
		slog.Error("Invalid data in data message", "conn_id", connID)
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data", "conn_id", connID, "error", err)
		return
	}

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		slog.Warn("Unknown connection ID", "conn_id", connID)
		return
	}

	// Write data to the connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetWriteDeadline(deadline)

	_, err = conn.Write(data)
	if err != nil {
		slog.Error("Failed to write data to connection", "conn_id", connID, "error", err)
		c.cleanupConnection(connID)
		return
	}
}

// handleCloseMessage processes a close message from the gateway
func (c *Client) handleCloseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in close message")
		return
	}

	c.cleanupConnection(connID)
}

// cleanupConnection cleans up a connection
func (c *Client) cleanupConnection(connID string) {
	c.connsMu.Lock()
	conn, exists := c.conns[connID]
	if exists {
		delete(c.conns, connID)
	}
	c.connsMu.Unlock()

	// Clean up message channel
	c.msgChansMu.Lock()
	if msgChan, exists := c.msgChans[connID]; exists {
		delete(c.msgChans, connID)
		close(msgChan)
	}
	c.msgChansMu.Unlock()

	if exists && conn != nil {
		conn.Close()
		slog.Debug("Connection cleaned up", "conn_id", connID)
	}
}

// sendPortForwardingRequest sends a port forwarding request to the gateway
func (c *Client) sendPortForwardingRequest() error {
	if len(c.config.OpenPorts) == 0 {
		slog.Info("No ports to forward")
		return nil
	}

	slog.Info("Sending port forwarding request", "port_count", len(c.config.OpenPorts), "ports", c.config.OpenPorts)

	// Convert config.OpenPort to the format expected by the gateway
	openPorts := make([]map[string]interface{}, len(c.config.OpenPorts))
	for i, openPort := range c.config.OpenPorts {
		openPorts[i] = map[string]interface{}{
			"remote_port": openPort.RemotePort,
			"local_port":  openPort.LocalPort,
			"local_host":  openPort.LocalHost,
			"protocol":    openPort.Protocol,
		}
	}

	request := map[string]interface{}{
		"type":       "port_forward_request",
		"open_ports": openPorts,
	}

	return c.writer.WriteJSON(request)
}

// handlePortForwardResponse processes a port forwarding response from the gateway
func (c *Client) handlePortForwardResponse(msg map[string]interface{}) {
	// Extract response information
	success, ok := msg["success"].(bool)
	if !ok {
		slog.Error("Invalid success status in port forwarding response")
		return
	}

	message, _ := msg["message"].(string)

	if success {
		slog.Info("Port forwarding request successful", "message", message)
	} else {
		slog.Error("Port forwarding request failed", "message", message)
	}
}
