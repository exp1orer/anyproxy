// Package proxy provides the v1 implementation of AnyProxy client and gateway.
// It includes WebSocket-based client-gateway communication, HTTP/SOCKS5 proxy support,
// port forwarding, and connection management with automatic reconnection.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
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
	"github.com/buhuipao/anyproxy/pkg/logger"
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
	logger.Info("Creating client", "id", cfg.ClientID, "gateway", cfg.GatewayAddr, "group", cfg.GroupID)

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		config:   cfg,
		conns:    make(map[string]net.Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
		writeBuf: make(chan interface{}, writeBufSize),
	}

	return client, nil
}

// Start starts the client with automatic reconnection
func (c *Client) Start() error {
	logger.Info("Starting client", "id", c.config.ClientID, "gateway", c.config.GatewayAddr)

	// Start the main connection loop with reconnection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectionLoop()
	}()

	logger.Info("Client started", "id", c.config.ClientID)
	return nil
}

// Stop stops the client gracefully
func (c *Client) Stop() error {
	logger.Info("Stopping client", "id", c.config.ClientID)

	// Step 1: Signal all goroutines to stop accepting new work
	c.cancel()

	// Step 2: Get connection count before cleanup
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	if connectionCount > 0 {
		logger.Info("Waiting for connections", "id", c.config.ClientID, "count", connectionCount)
	}

	// Give existing connections time to finish current operations
	select {
	case <-c.ctx.Done():
		// Already cancelled
	case <-time.After(500 * time.Millisecond):
		// Wait completed
	}

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
		logger.Debug("Client goroutines finished", "id", c.config.ClientID)
	case <-time.After(3 * time.Second):
		logger.Warn("Timeout waiting for goroutines", "id", c.config.ClientID)
	}

	logger.Info("Client stopped", "id", c.config.ClientID, "conns_closed", connectionCount)
	return nil
}

// connectionLoop handles connection and reconnection logic with context-aware backoff
func (c *Client) connectionLoop() {
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second
	connectionAttempts := 0

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		connectionAttempts++

		// Attempt to connect
		if err := c.connect(); err != nil {
			logger.Error("Failed to connect", "id", c.config.ClientID, "attempt", connectionAttempts, "err", err, "retry_in", backoff)

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
		logger.Info("Connected to gateway", "id", c.config.ClientID, "attempt", connectionAttempts)

		// Handle messages until connection fails or context is cancelled
		c.handleMessages()

		// Check if we're stopping
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		// Connection lost, cleanup and retry
		logger.Info("Connection lost, retrying", "id", c.config.ClientID, "attempts", connectionAttempts)
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

	// Get connection count before closing
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	// Close all connections
	if connectionCount > 0 {
		c.closeAllConnections()
	}

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

	connectionCount := len(c.conns)
	if connectionCount == 0 {
		return
	}

	closedCount := 0
	for connID, conn := range c.conns {
		if err := conn.Close(); err != nil {
			logger.Warn("Error closing connection", "id", c.config.ClientID, "conn", connID, "err", err)
		} else {
			closedCount++
		}
	}
	c.conns = make(map[string]net.Conn)

	// Close all message channels
	c.msgChansMu.Lock()
	for connID, msgChan := range c.msgChans {
		close(msgChan)
		delete(c.msgChans, connID)
	}
	c.msgChansMu.Unlock()
}

// connect establishes a WebSocket connection to the gateway
func (c *Client) connect() error {
	// Create TLS configuration
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		logger.Error("Failed to create TLS config", "id", c.config.ClientID, "err", err)
		return err
	}

	// Parse the gateway URL
	gatewayURL := url.URL{
		Scheme: "wss",
		Host:   c.config.GatewayAddr,
		Path:   "/ws",
	}

	// Set up headers
	clientID := c.generateClientID()
	headers := http.Header{}
	headers.Set("X-Client-ID", clientID)
	headers.Set("X-Group-ID", c.config.GroupID)

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
	logger.Info("Connecting to WebSocket", "id", c.config.ClientID, "url", gatewayURL.String())
	conn, resp, err := dialer.Dial(gatewayURL.String(), headers)

	if err != nil {
		var statusCode int
		if resp != nil {
			statusCode = resp.StatusCode
		}
		logger.Error("WebSocket connect failed", "id", c.config.ClientID, "status", statusCode, "err", err)
		return fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	c.wsConn = conn

	// Create and start WebSocket writer
	c.writer = NewWebSocketWriter(conn, c.writeBuf)
	c.writer.Start()

	// Send port forwarding request if configured
	if len(c.config.OpenPorts) > 0 {
		if err := c.sendPortForwardingRequest(); err != nil {
			logger.Error("Port forward request failed", "id", c.config.ClientID, "err", err)
			// Continue anyway, port forwarding is optional
		}
	}

	logger.Info("WebSocket connected", "id", c.config.ClientID)
	return nil
}

func (c *Client) generateClientID() string {
	return fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
}

// createTLSConfig creates a TLS configuration for the client
func (c *Client) createTLSConfig() (*tls.Config, error) {
	serverName := strings.Split(c.config.GatewayAddr, ":")[0]
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	// If a certificate file is provided, load it
	if c.config.GatewayTLSCert != "" {
		caCert, err := os.ReadFile(c.config.GatewayTLSCert)
		if err != nil {
			logger.Error("Failed to read TLS cert", "id", c.config.ClientID, "file", c.config.GatewayTLSCert, "err", err)
			return nil, fmt.Errorf("failed to read gateway TLS certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			logger.Error("Failed to parse gateway TLS certificate", "id", c.config.ClientID)
			return nil, fmt.Errorf("failed to parse gateway TLS certificate")
		}
		tlsConfig.RootCAs = caCertPool
	} else {
		logger.Debug("Using system default TLS certificates", "id", c.config.ClientID)
	}

	return tlsConfig, nil
}

// handleMessages processes incoming messages from the gateway with context awareness
func (c *Client) handleMessages() {
	messageCount := 0
	lastLogTime := time.Now()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Message handler stopping due to context cancellation", "id", c.config.ClientID, "messages_processed", messageCount)
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
				logger.Info("WebSocket connection closed normally", "id", c.config.ClientID, "messages_processed", messageCount, "err", err)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				logger.Error("Unexpected WebSocket close", "id", c.config.ClientID, "messages_processed", messageCount, "err", err)
			} else {
				logger.Error("WebSocket read error", "id", c.config.ClientID, "messages_processed", messageCount, "err", err)
			}

			// Connection failed, exit to trigger reconnection
			return
		}

		messageCount++

		// Log message statistics periodically (every 100 messages or 30 seconds)
		if messageCount%100 == 0 || time.Since(lastLogTime) > 30*time.Second {
			logger.Debug("Message processing statistics", "id", c.config.ClientID, "messages_processed", messageCount)
			lastLogTime = time.Now()
		}

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			logger.Error("Invalid message format from gateway - missing type field", "id", c.config.ClientID, "message_count", messageCount, "message_fields", getMessageFields(msg))
			continue
		}

		// Log message processing (but not for high-frequency data messages)
		if msgType != MsgTypeData {
			logger.Debug("Processing gateway message", "id", c.config.ClientID, "message_type", msgType, "message_count", messageCount)
		}

		switch msgType {
		case MsgTypeConnect, MsgTypeData, MsgTypeClose:
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		case MsgTypePortForwardResp:
			// Handle port forwarding response directly
			logger.Debug("Received port forwarding response", "id", c.config.ClientID)
			c.handlePortForwardResponse(msg)
		default:
			logger.Warn("Unknown message type from gateway", "id", c.config.ClientID, "message_type", msgType, "message_count", messageCount)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel
func (c *Client) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in message from gateway", "id", c.config.ClientID, "message_fields", getMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// For connect messages, create the channel first
	if msgType == MsgTypeConnect {
		logger.Debug("Creating message channel for new connection request", "id", c.config.ClientID, "conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// Connection doesn't exist, ignore message
		logger.Debug("Ignoring message for non-existent connection", "id", c.config.ClientID, "conn_id", connID, "message_type", msgType)
		return
	}

	// Send message to connection's channel (non-blocking with context awareness)
	select {
	case msgChan <- msg:
		// Successfully routed, don't log for high-frequency data messages
		if msgType != MsgTypeData {
			logger.Debug("Message routed to connection handler", "id", c.config.ClientID, "conn_id", connID, "message_type", msgType)
		}
	case <-c.ctx.Done():
		logger.Debug("Message routing cancelled due to context", "id", c.config.ClientID, "conn_id", connID, "message_type", msgType)
		return
	default:
		logger.Warn("Message channel full for connection, dropping message", "id", c.config.ClientID, "conn_id", connID, "message_type", msgType)
	}
}

// createMessageChannel creates a message channel for a connection
func (c *Client) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// Check if channel already exists
	if _, exists := c.msgChans[connID]; exists {
		logger.Debug("Message channel already exists for connection", "id", c.config.ClientID, "conn_id", connID)
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // Buffer for 100 messages
	c.msgChans[connID] = msgChan

	logger.Debug("Created message channel for connection", "id", c.config.ClientID, "conn_id", connID, "buffer_size", 100)

	// Start message processor for this connection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages processes messages for a specific connection in order
func (c *Client) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
	logger.Debug("Starting connection message processor", "id", c.config.ClientID, "conn_id", connID)

	messagesProcessed := 0

	defer func() {
		logger.Debug("Connection message processor finished", "id", c.config.ClientID, "conn_id", connID, "messages_processed", messagesProcessed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection message processor stopping due to context", "id", c.config.ClientID, "conn_id", connID, "messages_processed", messagesProcessed)
			return
		case msg, ok := <-msgChan:
			if !ok {
				logger.Debug("Message channel closed for connection", "id", c.config.ClientID, "conn_id", connID, "messages_processed", messagesProcessed)
				return
			}

			messagesProcessed++
			msgType, _ := msg["type"].(string)

			switch msgType {
			case MsgTypeConnect:
				c.handleConnectMessage(msg)
			case MsgTypeData:
				c.handleDataMessage(msg)
			case MsgTypeClose:
				logger.Debug("Received close message, stopping connection processor", "id", c.config.ClientID, "conn_id", connID, "messages_processed", messagesProcessed)
				c.handleCloseMessage(msg)
				return // Connection closed, stop processing
			default:
				logger.Warn("Unknown message type in connection processor", "id", c.config.ClientID, "conn_id", connID, "message_type", msgType)
			}
		}
	}
}

// handleConnectMessage processes a connect message from the gateway
func (c *Client) handleConnectMessage(msg map[string]interface{}) {
	// Extract connection information
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in connect message", "id", c.config.ClientID, "message_fields", getMessageFields(msg))
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		logger.Error("Invalid network in connect message", "id", c.config.ClientID, "conn_id", connID, "message_fields", getMessageFields(msg))
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		logger.Error("Invalid address in connect message", "id", c.config.ClientID, "conn_id", connID, "message_fields", getMessageFields(msg))
		return
	}

	logger.Info("Processing connect request from gateway", "id", c.config.ClientID, "conn_id", connID, "network", network, "address", address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		logger.Warn("Connection denied - forbidden host", "id", c.config.ClientID, "conn_id", connID, "address", address, "allowed_hosts", c.config.AllowedHosts, "forbidden_hosts", c.config.ForbiddenHosts)
		if err := c.sendConnectResponse(connID, false, "Host is forbidden"); err != nil {
			logger.Error("Failed to send connect response for forbidden host", "id", c.config.ClientID, "conn_id", connID, "err", err)
		}
		return
	}
	logger.Debug("Connection allowed by host filtering rules", "id", c.config.ClientID, "conn_id", connID, "address", address)

	// Establish connection to the target with context
	logger.Debug("Establishing connection to target", "id", c.config.ClientID, "conn_id", connID, "network", network, "address", address)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	connectStart := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	connectDuration := time.Since(connectStart)

	if err != nil {
		logger.Error("Failed to establish connection to target", "id", c.config.ClientID, "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration, "err", err)
		if sendErr := c.sendConnectResponse(connID, false, err.Error()); sendErr != nil {
			logger.Error("Failed to send connect response for connection error", "id", c.config.ClientID, "conn_id", connID, "original_error", err, "send_error", sendErr)
		}
		return
	}

	logger.Info("Successfully connected to target", "id", c.config.ClientID, "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration)

	// Register the connection
	c.connsMu.Lock()
	c.conns[connID] = conn
	connectionCount := len(c.conns)
	c.connsMu.Unlock()

	logger.Debug("Connection registered", "id", c.config.ClientID, "conn_id", connID, "total_connections", connectionCount)

	// Send success response
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		logger.Error("Error sending connect_response to gateway", "id", c.config.ClientID, "conn_id", connID, "err", err)
		c.cleanupConnection(connID)
		return
	}

	// Start handling the connection
	logger.Debug("Starting connection handler", "id", c.config.ClientID, "conn_id", connID)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleConnection(connID)
	}()
}

// sendConnectResponse sends a connection response to the gateway
func (c *Client) sendConnectResponse(connID string, success bool, errorMsg string) error {
	response := map[string]interface{}{
		"type":    MsgTypeConnectResponse,
		"id":      connID,
		"success": success,
	}

	if !success && errorMsg != "" {
		response["error"] = errorMsg
	}

	logger.Debug("Sending connect response to gateway", "id", c.config.ClientID, "conn_id", connID, "success", success, "error_message", errorMsg)

	err := c.writer.WriteJSON(response)
	if err != nil {
		logger.Error("Failed to write connect response to WebSocket", "id", c.config.ClientID, "conn_id", connID, "success", success, "err", err)
	} else {
		logger.Debug("Connect response sent successfully", "id", c.config.ClientID, "conn_id", connID, "success", success)
	}

	return err
}

// handleConnection reads from the target connection and sends data to gateway with context awareness
func (c *Client) handleConnection(connID string) {
	logger.Debug("Starting connection handler", "id", c.config.ClientID, "conn_id", connID)

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		logger.Warn("Connection handler started for unknown connection", "id", c.config.ClientID, "conn_id", connID)
		return
	}

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer to match gateway
	totalBytes := 0
	readCount := 0
	startTime := time.Now()

	defer func() {
		elapsed := time.Since(startTime)
		logger.Debug("Connection handler finished", "id", c.config.ClientID, "conn_id", connID, "total_bytes", totalBytes, "read_operations", readCount, "duration", elapsed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection handler stopping due to context cancellation", "id", c.config.ClientID, "conn_id", connID, "total_bytes", totalBytes)
			return
		default:
		}

		// Set read deadline based on context - use longer timeout for proxy connections
		deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			logger.Warn("Failed to set read deadline", "id", c.config.ClientID, "conn_id", connID, "err", err)
		}

		n, err := conn.Read(buffer)
		readCount++

		if n > 0 {
			totalBytes += n
			// Only log for larger transfers to reduce noise
			if totalBytes%100000 == 0 || n > 10000 {
				logger.Debug("Client read data from target connection", "id", c.config.ClientID, "conn_id", connID, "bytes_this_read", n, "total_bytes", totalBytes, "read_count", readCount)
			}

			// Encode binary data as base64 string
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			writeErr := c.writer.WriteJSON(map[string]interface{}{
				"type": MsgTypeData,
				"id":   connID,
				"data": encodedData,
			})
			if writeErr != nil {
				logger.Error("Error writing data to WebSocket", "id", c.config.ClientID, "conn_id", connID, "data_bytes", n, "total_bytes", totalBytes, "err", writeErr)
				c.cleanupConnection(connID)
				return
			}

			// Only log for larger transfers
			if n > 10000 {
				logger.Debug("Client successfully sent large data chunk to gateway", "id", c.config.ClientID, "conn_id", connID, "bytes", n, "total_bytes", totalBytes)
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if timeout is due to context cancellation
				select {
				case <-c.ctx.Done():
					logger.Debug("Connection handler stopping due to context during timeout", "id", c.config.ClientID, "conn_id", connID)
					return
				default:
					continue // Continue on timeout if context is still valid
				}
			}

			// Handle connection closed errors gracefully
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				logger.Debug("Target connection closed during read operation", "id", c.config.ClientID, "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			} else if err != io.EOF {
				logger.Error("Error reading from target connection", "id", c.config.ClientID, "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount, "err", err)
			} else {
				logger.Debug("Target connection closed (EOF)", "id", c.config.ClientID, "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			}

			// Send close message to gateway
			closeErr := c.writer.WriteJSON(map[string]interface{}{
				"type": MsgTypeClose,
				"id":   connID,
			})
			if closeErr != nil {
				logger.Warn("Error sending close message to gateway", "id", c.config.ClientID, "conn_id", connID, "err", closeErr)
			} else {
				logger.Debug("Sent close message to gateway", "id", c.config.ClientID, "conn_id", connID)
			}

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

	logger.Debug("Checking connection permissions", "id", c.config.ClientID, "address", address, "extracted_host", host, "allowed_hosts_count", len(c.config.AllowedHosts), "forbidden_hosts_count", len(c.config.ForbiddenHosts))

	// Check forbidden hosts first
	for _, forbidden := range c.config.ForbiddenHosts {
		re := regexp.MustCompile(forbidden)
		if re.MatchString(host) {
			logger.Debug("Connection rejected by forbidden regex pattern", "id", c.config.ClientID, "host", host, "forbidden_pattern", forbidden)
			return false
		}

		if strings.HasSuffix(host, forbidden) {
			logger.Debug("Connection rejected by forbidden suffix", "id", c.config.ClientID, "host", host, "forbidden_suffix", forbidden)
			return false
		}
	}

	// If no allowed hosts specified, allow all (except forbidden)
	if len(c.config.AllowedHosts) == 0 {
		logger.Debug("Connection allowed - no allowed hosts restrictions", "id", c.config.ClientID, "host", host)
		return true
	}

	// Check allowed hosts
	for _, allowed := range c.config.AllowedHosts {
		re := regexp.MustCompile(allowed)
		if re.MatchString(host) {
			logger.Debug("Connection allowed by regex pattern", "id", c.config.ClientID, "host", host, "allowed_pattern", allowed)
			return true
		}

		if strings.HasSuffix(host, allowed) {
			logger.Debug("Connection allowed by suffix", "id", c.config.ClientID, "host", host, "allowed_suffix", allowed)
			return true
		}
	}

	logger.Debug("Connection rejected - not in allowed hosts", "id", c.config.ClientID, "host", host, "allowed_hosts", c.config.AllowedHosts)
	return false
}

// handleDataMessage processes a data message from the gateway
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// Extract message information
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in data message", "id", c.config.ClientID, "message_fields", getMessageFields(msg))
		return
	}

	dataStr, ok := msg["data"].(string)
	if !ok {
		logger.Error("Invalid data format in data message", "id", c.config.ClientID, "conn_id", connID, "data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		logger.Error("Failed to decode base64 data", "id", c.config.ClientID, "conn_id", connID, "data_length", len(dataStr), "err", err)
		return
	}

	// Only log for larger transfers to reduce noise
	if len(data) > 10000 {
		logger.Debug("Client received large data chunk from gateway", "id", c.config.ClientID, "conn_id", connID, "bytes", len(data))
	}

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		logger.Warn("Data message for unknown connection", "id", c.config.ClientID, "conn_id", connID, "data_bytes", len(data))
		return
	}

	// Write data to the connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		logger.Warn("Failed to set write deadline", "id", c.config.ClientID, "conn_id", connID, "err", err)
	}

	n, err := conn.Write(data)
	if err != nil {
		logger.Error("Failed to write data to target connection", "id", c.config.ClientID, "conn_id", connID, "data_bytes", len(data), "written_bytes", n, "err", err)
		c.cleanupConnection(connID)
		return
	}

	// Only log for larger transfers
	if n > 10000 {
		logger.Debug("Client successfully wrote large data chunk to target connection", "id", c.config.ClientID, "conn_id", connID, "bytes", n)
	}
}

// handleCloseMessage processes a close message from the gateway
func (c *Client) handleCloseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in close message", "id", c.config.ClientID, "message_fields", getMessageFields(msg))
		return
	}

	logger.Info("Received close message from gateway", "id", c.config.ClientID, "conn_id", connID)
	c.cleanupConnection(connID)
}

// cleanupConnection cleans up a connection
func (c *Client) cleanupConnection(connID string) {
	logger.Debug("Initiating connection cleanup", "id", c.config.ClientID, "conn_id", connID)

	c.connsMu.Lock()
	conn, exists := c.conns[connID]
	if exists {
		delete(c.conns, connID)
	}
	remainingConnections := len(c.conns)
	c.connsMu.Unlock()

	// Clean up message channel
	c.msgChansMu.Lock()
	if msgChan, exists := c.msgChans[connID]; exists {
		delete(c.msgChans, connID)
		close(msgChan)
		logger.Debug("Message channel closed and removed", "id", c.config.ClientID, "conn_id", connID)
	}
	c.msgChansMu.Unlock()

	if exists && conn != nil {
		if err := conn.Close(); err != nil {
			logger.Debug("Error closing target connection (expected during shutdown)", "id", c.config.ClientID, "conn_id", connID, "err", err)
		} else {
			logger.Debug("Target connection closed successfully", "id", c.config.ClientID, "conn_id", connID)
		}

		logger.Info("Connection cleaned up successfully", "id", c.config.ClientID, "conn_id", connID, "remaining_connections", remainingConnections)
	} else {
		logger.Debug("Connection cleanup requested for non-existent connection", "id", c.config.ClientID, "conn_id", connID)
	}
}

// sendPortForwardingRequest sends a port forwarding request to the gateway
func (c *Client) sendPortForwardingRequest() error {
	if len(c.config.OpenPorts) == 0 {
		logger.Debug("No ports configured for forwarding", "id", c.config.ClientID)
		return nil
	}

	logger.Info("Sending port forwarding request to gateway", "id", c.config.ClientID, "port_count", len(c.config.OpenPorts))

	// Log details of each port configuration
	for i, openPort := range c.config.OpenPorts {
		logger.Debug("Port forwarding configuration", "id", c.config.ClientID, "port_index", i, "remote_port", openPort.RemotePort, "local_port", openPort.LocalPort, "local_host", openPort.LocalHost, "protocol", openPort.Protocol)
	}

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

	err := c.writer.WriteJSON(request)
	if err != nil {
		logger.Error("Failed to send port forwarding request", "id", c.config.ClientID, "port_count", len(c.config.OpenPorts), "err", err)
	} else {
		logger.Debug("Port forwarding request sent successfully", "id", c.config.ClientID, "port_count", len(c.config.OpenPorts))
	}

	return err
}

// Helper function to get safe message field names for logging
func getMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}

// handlePortForwardResponse processes a port forwarding response from the gateway
func (c *Client) handlePortForwardResponse(msg map[string]interface{}) {
	// Extract response information
	success, ok := msg["success"].(bool)
	if !ok {
		logger.Error("Invalid success status in port forwarding response", "id", c.config.ClientID, "message_fields", getMessageFields(msg))
		return
	}

	message, _ := msg["message"].(string)

	if success {
		logger.Info("Port forwarding request successful", "id", c.config.ClientID, "message", message, "port_count", len(c.config.OpenPorts))
	} else {
		logger.Error("Port forwarding request failed", "id", c.config.ClientID, "message", message, "port_count", len(c.config.OpenPorts))
	}
}
