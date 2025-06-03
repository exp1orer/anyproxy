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
	slog.Info("Creating new client",
		"client_id", cfg.ClientID,
		"gateway_addr", cfg.GatewayAddr,
		"group_id", cfg.GroupID,
		"allowed_hosts_count", len(cfg.AllowedHosts),
		"forbidden_hosts_count", len(cfg.ForbiddenHosts),
		"open_ports_count", len(cfg.OpenPorts),
		"auth_enabled", cfg.AuthUsername != "")

	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		config:   cfg,
		conns:    make(map[string]net.Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
		writeBuf: make(chan interface{}, writeBufSize),
	}

	slog.Debug("Client initialization completed",
		"client_id", cfg.ClientID,
		"write_buffer_size", writeBufSize)

	return client, nil
}

// Start starts the client with automatic reconnection
func (c *Client) Start() error {
	slog.Info("Starting proxy client",
		"client_id", c.config.ClientID,
		"gateway_addr", c.config.GatewayAddr,
		"group_id", c.config.GroupID)

	startTime := time.Now()

	// Start the main connection loop with reconnection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectionLoop()
	}()

	elapsed := time.Since(startTime)
	slog.Info("Client started successfully",
		"client_id", c.config.ClientID,
		"startup_duration", elapsed)

	return nil
}

// Stop stops the client gracefully
func (c *Client) Stop() error {
	slog.Info("Initiating graceful client shutdown", "client_id", c.config.ClientID)
	stopTime := time.Now()

	// Step 1: Signal all goroutines to stop accepting new work
	slog.Debug("Cancelling client context", "client_id", c.config.ClientID)
	c.cancel()

	// Step 2: Get connection count before cleanup
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	if connectionCount > 0 {
		slog.Info("Waiting for active connections to finish",
			"client_id", c.config.ClientID,
			"connection_count", connectionCount)
	}

	// Give existing connections time to finish current operations
	gracefulWait := func(duration time.Duration) bool {
		select {
		case <-c.ctx.Done():
			return false // Already cancelled
		case <-time.After(duration):
			return true // Wait completed
		}
	}
	if gracefulWait(500 * time.Millisecond) {
		slog.Debug("Graceful wait completed", "client_id", c.config.ClientID)
	} else {
		slog.Debug("Graceful wait skipped - context cancelled", "client_id", c.config.ClientID)
	}

	// Step 3: Stop WebSocket writer - this will close the WebSocket connection
	if c.writer != nil {
		slog.Debug("Stopping WebSocket writer", "client_id", c.config.ClientID)
		c.writer.Stop()
		slog.Debug("WebSocket writer stopped", "client_id", c.config.ClientID)
	}

	// Step 4: Close all remaining connections
	slog.Debug("Closing all connections",
		"client_id", c.config.ClientID,
		"connection_count", connectionCount)
	c.closeAllConnections()
	if connectionCount > 0 {
		slog.Debug("All connections closed", "client_id", c.config.ClientID)
	}

	// Step 5: Wait for all goroutines to finish with timeout
	slog.Debug("Waiting for all goroutines to finish", "client_id", c.config.ClientID)
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Debug("All client goroutines finished gracefully", "client_id", c.config.ClientID)
	case <-time.After(3 * time.Second):
		slog.Warn("Timeout waiting for client goroutines to finish", "client_id", c.config.ClientID)
	}

	elapsed := time.Since(stopTime)
	slog.Info("Client shutdown completed",
		"client_id", c.config.ClientID,
		"shutdown_duration", elapsed,
		"connections_closed", connectionCount)

	return nil
}

// connectionLoop handles connection and reconnection logic with context-aware backoff
func (c *Client) connectionLoop() {
	slog.Debug("Starting connection loop", "client_id", c.config.ClientID)

	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second
	connectionAttempts := 0

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection loop stopping due to context cancellation",
				"client_id", c.config.ClientID,
				"total_attempts", connectionAttempts)
			return
		default:
		}

		connectionAttempts++
		slog.Debug("Attempting to connect to gateway",
			"client_id", c.config.ClientID,
			"attempt", connectionAttempts,
			"gateway_addr", c.config.GatewayAddr)

		// Attempt to connect
		connectStart := time.Now()
		if err := c.connect(); err != nil {
			connectDuration := time.Since(connectStart)
			slog.Error("Failed to connect to gateway",
				"client_id", c.config.ClientID,
				"attempt", connectionAttempts,
				"connect_duration", connectDuration,
				"error", err,
				"retrying_in", backoff)

			// Context-aware wait before retry
			select {
			case <-c.ctx.Done():
				slog.Debug("Connection retry cancelled due to context",
					"client_id", c.config.ClientID)
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
		connectDuration := time.Since(connectStart)
		backoff = 1 * time.Second
		slog.Info("Successfully connected to gateway",
			"client_id", c.config.ClientID,
			"attempt", connectionAttempts,
			"connect_duration", connectDuration,
			"gateway_addr", c.config.GatewayAddr)

		// Handle messages until connection fails or context is cancelled
		messageStart := time.Now()
		c.handleMessages()
		messageDuration := time.Since(messageStart)

		// Check if we're stopping
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection loop ending due to context cancellation",
				"client_id", c.config.ClientID,
				"message_handling_duration", messageDuration)
			return
		default:
		}

		// Connection lost, cleanup and retry
		slog.Info("Connection to gateway lost, cleaning up and retrying...",
			"client_id", c.config.ClientID,
			"message_handling_duration", messageDuration,
			"total_attempts", connectionAttempts)
		c.cleanup()
	}
}

// cleanup cleans up resources after connection loss
func (c *Client) cleanup() {
	slog.Debug("Starting cleanup after connection loss", "client_id", c.config.ClientID)
	cleanupStart := time.Now()

	// Stop writer first - this will close the WebSocket connection
	// and stop using writeBuf
	if c.writer != nil {
		slog.Debug("Stopping WebSocket writer during cleanup", "client_id", c.config.ClientID)
		c.writer.Stop()
		c.writer = nil
		slog.Debug("WebSocket writer stopped", "client_id", c.config.ClientID)
	}

	// Clear the connection reference (already closed by writer)
	c.wsConn = nil

	// Get connection count before closing
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	// Close all connections
	if connectionCount > 0 {
		slog.Debug("Closing connections during cleanup",
			"client_id", c.config.ClientID,
			"connection_count", connectionCount)
		c.closeAllConnections()
	}

	// Close write buffer and recreate for next connection (only if not stopping)
	if c.writeBuf != nil {
		close(c.writeBuf)
		c.writeBuf = nil
		slog.Debug("Closed write buffer", "client_id", c.config.ClientID)
	}

	select {
	case <-c.ctx.Done():
		// Don't recreate if we're stopping
		slog.Debug("Not recreating write buffer - client stopping", "client_id", c.config.ClientID)
	default:
		c.writeBuf = make(chan interface{}, writeBufSize)
		slog.Debug("Recreated write buffer for next connection",
			"client_id", c.config.ClientID,
			"buffer_size", writeBufSize)
	}

	elapsed := time.Since(cleanupStart)
	slog.Debug("Cleanup completed",
		"client_id", c.config.ClientID,
		"cleanup_duration", elapsed,
		"connections_closed", connectionCount)
}

// closeAllConnections closes all active connections
func (c *Client) closeAllConnections() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	connectionCount := len(c.conns)
	if connectionCount == 0 {
		slog.Debug("No connections to close", "client_id", c.config.ClientID)
		return
	}

	slog.Debug("Closing all active connections",
		"client_id", c.config.ClientID,
		"connection_count", connectionCount)

	closedCount := 0
	for connID, conn := range c.conns {
		if err := conn.Close(); err != nil {
			slog.Debug("Error closing connection (expected during shutdown)",
				"client_id", c.config.ClientID,
				"conn_id", connID,
				"error", err)
		} else {
			closedCount++
		}
	}
	c.conns = make(map[string]net.Conn)

	// Close all message channels
	c.msgChansMu.Lock()
	channelCount := len(c.msgChans)
	for connID, msgChan := range c.msgChans {
		close(msgChan)
		delete(c.msgChans, connID)
	}
	c.msgChansMu.Unlock()

	slog.Debug("All connections and channels closed",
		"client_id", c.config.ClientID,
		"connections_closed", closedCount,
		"channels_closed", channelCount)
}

// connect establishes a WebSocket connection to the gateway
func (c *Client) connect() error {
	slog.Debug("Establishing WebSocket connection to gateway",
		"client_id", c.config.ClientID,
		"gateway_addr", c.config.GatewayAddr)

	// Create TLS configuration
	slog.Debug("Creating TLS configuration", "client_id", c.config.ClientID)
	tlsConfig, err := c.createTLSConfig()
	if err != nil {
		slog.Error("Failed to create TLS configuration",
			"client_id", c.config.ClientID,
			"error", err)
		return err
	}
	slog.Debug("TLS configuration created successfully", "client_id", c.config.ClientID)

	// Parse the gateway URL
	gatewayURL := url.URL{
		Scheme: "wss",
		Host:   c.config.GatewayAddr,
		Path:   "/ws",
	}
	slog.Debug("Gateway URL constructed",
		"client_id", c.config.ClientID,
		"url", gatewayURL.String())

	// Set up headers
	clientID := c.generateClientID()
	headers := http.Header{}
	headers.Set("X-Client-ID", clientID)
	headers.Set("X-Group-ID", c.config.GroupID)
	slog.Debug("WebSocket headers prepared",
		"client_id", c.config.ClientID,
		"generated_client_id", clientID,
		"group_id", c.config.GroupID)

	// Use Basic Auth for authentication
	auth := base64.StdEncoding.EncodeToString(
		[]byte(c.config.AuthUsername + ":" + c.config.AuthPassword),
	)
	headers.Set("Authorization", "Basic "+auth)
	slog.Debug("Authentication header set", "client_id", c.config.ClientID)

	// Create WebSocket dialer with context
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}
	slog.Debug("WebSocket dialer configured",
		"client_id", c.config.ClientID,
		"handshake_timeout", "10s")

	// Connect to WebSocket
	slog.Info("Connecting to WebSocket endpoint",
		"client_id", c.config.ClientID,
		"url", gatewayURL.String())
	connectStart := time.Now()
	conn, resp, err := dialer.Dial(gatewayURL.String(), headers)
	connectDuration := time.Since(connectStart)

	if err != nil {
		var statusCode int
		if resp != nil {
			statusCode = resp.StatusCode
		}
		slog.Error("Failed to connect to WebSocket",
			"client_id", c.config.ClientID,
			"url", gatewayURL.String(),
			"connect_duration", connectDuration,
			"status_code", statusCode,
			"error", err)
		return fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	if resp != nil {
		slog.Debug("WebSocket connection established",
			"client_id", c.config.ClientID,
			"status_code", resp.StatusCode,
			"connect_duration", connectDuration)
	}

	c.wsConn = conn

	// Create and start WebSocket writer
	slog.Debug("Creating WebSocket writer", "client_id", c.config.ClientID)
	c.writer = NewWebSocketWriter(conn, c.writeBuf)
	c.writer.Start()
	slog.Debug("WebSocket writer started", "client_id", c.config.ClientID)

	// Send port forwarding request if configured
	if len(c.config.OpenPorts) > 0 {
		slog.Debug("Sending port forwarding request",
			"client_id", c.config.ClientID,
			"port_count", len(c.config.OpenPorts))
		if err := c.sendPortForwardingRequest(); err != nil {
			slog.Error("Failed to send port forwarding request",
				"client_id", c.config.ClientID,
				"error", err)
			// Continue anyway, port forwarding is optional
		}
	} else {
		slog.Debug("No port forwarding configured", "client_id", c.config.ClientID)
	}

	slog.Info("WebSocket connection fully established",
		"client_id", c.config.ClientID,
		"total_setup_duration", time.Since(connectStart))

	return nil
}

func (c *Client) generateClientID() string {
	generatedID := fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
	slog.Debug("Generated unique client ID",
		"base_client_id", c.config.ClientID,
		"generated_client_id", generatedID)
	return generatedID
}

// createTLSConfig creates a TLS configuration for the client
func (c *Client) createTLSConfig() (*tls.Config, error) {
	serverName := strings.Split(c.config.GatewayAddr, ":")[0]
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}

	slog.Debug("Base TLS configuration created",
		"client_id", c.config.ClientID,
		"server_name", serverName,
		"min_version", "TLS 1.2")

	// If a certificate file is provided, load it
	if c.config.GatewayTLSCert != "" {
		slog.Debug("Loading custom gateway TLS certificate",
			"client_id", c.config.ClientID,
			"cert_file", c.config.GatewayTLSCert)

		caCert, err := os.ReadFile(c.config.GatewayTLSCert)
		if err != nil {
			slog.Error("Failed to read gateway TLS certificate file",
				"client_id", c.config.ClientID,
				"cert_file", c.config.GatewayTLSCert,
				"error", err)
			return nil, fmt.Errorf("failed to read gateway TLS certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			slog.Error("Failed to parse gateway TLS certificate",
				"client_id", c.config.ClientID,
				"cert_file", c.config.GatewayTLSCert)
			return nil, fmt.Errorf("failed to parse gateway TLS certificate")
		}
		tlsConfig.RootCAs = caCertPool

		slog.Debug("Custom TLS certificate loaded successfully",
			"client_id", c.config.ClientID,
			"cert_file", c.config.GatewayTLSCert)
	} else {
		slog.Debug("Using system default TLS certificates", "client_id", c.config.ClientID)
	}

	return tlsConfig, nil
}

// handleMessages processes incoming messages from the gateway with context awareness
func (c *Client) handleMessages() {
	slog.Debug("Starting message handler for gateway messages", "client_id", c.config.ClientID)
	messageCount := 0
	lastLogTime := time.Now()

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Message handler stopping due to context cancellation",
				"client_id", c.config.ClientID,
				"messages_processed", messageCount)
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
				slog.Info("WebSocket connection closed normally",
					"client_id", c.config.ClientID,
					"messages_processed", messageCount,
					"error", err)
			} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				slog.Error("Unexpected WebSocket close",
					"client_id", c.config.ClientID,
					"messages_processed", messageCount,
					"error", err)
			} else {
				slog.Error("WebSocket read error",
					"client_id", c.config.ClientID,
					"messages_processed", messageCount,
					"error", err)
			}

			// Connection failed, exit to trigger reconnection
			return
		}

		messageCount++

		// Log message statistics periodically (every 100 messages or 30 seconds)
		if messageCount%100 == 0 || time.Since(lastLogTime) > 30*time.Second {
			slog.Debug("Message processing statistics",
				"client_id", c.config.ClientID,
				"messages_processed", messageCount)
			lastLogTime = time.Now()
		}

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from gateway - missing type field",
				"client_id", c.config.ClientID,
				"message_count", messageCount,
				"message_fields", getMessageFields(msg))
			continue
		}

		// Log message processing (but not for high-frequency data messages)
		if msgType != "data" {
			slog.Debug("Processing gateway message",
				"client_id", c.config.ClientID,
				"message_type", msgType,
				"message_count", messageCount)
		}

		switch msgType {
		case "connect", "data", "close":
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		case "port_forward_response":
			// Handle port forwarding response directly
			slog.Debug("Received port forwarding response", "client_id", c.config.ClientID)
			c.handlePortForwardResponse(msg)
		default:
			slog.Warn("Unknown message type from gateway",
				"client_id", c.config.ClientID,
				"message_type", msgType,
				"message_count", messageCount)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel
func (c *Client) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message from gateway",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// For connect messages, create the channel first
	if msgType == "connect" {
		slog.Debug("Creating message channel for new connection request",
			"client_id", c.config.ClientID,
			"conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// Connection doesn't exist, ignore message
		slog.Debug("Ignoring message for non-existent connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_type", msgType)
		return
	}

	// Send message to connection's channel (non-blocking with context awareness)
	select {
	case msgChan <- msg:
		// Successfully routed, don't log for high-frequency data messages
		if msgType != "data" {
			slog.Debug("Message routed to connection handler",
				"client_id", c.config.ClientID,
				"conn_id", connID,
				"message_type", msgType)
		}
	case <-c.ctx.Done():
		slog.Debug("Message routing cancelled due to context",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_type", msgType)
		return
	default:
		slog.Warn("Message channel full for connection, dropping message",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_type", msgType)
	}
}

// createMessageChannel creates a message channel for a connection
func (c *Client) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// Check if channel already exists
	if _, exists := c.msgChans[connID]; exists {
		slog.Debug("Message channel already exists for connection",
			"client_id", c.config.ClientID,
			"conn_id", connID)
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // Buffer for 100 messages
	c.msgChans[connID] = msgChan

	slog.Debug("Created message channel for connection",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"buffer_size", 100)

	// Start message processor for this connection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages processes messages for a specific connection in order
func (c *Client) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
	slog.Debug("Starting connection message processor",
		"client_id", c.config.ClientID,
		"conn_id", connID)

	messagesProcessed := 0

	defer func() {
		slog.Debug("Connection message processor finished",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"messages_processed", messagesProcessed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection message processor stopping due to context",
				"client_id", c.config.ClientID,
				"conn_id", connID,
				"messages_processed", messagesProcessed)
			return
		case msg, ok := <-msgChan:
			if !ok {
				slog.Debug("Message channel closed for connection",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"messages_processed", messagesProcessed)
				return
			}

			messagesProcessed++
			msgType, _ := msg["type"].(string)

			switch msgType {
			case "connect":
				c.handleConnectMessage(msg)
			case "data":
				c.handleDataMessage(msg)
			case "close":
				slog.Debug("Received close message, stopping connection processor",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"messages_processed", messagesProcessed)
				c.handleCloseMessage(msg)
				return // Connection closed, stop processing
			default:
				slog.Warn("Unknown message type in connection processor",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"message_type", msgType)
			}
		}
	}
}

// handleConnectMessage processes a connect message from the gateway
func (c *Client) handleConnectMessage(msg map[string]interface{}) {
	// Extract connection information
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in connect message",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		slog.Error("Invalid network in connect message",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_fields", getMessageFields(msg))
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		slog.Error("Invalid address in connect message",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_fields", getMessageFields(msg))
		return
	}

	slog.Info("Processing connect request from gateway",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"network", network,
		"address", address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		slog.Warn("Connection denied - forbidden host",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"address", address,
			"allowed_hosts", c.config.AllowedHosts,
			"forbidden_hosts", c.config.ForbiddenHosts)
		c.sendConnectResponse(connID, false, "Host is forbidden")
		return
	}
	slog.Debug("Connection allowed by host filtering rules",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"address", address)

	// Establish connection to the target with context
	slog.Debug("Establishing connection to target",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"network", network,
		"address", address)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	connectStart := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	connectDuration := time.Since(connectStart)

	if err != nil {
		slog.Error("Failed to establish connection to target",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"network", network,
			"address", address,
			"connect_duration", connectDuration,
			"error", err)
		c.sendConnectResponse(connID, false, err.Error())
		return
	}

	slog.Info("Successfully connected to target",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"network", network,
		"address", address,
		"connect_duration", connectDuration)

	// Register the connection
	c.connsMu.Lock()
	c.conns[connID] = conn
	connectionCount := len(c.conns)
	c.connsMu.Unlock()

	slog.Debug("Connection registered",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"total_connections", connectionCount)

	// Send success response
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		slog.Error("Error sending connect_response to gateway",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"error", err)
		c.cleanupConnection(connID)
		return
	}

	// Start handling the connection
	slog.Debug("Starting connection handler",
		"client_id", c.config.ClientID,
		"conn_id", connID)
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

	slog.Debug("Sending connect response to gateway",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"success", success,
		"error_message", errorMsg)

	err := c.writer.WriteJSON(response)
	if err != nil {
		slog.Error("Failed to write connect response to WebSocket",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"success", success,
			"error", err)
	} else {
		slog.Debug("Connect response sent successfully",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"success", success)
	}

	return err
}

// handleConnection reads from the target connection and sends data to gateway with context awareness
func (c *Client) handleConnection(connID string) {
	slog.Debug("Starting connection handler",
		"client_id", c.config.ClientID,
		"conn_id", connID)

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		slog.Warn("Connection handler started for unknown connection",
			"client_id", c.config.ClientID,
			"conn_id", connID)
		return
	}

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer to match gateway
	totalBytes := 0
	readCount := 0
	startTime := time.Now()

	defer func() {
		elapsed := time.Since(startTime)
		slog.Debug("Connection handler finished",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"total_bytes", totalBytes,
			"read_operations", readCount,
			"duration", elapsed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection handler stopping due to context cancellation",
				"client_id", c.config.ClientID,
				"conn_id", connID,
				"total_bytes", totalBytes)
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
		readCount++

		if n > 0 {
			totalBytes += n
			// Only log for larger transfers to reduce noise
			if totalBytes%100000 == 0 || n > 10000 {
				slog.Debug("Client read data from target connection",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"bytes_this_read", n,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// Encode binary data as base64 string
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			writeErr := c.writer.WriteJSON(map[string]interface{}{
				"type": "data",
				"id":   connID,
				"data": encodedData,
			})
			if writeErr != nil {
				slog.Error("Error writing data to WebSocket",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"data_bytes", n,
					"total_bytes", totalBytes,
					"error", writeErr)
				c.cleanupConnection(connID)
				return
			}

			// Only log for larger transfers
			if n > 10000 {
				slog.Debug("Client successfully sent large data chunk to gateway",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"bytes", n,
					"total_bytes", totalBytes)
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check if timeout is due to context cancellation
				select {
				case <-c.ctx.Done():
					slog.Debug("Connection handler stopping due to context during timeout",
						"client_id", c.config.ClientID,
						"conn_id", connID)
					return
				default:
					continue // Continue on timeout if context is still valid
				}
			}

			// Handle connection closed errors gracefully
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				slog.Debug("Target connection closed during read operation",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			} else if err != io.EOF {
				slog.Error("Error reading from target connection",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount,
					"error", err)
			} else {
				slog.Debug("Target connection closed (EOF)",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// Send close message to gateway
			closeErr := c.writer.WriteJSON(map[string]interface{}{
				"type": "close",
				"id":   connID,
			})
			if closeErr != nil {
				slog.Debug("Error sending close message to gateway",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"error", closeErr)
			} else {
				slog.Debug("Sent close message to gateway",
					"client_id", c.config.ClientID,
					"conn_id", connID)
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

	slog.Debug("Checking connection permissions",
		"client_id", c.config.ClientID,
		"address", address,
		"extracted_host", host,
		"allowed_hosts_count", len(c.config.AllowedHosts),
		"forbidden_hosts_count", len(c.config.ForbiddenHosts))

	// Check forbidden hosts first
	for _, forbidden := range c.config.ForbiddenHosts {
		re := regexp.MustCompile(forbidden)
		if re.MatchString(host) {
			slog.Debug("Connection rejected by forbidden regex pattern",
				"client_id", c.config.ClientID,
				"host", host,
				"forbidden_pattern", forbidden)
			return false
		}

		if strings.HasSuffix(host, forbidden) {
			slog.Debug("Connection rejected by forbidden suffix",
				"client_id", c.config.ClientID,
				"host", host,
				"forbidden_suffix", forbidden)
			return false
		}
	}

	// If no allowed hosts specified, allow all (except forbidden)
	if len(c.config.AllowedHosts) == 0 {
		slog.Debug("Connection allowed - no allowed hosts restrictions",
			"client_id", c.config.ClientID,
			"host", host)
		return true
	}

	// Check allowed hosts
	for _, allowed := range c.config.AllowedHosts {
		re := regexp.MustCompile(allowed)
		if re.MatchString(host) {
			slog.Debug("Connection allowed by regex pattern",
				"client_id", c.config.ClientID,
				"host", host,
				"allowed_pattern", allowed)
			return true
		}

		if strings.HasSuffix(host, allowed) {
			slog.Debug("Connection allowed by suffix",
				"client_id", c.config.ClientID,
				"host", host,
				"allowed_suffix", allowed)
			return true
		}
	}

	slog.Debug("Connection rejected - not in allowed hosts",
		"client_id", c.config.ClientID,
		"host", host,
		"allowed_hosts", c.config.AllowedHosts)
	return false
}

// handleDataMessage processes a data message from the gateway
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// Extract message information
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in data message",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	dataStr, ok := msg["data"].(string)
	if !ok {
		slog.Error("Invalid data format in data message",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"data_length", len(dataStr),
			"error", err)
		return
	}

	// Only log for larger transfers to reduce noise
	if len(data) > 10000 {
		slog.Debug("Client received large data chunk from gateway",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"bytes", len(data))
	}

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		slog.Warn("Data message for unknown connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"data_bytes", len(data))
		return
	}

	// Write data to the connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	conn.SetWriteDeadline(deadline)

	n, err := conn.Write(data)
	if err != nil {
		slog.Error("Failed to write data to target connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"data_bytes", len(data),
			"written_bytes", n,
			"error", err)
		c.cleanupConnection(connID)
		return
	}

	// Only log for larger transfers
	if n > 10000 {
		slog.Debug("Client successfully wrote large data chunk to target connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"bytes", n)
	}
}

// handleCloseMessage processes a close message from the gateway
func (c *Client) handleCloseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in close message",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	slog.Info("Received close message from gateway",
		"client_id", c.config.ClientID,
		"conn_id", connID)
	c.cleanupConnection(connID)
}

// cleanupConnection cleans up a connection
func (c *Client) cleanupConnection(connID string) {
	slog.Debug("Initiating connection cleanup",
		"client_id", c.config.ClientID,
		"conn_id", connID)

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
		slog.Debug("Message channel closed and removed",
			"client_id", c.config.ClientID,
			"conn_id", connID)
	}
	c.msgChansMu.Unlock()

	if exists && conn != nil {
		if err := conn.Close(); err != nil {
			slog.Debug("Error closing target connection (expected during shutdown)",
				"client_id", c.config.ClientID,
				"conn_id", connID,
				"error", err)
		} else {
			slog.Debug("Target connection closed successfully",
				"client_id", c.config.ClientID,
				"conn_id", connID)
		}

		slog.Info("Connection cleaned up successfully",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"remaining_connections", remainingConnections)
	} else {
		slog.Debug("Connection cleanup requested for non-existent connection",
			"client_id", c.config.ClientID,
			"conn_id", connID)
	}
}

// sendPortForwardingRequest sends a port forwarding request to the gateway
func (c *Client) sendPortForwardingRequest() error {
	if len(c.config.OpenPorts) == 0 {
		slog.Debug("No ports configured for forwarding", "client_id", c.config.ClientID)
		return nil
	}

	slog.Info("Sending port forwarding request to gateway",
		"client_id", c.config.ClientID,
		"port_count", len(c.config.OpenPorts))

	// Log details of each port configuration
	for i, openPort := range c.config.OpenPorts {
		slog.Debug("Port forwarding configuration",
			"client_id", c.config.ClientID,
			"port_index", i,
			"remote_port", openPort.RemotePort,
			"local_port", openPort.LocalPort,
			"local_host", openPort.LocalHost,
			"protocol", openPort.Protocol)
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
		slog.Error("Failed to send port forwarding request",
			"client_id", c.config.ClientID,
			"port_count", len(c.config.OpenPorts),
			"error", err)
	} else {
		slog.Debug("Port forwarding request sent successfully",
			"client_id", c.config.ClientID,
			"port_count", len(c.config.OpenPorts))
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
		slog.Error("Invalid success status in port forwarding response",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	message, _ := msg["message"].(string)

	if success {
		slog.Info("Port forwarding request successful",
			"client_id", c.config.ClientID,
			"message", message,
			"port_count", len(c.config.OpenPorts))
	} else {
		slog.Error("Port forwarding request failed",
			"client_id", c.config.ClientID,
			"message", message,
			"port_count", len(c.config.OpenPorts))
	}
}
