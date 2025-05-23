package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/gorilla/websocket"
	"github.com/rs/xid"
)

const (
	writeBufSize = 4096
)

// ProxyClient represents the proxy client
type ProxyClient struct {
	config     *config.ClientConfig
	wsConn     *websocket.Conn
	writer     *WebSocketWriter
	writeBuf   chan interface{}
	connsMu    sync.RWMutex
	conns      map[string]net.Conn
	msgChans   map[string]chan map[string]interface{} // Message channels per connection
	msgChansMu sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewClient creates a new proxy client
func NewClient(cfg *config.ClientConfig) (*ProxyClient, error) {
	return &ProxyClient{
		config:   cfg,
		conns:    make(map[string]net.Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
		writeBuf: make(chan interface{}, writeBufSize),
	}, nil
}

// Start starts the client with automatic reconnection
func (c *ProxyClient) Start() error {
	// Start the main connection loop with reconnection
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectionLoop()
	}()

	return nil
}

// Stop stops the client gracefully
func (c *ProxyClient) Stop() error {
	log.Printf("Stopping client gracefully...")

	// Step 1: Signal all goroutines to stop accepting new work
	close(c.stopCh)

	// Step 2: Give existing connections time to finish current operations
	log.Printf("Waiting for active connections to finish...")
	time.Sleep(500 * time.Millisecond)

	// Step 3: Close WebSocket connection to stop receiving new requests
	if c.wsConn != nil {
		c.wsConn.Close()
	}

	// Step 4: Give a bit more time for pending writes to complete
	time.Sleep(200 * time.Millisecond)

	// Step 5: Stop WebSocket writer
	if c.writer != nil {
		c.writer.Stop()
	}

	// Step 6: Close all remaining connections
	c.closeAllConnections()

	// Step 7: Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("All client goroutines finished gracefully")
	case <-time.After(3 * time.Second):
		log.Printf("Warning: timeout waiting for client goroutines to finish")
	}

	return nil
}

// connectionLoop handles connection and reconnection logic
func (c *ProxyClient) connectionLoop() {
	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Attempt to connect
		if err := c.connect(); err != nil {
			log.Printf("Failed to connect to gateway: %v, retrying in %v", err, backoff)

			// Wait before retry
			select {
			case <-c.stopCh:
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
		log.Printf("Successfully connected to gateway")

		// Handle messages until connection fails
		c.handleMessages()

		// Connection lost, cleanup and retry
		log.Printf("Connection to gateway lost, cleaning up and retrying...")
		c.cleanup()
	}
}

// cleanup cleans up resources after connection loss
func (c *ProxyClient) cleanup() {
	// Stop writer
	c.writer.Stop()
	close(c.writeBuf)

	// Close WebSocket connection
	c.wsConn.Close()
	c.wsConn = nil

	// Close all connections
	c.closeAllConnections()

	// Recreate write buffer for next connection
	c.writeBuf = make(chan interface{}, writeBufSize)
}

// closeAllConnections closes all active connections
func (c *ProxyClient) closeAllConnections() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	for _, conn := range c.conns {
		conn.Close()
	}
	c.conns = make(map[string]net.Conn)
}

// connect establishes a WebSocket connection to the gateway
func (c *ProxyClient) connect() error {
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

	// Use Basic Auth for authentication
	auth := base64.StdEncoding.EncodeToString(
		[]byte(c.config.AuthUsername + ":" + c.config.AuthPassword),
	)
	headers.Set("Authorization", "Basic "+auth)

	// Create WebSocket dialer
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

	return nil
}

func (c *ProxyClient) generateClientID() string {
	return fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
}

// createTLSConfig creates a TLS configuration for the client
func (c *ProxyClient) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
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

// handleMessages processes incoming messages from the gateway
func (c *ProxyClient) handleMessages() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}

		// Read message from gateway
		var msg map[string]interface{}
		if err := c.wsConn.ReadJSON(&msg); err != nil {
			log.Printf("WebSocket read error: %v", err)
			return
		}

		// Process message based on its type
		msgType, ok := msg["type"].(string)
		if !ok {
			log.Printf("Invalid message format from gateway")
			continue
		}

		switch msgType {
		case "connect", "data", "close":
			// Route all messages to per-connection channels
			c.routeMessage(msg)
		default:
			log.Printf("Unknown message type: %s", msgType)
		}
	}
}

// routeMessage routes messages to the appropriate connection's message channel
func (c *ProxyClient) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		log.Printf("Invalid connection ID in message")
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

	// Send message to connection's channel (non-blocking)
	select {
	case msgChan <- msg:
	default:
		log.Printf("Message channel full for connection %s, dropping message", connID)
	}
}

// createMessageChannel creates a message channel for a connection
func (c *ProxyClient) createMessageChannel(connID string) {
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
func (c *ProxyClient) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
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
func (c *ProxyClient) handleConnectMessage(msg map[string]interface{}) {
	// Extract connection information
	connID, ok := msg["id"].(string)
	if !ok {
		log.Printf("Invalid connection ID in connect message")
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		log.Printf("Invalid network in connect message")
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		log.Printf("Invalid address in connect message")
		return
	}

	log.Printf("Handling connect request %s to %s://%s", connID, network, address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		log.Printf("Connection to %s denied (forbidden host)", address)
		c.sendConnectResponse(connID, false, "Host is forbidden")
		return
	}

	// Establish connection to the target
	conn, err := net.DialTimeout(network, address, 30*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", address, err)
		c.sendConnectResponse(connID, false, err.Error())
		return
	}

	log.Printf("Successfully connected to %s for connection %s", address, connID)

	// Register the connection
	c.connsMu.Lock()
	c.conns[connID] = conn
	c.connsMu.Unlock()

	// Send success response
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		log.Printf("Error sending connect_response: %v", err)
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
func (c *ProxyClient) sendConnectResponse(connID string, success bool, errorMsg string) error {
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

// handleConnection reads from the target connection and sends data to gateway
func (c *ProxyClient) handleConnection(connID string) {
	log.Printf("Starting to handle connection %s", connID)

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		log.Printf("Unknown connection ID: %s", connID)
		return
	}

	// Increase buffer size for better performance
	buffer := make([]byte, 32*1024) // 32KB buffer to match gateway

	for {
		select {
		case <-c.stopCh:
			log.Printf("Client stopping, exiting connection handler %s", connID)
			return
		default:
		}

		// Set reasonable read timeout for shutdown response
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

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
				log.Printf("Error writing data to WebSocket for connection %s: %v", connID, writeErr)
				c.cleanupConnection(connID)
				return
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue on timeout without logging
			}

			if err != io.EOF {
				log.Printf("Failed to read from connection %s: %v", connID, err)
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
func (c *ProxyClient) isConnectionAllowed(address string) bool {
	host := address
	if idx := strings.LastIndex(address, ":"); idx > 0 {
		host = address[:idx]
	}

	for _, forbidden := range c.config.ForbiddenHosts {
		if strings.HasPrefix(host, forbidden) {
			return false
		}
	}

	return true
}

// handleDataMessage processes a data message from the gateway
func (c *ProxyClient) handleDataMessage(msg map[string]interface{}) {
	// Extract message information
	connID, ok := msg["id"].(string)
	if !ok {
		log.Printf("Invalid connection ID in data message")
		return
	}

	dataStr, ok := msg["data"].(string)
	if !ok {
		log.Printf("Invalid data in data message for connection %s", connID)
		return
	}

	// Decode base64 string back to []byte
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		log.Printf("Failed to decode base64 data for connection %s: %v", connID, err)
		return
	}

	// Get the connection
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		log.Printf("Unknown connection ID: %s", connID)
		return
	}

	// Write data to the connection
	_, err = conn.Write(data)
	if err != nil {
		log.Printf("Failed to write data to connection %s: %v", connID, err)
		c.cleanupConnection(connID)
		return
	}
}

// handleCloseMessage processes a close message from the gateway
func (c *ProxyClient) handleCloseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		log.Printf("Invalid connection ID in close message")
		return
	}

	c.cleanupConnection(connID)
}

// cleanupConnection cleans up a connection
func (c *ProxyClient) cleanupConnection(connID string) {
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
		log.Printf("Connection %s cleaned up", connID)
	}
}
