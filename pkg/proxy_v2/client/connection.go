package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/message"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/monitoring"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/protocol"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// connectionLoop handles connection and reconnection logic (same as v1, but using transport layer)
func (c *Client) connectionLoop() {
	logger.Debug("Starting connection loop", "client_id", c.getClientID())

	backoff := 1 * time.Second
	maxBackoff := 60 * time.Second
	connectionAttempts := 0

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection loop stopping due to context cancellation", "client_id", c.getClientID(), "total_attempts", connectionAttempts)
			return
		default:
		}

		connectionAttempts++
		logger.Debug("Attempting to connect to gateway", "client_id", c.getClientID(), "attempt", connectionAttempts, "gateway_addr", c.config.GatewayAddr)

		// Attempt to connect (🆕 using transport layer abstraction)
		if err := c.connect(); err != nil {
			logger.Error("Failed to connect to gateway", "client_id", c.getClientID(), "attempt", connectionAttempts, "err", err, "retrying_in", backoff)

			// Add jitter to avoid thundering herd problem
			// Using math/rand is intentional, we don't need cryptographically secure random numbers here
			jitter := time.Duration(rand.Int63n(int64(backoff) / 4)) //nolint:gosec // jitter doesn't require crypto rand
			sleepTime := backoff + jitter

			// Wait for retry (same as v1)
			select {
			case <-c.ctx.Done():
				logger.Debug("Connection retry cancelled due to context", "client_id", c.getClientID())
				return
			case <-time.After(sleepTime):
			}

			// Exponential backoff (same as v1)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// Reset backoff (same as v1)
		backoff = 1 * time.Second
		logger.Info("Successfully connected to gateway", "client_id", c.getClientID(), "attempt", connectionAttempts, "gateway_addr", c.config.GatewayAddr)

		// Handle messages (same as v1)
		c.handleMessages()

		// Check if stopping (same as v1)
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection loop ending due to context cancellation", "client_id", c.getClientID())
			return
		default:
		}

		// Connection lost, clean up and retry (same as v1)
		logger.Info("Connection to gateway lost, cleaning up and retrying...", "client_id", c.getClientID(), "total_attempts", connectionAttempts)
		c.cleanup()
	}
}

// connect establishes a connection to the gateway (🆕 using transport layer abstraction, but logic same as v1)
func (c *Client) connect() error {
	logger.Debug("Establishing connection to gateway", "client_id", c.getClientID(), "gateway_addr", c.config.GatewayAddr)

	c.actualID = c.generateClientID()

	// 🆕 Create TLS configuration (migrated from v1)
	var tlsConfig *tls.Config
	if c.config.GatewayTLSCert != "" || strings.HasPrefix(c.config.GatewayAddr, "wss://") {
		logger.Debug("Creating TLS configuration", "client_id", c.actualID)
		var err error
		tlsConfig, err = c.createTLSConfig()
		if err != nil {
			logger.Error("Failed to create TLS configuration", "client_id", c.actualID, "gateway_addr", c.config.GatewayAddr, "err", err)
			return fmt.Errorf("failed to create TLS configuration: %v", err)
		}
		logger.Debug("TLS configuration created successfully", "client_id", c.actualID)
	}

	// 🆕 Create transport layer client configuration
	transportConfig := &transport.ClientConfig{
		ClientID:   c.actualID,
		GroupID:    c.config.GroupID,
		Username:   c.config.AuthUsername,
		Password:   c.config.AuthPassword,
		TLSCert:    c.config.GatewayTLSCert,
		TLSConfig:  tlsConfig, // 🆕 Pass TLS configuration
		SkipVerify: false,     // Configure as needed
	}

	logger.Debug("Transport configuration created", "client_id", c.actualID, "group_id", c.config.GroupID, "auth_enabled", c.config.AuthUsername != "", "tls_enabled", tlsConfig != nil)

	// 🆕 Connect using transport layer
	conn, err := c.transport.DialWithConfig(c.config.GatewayAddr, transportConfig)
	if err != nil {
		logger.Error("Failed to connect via transport layer", "client_id", c.actualID, "gateway_addr", c.config.GatewayAddr, "err", err)
		return fmt.Errorf("failed to connect via transport: %v", err)
	}

	c.conn = conn
	logger.Info("Transport connection established successfully", "client_id", c.actualID, "group_id", c.config.GroupID, "remote_addr", conn.RemoteAddr())

	// 🆕 Initialize message handler
	c.msgHandler = message.NewClientExtendedMessageHandler(conn)

	// Send port forwarding request (same as v1)
	if len(c.config.OpenPorts) > 0 {
		logger.Debug("Sending port forwarding request", "client_id", c.actualID, "port_count", len(c.config.OpenPorts))
		if err := c.sendPortForwardingRequest(); err != nil {
			logger.Error("Failed to send port forwarding request", "client_id", c.actualID, "err", err)
			// Continue execution, port forwarding is optional
		}
	} else {
		logger.Debug("No port forwarding configured", "client_id", c.actualID)
	}

	return nil
}

// cleanup cleans up resources after connection loss (same logic as v1, using transport layer)
func (c *Client) cleanup() {
	logger.Debug("Starting cleanup after connection loss", "client_id", c.getClientID())

	// 🆕 Stop transport layer connection
	if c.conn != nil {
		logger.Debug("Stopping transport connection during cleanup", "client_id", c.getClientID())
		if err := c.conn.Close(); err != nil {
			logger.Debug("Error closing client connection during stop (expected)", "err", err)
		}
		logger.Debug("Transport connection stopped", "client_id", c.getClientID())
	}

	// Get connection count (using ConnectionManager)
	connectionCount := c.connMgr.GetConnectionCount()

	// Close all connections (using ConnectionManager)
	if connectionCount > 0 {
		logger.Debug("Closing connections during cleanup", "client_id", c.getClientID(), "connection_count", connectionCount)
		c.connMgr.CloseAllConnections()
		c.connMgr.CloseAllMessageChannels()
	}

	logger.Debug("Cleanup completed", "client_id", c.getClientID(), "connections_closed", connectionCount)
}

// handleConnection handles data transfer for a single client connection (same as v1)
func (c *Client) handleConnection(connID string) {
	logger.Debug("Starting connection handler", "client_id", c.getClientID(), "conn_id", connID)

	// Get connection (using ConnectionManager)
	conn, exists := c.connMgr.GetConnection(connID)
	if !exists {
		logger.Error("Connection not found in connection handler", "client_id", c.getClientID(), "conn_id", connID)
		return
	}

	// Use buffered reading for better performance (same as v1)
	buffer := make([]byte, protocol.DefaultBufferSize)
	totalBytes := 0
	readCount := 0

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection handler stopping due to context cancellation", "client_id", c.getClientID(), "conn_id", connID, "bytes_transferred", totalBytes)
			return
		default:
		}

		// Set read timeout with context awareness (same as v1)
		deadline := time.Now().Add(protocol.DefaultReadTimeout)
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			logger.Warn("Failed to set read deadline", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		}

		// Read data from local connection (same as v1)
		n, err := conn.Read(buffer)
		readCount++

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Read timeout, continue (same as v1)
				continue
			}

			// Gracefully log connection close (same as v1)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "connection reset by peer") ||
				err == io.EOF {
				logger.Debug("Local connection closed gracefully", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			} else {
				logger.Error("Error reading from local connection", "client_id", c.getClientID(), "conn_id", connID, "err", err, "total_bytes", totalBytes)
			}

			// Send close message to gateway (same as v1)
			if err := c.writeCloseMessage(connID); err != nil {
				logger.Warn("Failed to send close message to gateway", "client_id", c.getClientID(), "conn_id", connID, "err", err)
			}

			// Clean up connection (using ConnectionManager)
			c.cleanupConnection(connID)
			return
		}

		if n > 0 {
			totalBytes += n

			// Sample logs to reduce log volume
			if monitoring.ShouldLogData() && n > 1000 {
				logger.Debug("Read data from local connection", "client_id", c.getClientID(), "conn_id", connID, "bytes", n, "total_bytes", totalBytes)
			}

			// 🆕 Send data to gateway (using binary protocol)
			if err := c.writeDataMessage(connID, buffer[:n]); err != nil {
				logger.Error("Failed to send data to gateway", "client_id", c.getClientID(), "conn_id", connID, "bytes", n, "err", err)
				c.cleanupConnection(connID)
				return
			}
		}
	}
}

// cleanupConnection cleans up connection and sends close message (using ConnectionManager)
func (c *Client) cleanupConnection(connID string) {
	logger.Debug("Cleaning up connection", "client_id", c.getClientID(), "conn_id", connID)

	// Use ConnectionManager to clean up connection
	c.connMgr.CleanupConnection(connID)

	logger.Debug("Connection cleaned up", "client_id", c.getClientID(), "conn_id", connID)
}
