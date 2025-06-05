package quic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// dialQUICWithConfig connects to QUIC server with configuration
func (t *quicTransport) dialQUICWithConfig(addr string, config *transport.ClientConfig) (transport.Connection, error) {
	slog.Debug("Establishing QUIC connection to gateway",
		"client_id", config.ClientID,
		"gateway_addr", addr)

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipVerify,
		NextProtos:         []string{"anyproxy-quic"},
	}

	// Use provided TLS config if available
	if config.TLSConfig != nil {
		tlsConfig = config.TLSConfig.Clone()
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"anyproxy-quic"}
		}
	}

	slog.Debug("QUIC TLS configuration prepared",
		"client_id", config.ClientID,
		"skip_verify", tlsConfig.InsecureSkipVerify)

	// 🚨 Fix: Configure QUIC keepalive and idle timeout to prevent unexpected connection drops
	quicConfig := &quic.Config{
		KeepAlivePeriod: 30 * time.Second, // Send PING keepalive every 30 seconds
		MaxIdleTimeout:  5 * time.Minute,  // 5-minute idle timeout
	}

	// Set connection timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	slog.Info("Connecting to QUIC endpoint",
		"client_id", config.ClientID,
		"addr", addr,
		"keepalive_period", "30s",
		"idle_timeout", "5m")

	// Establish QUIC connection
	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		slog.Error("Failed to connect to QUIC server",
			"client_id", config.ClientID,
			"addr", addr,
			"error", err)
		return nil, fmt.Errorf("failed to connect to QUIC server: %v", err)
	}

	slog.Debug("QUIC connection established", "client_id", config.ClientID)

	// Open a stream for communication
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed to open stream")
		slog.Error("Failed to open QUIC stream",
			"client_id", config.ClientID,
			"error", err)
		return nil, fmt.Errorf("failed to open QUIC stream: %v", err)
	}

	slog.Debug("QUIC stream opened", "client_id", config.ClientID)

	// 🚨 Fix: Send authentication message and wait for response
	if err := t.authenticateClient(stream, config); err != nil {
		conn.CloseWithError(1, "authentication failed")
		return nil, fmt.Errorf("authentication failed: %v", err)
	}

	// Create client connection
	quicConn := newQUICConnection(stream, conn, config.ClientID, config.GroupID)

	slog.Info("QUIC connection established successfully",
		"client_id", config.ClientID)

	return quicConn, nil
}

// authenticateClient sends authentication message and waits for server response
func (t *quicTransport) authenticateClient(stream quic.Stream, config *transport.ClientConfig) error {
	slog.Debug("Starting QUIC client authentication",
		"client_id", config.ClientID,
		"group_id", config.GroupID)

	// Create authentication message
	authMsg := map[string]interface{}{
		"type":      "auth",
		"client_id": config.ClientID,
		"group_id":  config.GroupID,
	}

	// Add authentication credentials (if provided)
	if config.Username != "" {
		authMsg["username"] = config.Username
		authMsg["password"] = config.Password
	}

	// Serialize authentication message
	authData, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal auth message: %v", err)
	}

	// Create temporary connection to send authentication message
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tempConn := &quicConnection{
		stream:    stream,
		readChan:  make(chan []byte, 1),
		errorChan: make(chan error, 1),
		ctx:       ctx,
		cancel:    cancel,
		isClient:  true,
	}

	// 🆕 确保临时 channels 被关闭
	defer func() {
		close(tempConn.readChan)
		close(tempConn.errorChan)
	}()

	// Send authentication message
	if err := tempConn.writeData(authData); err != nil {
		return fmt.Errorf("failed to send auth message: %v", err)
	}

	slog.Debug("Auth message sent, waiting for response",
		"client_id", config.ClientID)

	// Start receive loop to read response
	go func() {
		data, readErr := tempConn.readData()
		if readErr != nil {
			select {
			case tempConn.errorChan <- readErr:
			case <-ctx.Done():
			}
		} else {
			select {
			case tempConn.readChan <- data:
			case <-ctx.Done():
			}
		}
	}()

	// Wait for authentication response (10-second timeout)
	timeout := time.After(10 * time.Second)

	var responseData []byte
	select {
	case responseData = <-tempConn.readChan:
		// Successfully received response
	case err = <-tempConn.errorChan:
		return fmt.Errorf("failed to read auth response: %v", err)
	case <-timeout:
		return fmt.Errorf("authentication response timeout")
	}

	// Parse authentication response
	var authResponse map[string]interface{}
	if err := json.Unmarshal(responseData, &authResponse); err != nil {
		return fmt.Errorf("invalid auth response format: %v", err)
	}

	// Check response type and status
	msgType, ok := authResponse["type"].(string)
	if !ok || msgType != "auth_response" {
		return fmt.Errorf("unexpected response type: %v", msgType)
	}

	status, ok := authResponse["status"].(string)
	if !ok || status != "success" {
		reason, _ := authResponse["reason"].(string)
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("authentication failed: %s", reason)
	}

	slog.Debug("QUIC client authentication successful",
		"client_id", config.ClientID,
		"group_id", config.GroupID)

	return nil
}
