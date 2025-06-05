package quic

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// quicTransport implements the Transport interface for QUIC
type quicTransport struct {
	listener   *quic.Listener
	handler    func(transport.Connection)
	mu         sync.Mutex
	running    bool
	authConfig *transport.AuthConfig
}

var _ transport.Transport = (*quicTransport)(nil)

// NewQUICTransport creates a new QUIC transport
func NewQUICTransport() transport.Transport {
	return &quicTransport{}
}

// NewQUICTransportWithAuth creates a new QUIC transport with authentication
func NewQUICTransportWithAuth(authConfig *transport.AuthConfig) transport.Transport {
	return &quicTransport{
		authConfig: authConfig,
	}
}

// ListenAndServe implements Transport interface - serves QUIC without TLS (not supported)
func (t *quicTransport) ListenAndServe(addr string, handler func(transport.Connection)) error {
	// QUIC always requires TLS, so we'll use a self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		return fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"anyproxy-quic"},
	}

	return t.listenAndServe(addr, handler, tlsConfig)
}

// ListenAndServeWithTLS implements Transport interface - serves QUIC with TLS
func (t *quicTransport) ListenAndServeWithTLS(addr string, handler func(transport.Connection), tlsConfig *tls.Config) error {
	if tlsConfig == nil {
		return fmt.Errorf("TLS configuration is required for QUIC")
	}

	// Ensure NextProtos is set for QUIC
	if tlsConfig.NextProtos == nil {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.NextProtos = []string{"anyproxy-quic"}
	}

	return t.listenAndServe(addr, handler, tlsConfig)
}

// listenAndServe unified server startup logic
func (t *quicTransport) listenAndServe(addr string, handler func(transport.Connection), tlsConfig *tls.Config) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		return nil
	}

	t.handler = handler

	slog.Info("Starting QUIC server", "listen_addr", addr)

	// 🚨 修复：配置QUIC心跳和空闲超时，防止连接意外断开
	quicConfig := &quic.Config{
		KeepAlivePeriod: 30 * time.Second, // 每30秒发送PING心跳
		MaxIdleTimeout:  5 * time.Minute,  // 5分钟空闲超时
	}

	// Create QUIC listener
	listener, err := quic.ListenAddr(addr, tlsConfig, quicConfig)
	if err != nil {
		slog.Error("Failed to create QUIC listener", "addr", addr, "error", err)
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	t.listener = listener

	slog.Info("QUIC listener created",
		"addr", addr,
		"keepalive_period", "30s",
		"idle_timeout", "5m")

	// Start accepting connections in a goroutine
	go func() {
		slog.Info("Starting QUIC server", "addr", addr)
		for {
			conn, err := listener.Accept(context.Background())
			if err != nil {
				slog.Error("QUIC server accept error", "error", err)
				return
			}

			// Handle connection in a separate goroutine
			go t.handleConnection(conn)
		}
	}()

	t.running = true
	slog.Info("QUIC server started successfully", "addr", addr)
	return nil
}

// handleConnection handles a new QUIC connection
func (t *quicTransport) handleConnection(conn quic.Connection) {
	slog.Debug("New QUIC connection accepted", "remote_addr", conn.RemoteAddr())

	// Accept the first stream
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		slog.Error("Failed to accept QUIC stream", "error", err)
		conn.CloseWithError(0, "failed to accept stream")
		return
	}

	slog.Debug("QUIC stream accepted")

	// 🚨 修复：等待并验证认证消息
	clientID, groupID, err := t.authenticateConnection(stream)
	if err != nil {
		slog.Warn("QUIC connection rejected during authentication",
			"remote_addr", conn.RemoteAddr(),
			"error", err)
		conn.CloseWithError(1, "authentication failed")
		return
	}

	slog.Info("Client connected via QUIC",
		"client_id", clientID,
		"group_id", groupID,
		"remote_addr", conn.RemoteAddr())

	// 创建服务端连接
	quicConn := newQUICServerConnection(stream, conn, clientID, groupID)

	// 调用连接处理器，不使用recover掩盖问题
	defer func() {
		quicConn.Close()
		slog.Info("Client disconnected from QUIC",
			"client_id", clientID,
			"group_id", groupID)
	}()

	t.handler(quicConn)
}

// authenticateConnection 认证QUIC连接并提取客户端信息
func (t *quicTransport) authenticateConnection(stream quic.Stream) (clientID, groupID string, err error) {
	// 创建临时连接来读取认证消息
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tempConn := &quicConnection{
		stream:    stream,
		readChan:  make(chan []byte, 1),
		errorChan: make(chan error, 1),
		ctx:       ctx,
		cancel:    cancel,
		isClient:  false,
	}

	// 🆕 确保临时 channels 被关闭
	defer func() {
		close(tempConn.readChan)
		close(tempConn.errorChan)
	}()

	// 启动接收循环来读取第一条消息
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

	// 设置认证超时
	timeout := time.After(10 * time.Second)

	var authData []byte
	select {
	case authData = <-tempConn.readChan:
		// 成功接收到认证数据
	case err = <-tempConn.errorChan:
		return "", "", fmt.Errorf("failed to read auth message: %v", err)
	case <-timeout:
		return "", "", fmt.Errorf("authentication timeout")
	}

	// 解析认证消息
	var authMsg map[string]interface{}
	if err = json.Unmarshal(authData, &authMsg); err != nil {
		return "", "", fmt.Errorf("invalid auth message format: %v", err)
	}

	// 检查消息类型
	msgType, ok := authMsg["type"].(string)
	if !ok || msgType != "auth" {
		return "", "", fmt.Errorf("expected auth message, got: %v", msgType)
	}

	// 提取客户端信息
	clientID, ok = authMsg["client_id"].(string)
	if !ok || clientID == "" {
		return "", "", fmt.Errorf("missing or invalid client_id")
	}

	groupID, _ = authMsg["group_id"].(string) // 组ID可选

	// 验证认证信息
	if t.authConfig != nil && t.authConfig.Username != "" {
		username, ok1 := authMsg["username"].(string)
		password, ok2 := authMsg["password"].(string)

		if !ok1 || !ok2 {
			return "", "", fmt.Errorf("missing authentication credentials")
		}

		if username != t.authConfig.Username || password != t.authConfig.Password {
			return "", "", fmt.Errorf("invalid credentials")
		}

		slog.Debug("QUIC client authentication successful", "client_id", clientID)
	}

	// 发送认证成功响应
	authResponse := map[string]interface{}{
		"type":   "auth_response",
		"status": "success",
	}

	responseData, _ := json.Marshal(authResponse)
	if writeErr := tempConn.writeData(responseData); writeErr != nil {
		return "", "", fmt.Errorf("failed to send auth response: %v", writeErr)
	}

	slog.Debug("QUIC authentication completed successfully",
		"client_id", clientID,
		"group_id", groupID)

	return clientID, groupID, nil
}

// DialWithConfig implements Transport interface - client connection
func (t *quicTransport) DialWithConfig(addr string, config *transport.ClientConfig) (transport.Connection, error) {
	slog.Debug("QUIC transport dialing with config",
		"addr", addr,
		"client_id", config.ClientID,
		"group_id", config.GroupID,
		"tls_enabled", config.TLSConfig != nil)

	return t.dialQUICWithConfig(addr, config)
}

// Close implements Transport interface
func (t *quicTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return nil
	}

	slog.Info("Stopping QUIC server")

	if t.listener != nil {
		err := t.listener.Close()
		if err != nil {
			slog.Error("Error closing QUIC listener", "error", err)
		} else {
			slog.Debug("QUIC listener closed")
		}
	}

	t.running = false
	slog.Info("QUIC server stopped successfully")
	return nil
}

// generateSelfSignedCert generates a self-signed certificate for QUIC
func generateSelfSignedCert() (tls.Certificate, error) {
	// This is a simplified implementation
	// In production, you should use proper certificate generation
	return tls.Certificate{}, fmt.Errorf("self-signed certificate generation not implemented")
}

// Register the transport creator
func init() {
	transport.RegisterTransportCreator("quic", NewQUICTransportWithAuth)
}
