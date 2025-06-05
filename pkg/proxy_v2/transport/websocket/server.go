package websocket

import (
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
	"github.com/gorilla/websocket"
)

// webSocketTransport WebSocket传输层实现
type webSocketTransport struct {
	server     *http.Server
	handler    func(transport.Connection)
	upgrader   websocket.Upgrader
	mu         sync.Mutex
	running    bool
	authConfig *transport.AuthConfig // 添加认证配置
}

var _ transport.Transport = (*webSocketTransport)(nil)

// NewWebSocketTransport 创建新的WebSocket传输层
func NewWebSocketTransport() transport.Transport {
	return &webSocketTransport{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool {
				return true // 允许所有来源，生产环境应该限制
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
	}
}

// NewWebSocketTransportWithAuth 创建带认证的WebSocket传输层
func NewWebSocketTransportWithAuth(authConfig *transport.AuthConfig) transport.Transport {
	return &webSocketTransport{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(_ *http.Request) bool {
				return true
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		authConfig: authConfig,
	}
}

// ListenAndServe 实现 Transport 接口 - 服务器端监听（HTTP）
func (s *webSocketTransport) ListenAndServe(addr string, handler func(transport.Connection)) error {
	return s.listenAndServe(addr, handler, nil)
}

// ListenAndServeWithTLS 实现 Transport 接口 - 服务器端监听（HTTPS/WSS）(🆕 从 v1 迁移)
func (s *webSocketTransport) ListenAndServeWithTLS(addr string, handler func(transport.Connection), tlsConfig *tls.Config) error {
	return s.listenAndServe(addr, handler, tlsConfig)
}

// listenAndServe 统一的服务器启动逻辑 (🆕 支持 TLS)
func (s *webSocketTransport) listenAndServe(addr string, handler func(transport.Connection), tlsConfig *tls.Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return nil
	}

	s.handler = handler

	protocol := "HTTP"
	if tlsConfig != nil {
		protocol = "HTTPS"
	}
	logger.Info("Starting WebSocket server", "listen_addr", addr, "protocol", protocol)

	// 创建HTTP服务器
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)

	s.server = &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         tlsConfig,        // 🆕 设置 TLS 配置
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
	}

	// 启动服务器
	go func() {
		var err error
		if tlsConfig != nil {
			logger.Info("Starting HTTPS WebSocket server (WSS)", "addr", addr)
			// 🆕 使用 TLS 启动服务器（与 v1 相同）
			err = s.server.ListenAndServeTLS("", "")
		} else {
			logger.Info("Starting HTTP WebSocket server (WS)", "addr", addr)
			err = s.server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			logger.Error("WebSocket server error", "protocol", protocol, "err", err)
		} else {
			logger.Info("WebSocket server stopped", "protocol", protocol)
		}
	}()

	s.running = true
	logger.Info("WebSocket server started successfully", "addr", addr, "protocol", protocol)
	return nil
}

// DialWithConfig 使用配置连接到服务器 (🆕 使用高性能连接)
func (s *webSocketTransport) DialWithConfig(addr string, config *transport.ClientConfig) (transport.Connection, error) {
	logger.Debug("WebSocket transport dialing with config", "addr", addr, "client_id", config.ClientID, "group_id", config.GroupID, "tls_enabled", config.TLSConfig != nil)

	// 🆕 使用高性能的 WebSocket 连接实现
	return s.dialWebSocketWithConfig(addr, config)
}

// Close 实现 Transport 接口 - 关闭传输层
func (s *webSocketTransport) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	logger.Info("Stopping WebSocket server")

	err := s.server.Close()
	if err != nil {
		logger.Error("Error closing WebSocket server", "err", err)
	} else {
		logger.Info("WebSocket server stopped successfully")
	}

	s.running = false
	return err
}

// handleWebSocket 处理WebSocket连接升级 (基于 v1 的认证逻辑)
func (s *webSocketTransport) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 获取客户端ID (与 v1 相同)
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		logger.Warn("WebSocket connection rejected: missing client ID", "remote_addr", r.RemoteAddr, "user_agent", r.Header.Get("User-Agent"))
		http.Error(w, "Client ID is required", http.StatusBadRequest)
		return
	}

	// 获取组ID (与 v1 相同)
	groupID := r.Header.Get("X-Group-ID")
	logger.Debug("WebSocket connection attempt", "client_id", clientID, "group_id", groupID, "remote_addr", r.RemoteAddr)

	// 认证检查 (与 v1 相同)
	if s.authConfig != nil && s.authConfig.Username != "" {
		username, password, ok := r.BasicAuth()
		if !ok {
			logger.Warn("WebSocket connection rejected: missing authentication", "client_id", clientID, "remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if username != s.authConfig.Username || password != s.authConfig.Password {
			logger.Warn("WebSocket connection rejected: invalid credentials", "client_id", clientID, "username", username, "remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		logger.Debug("Client authentication successful", "client_id", clientID)
	}

	// 升级到WebSocket
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Error("Failed to upgrade WebSocket connection", "client_id", clientID, "remote_addr", r.RemoteAddr, "err", err)
		return
	}

	logger.Debug("WebSocket connection upgraded successfully", "client_id", clientID)

	// 创建带有客户端信息的连接包装器
	wsConn := NewWebSocketConnectionWithInfo(conn, clientID, groupID)

	logger.Info("Client connected", "client_id", clientID, "group_id", groupID, "remote_addr", r.RemoteAddr)

	// 调用连接处理器，不使用recover掩盖问题
	defer func() {
		if err := wsConn.Close(); err != nil {
			logger.Debug("Error closing websocket connection", "err", err)
		}
		logger.Info("Client disconnected from WebSocket", "client_id", clientID, "group_id", groupID)
	}()

	// 调用连接处理器
	s.handler(wsConn)
}

func init() {
	transport.RegisterTransportCreator("websocket", NewWebSocketTransportWithAuth)
}
