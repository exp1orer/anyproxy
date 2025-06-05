// Package websocket provides WebSocket transport implementation for AnyProxy v2.
package websocket

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// dialWebSocketWithConfig 使用配置连接到 WebSocket 服务器 (基于 v1 逻辑，🆕 返回高性能连接)
func (t *webSocketTransport) dialWebSocketWithConfig(addr string, config *transport.ClientConfig) (transport.Connection, error) {
	logger.Debug("Establishing WebSocket connection to gateway", "client_id", config.ClientID, "gateway_addr", addr)

	// Parse the gateway URL
	gatewayURL := url.URL{
		Scheme: "wss",
		Host:   addr,
		Path:   "/ws",
	}

	// 检测协议 (支持 ws/wss 自动检测)
	if config.TLSConfig == nil {
		gatewayURL.Scheme = "ws"
	}

	logger.Debug("Gateway URL constructed", "client_id", config.ClientID, "url", gatewayURL.String())

	// Set up headers (与 v1 相同)
	headers := http.Header{}
	headers.Set("X-Client-ID", config.ClientID)
	headers.Set("X-Group-ID", config.GroupID)
	logger.Debug("WebSocket headers prepared", "client_id", config.ClientID, "group_id", config.GroupID)

	// Use Basic Auth for authentication (与 v1 相同)
	auth := base64.StdEncoding.EncodeToString(
		[]byte(config.Username + ":" + config.Password),
	)
	headers.Set("Authorization", "Basic "+auth)
	logger.Debug("Authentication header set", "client_id", config.ClientID)

	// Create WebSocket dialer with context (与 v1 相同，🆕 使用传递的 TLS 配置)
	dialer := websocket.Dialer{
		TLSClientConfig:  config.TLSConfig, // 🆕 使用传递的 TLS 配置
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
	}
	logger.Debug("WebSocket dialer configured", "client_id", config.ClientID, "handshake_timeout", "10s", "tls_enabled", config.TLSConfig != nil)

	// Connect to WebSocket (与 v1 相同)
	logger.Info("Connecting to WebSocket endpoint", "client_id", config.ClientID, "url", gatewayURL.String())
	conn, resp, err := dialer.Dial(gatewayURL.String(), headers)
	if err != nil {
		var statusCode int
		if resp != nil {
			statusCode = resp.StatusCode
		}
		logger.Error("Failed to connect to WebSocket", "client_id", config.ClientID, "url", gatewayURL.String(), "status_code", statusCode, "err", err)
		return nil, fmt.Errorf("failed to connect to WebSocket: %v", err)
	}

	if resp != nil {
		logger.Debug("WebSocket connection established", "client_id", config.ClientID, "status_code", resp.StatusCode)
	}

	// 🆕 创建高性能连接 (集成 v1 的 Writer)，传递客户端信息
	wsConn := NewWebSocketConnectionWithInfo(conn, config.ClientID, config.GroupID)

	logger.Info("WebSocket connection established successfully", "client_id", config.ClientID, "group_id", config.GroupID)

	return wsConn, nil
}
