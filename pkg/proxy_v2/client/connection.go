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

// connectionLoop handles connection and reconnection logic (与 v1 相同，但使用传输层)
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

		// 尝试连接 (🆕 使用传输层抽象)
		if err := c.connect(); err != nil {
			logger.Error("Failed to connect to gateway", "client_id", c.getClientID(), "attempt", connectionAttempts, "err", err, "retrying_in", backoff)

			// 添加抖动避免雷鸣群问题
			// 使用 math/rand 是有意为之，这里不需要加密安全的随机数
			jitter := time.Duration(rand.Int63n(int64(backoff) / 4)) //nolint:gosec // jitter doesn't require crypto rand
			sleepTime := backoff + jitter

			// 等待重试 (与 v1 相同)
			select {
			case <-c.ctx.Done():
				logger.Debug("Connection retry cancelled due to context", "client_id", c.getClientID())
				return
			case <-time.After(sleepTime):
			}

			// 指数退避 (与 v1 相同)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		// 重置退避 (与 v1 相同)
		backoff = 1 * time.Second
		logger.Info("Successfully connected to gateway", "client_id", c.getClientID(), "attempt", connectionAttempts, "gateway_addr", c.config.GatewayAddr)

		// 处理消息 (与 v1 相同)
		c.handleMessages()

		// 检查是否停止 (与 v1 相同)
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection loop ending due to context cancellation", "client_id", c.getClientID())
			return
		default:
		}

		// 连接丢失，清理并重试 (与 v1 相同)
		logger.Info("Connection to gateway lost, cleaning up and retrying...", "client_id", c.getClientID(), "total_attempts", connectionAttempts)
		c.cleanup()
	}
}

// connect establishes a connection to the gateway (🆕 使用传输层抽象，但逻辑与 v1 相同)
func (c *Client) connect() error {
	logger.Debug("Establishing connection to gateway", "client_id", c.getClientID(), "gateway_addr", c.config.GatewayAddr)

	c.actualID = c.generateClientID()

	// 🆕 创建 TLS 配置 (从 v1 迁移)
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

	// 🆕 创建传输层客户端配置
	transportConfig := &transport.ClientConfig{
		ClientID:   c.actualID,
		GroupID:    c.config.GroupID,
		Username:   c.config.AuthUsername,
		Password:   c.config.AuthPassword,
		TLSCert:    c.config.GatewayTLSCert,
		TLSConfig:  tlsConfig, // 🆕 传递 TLS 配置
		SkipVerify: false,     // 根据需要配置
	}

	logger.Debug("Transport configuration created", "client_id", c.actualID, "group_id", c.config.GroupID, "auth_enabled", c.config.AuthUsername != "", "tls_enabled", tlsConfig != nil)

	// 🆕 使用传输层进行连接
	conn, err := c.transport.DialWithConfig(c.config.GatewayAddr, transportConfig)
	if err != nil {
		logger.Error("Failed to connect via transport layer", "client_id", c.actualID, "gateway_addr", c.config.GatewayAddr, "err", err)
		return fmt.Errorf("failed to connect via transport: %v", err)
	}

	c.conn = conn
	logger.Info("Transport connection established successfully", "client_id", c.actualID, "group_id", c.config.GroupID, "remote_addr", conn.RemoteAddr())

	// 🆕 初始化消息处理器
	c.msgHandler = message.NewClientExtendedMessageHandler(conn)

	// 发送端口转发请求 (与 v1 相同)
	if len(c.config.OpenPorts) > 0 {
		logger.Debug("Sending port forwarding request", "client_id", c.actualID, "port_count", len(c.config.OpenPorts))
		if err := c.sendPortForwardingRequest(); err != nil {
			logger.Error("Failed to send port forwarding request", "client_id", c.actualID, "err", err)
			// 继续执行，端口转发是可选的
		}
	} else {
		logger.Debug("No port forwarding configured", "client_id", c.actualID)
	}

	return nil
}

// cleanup cleans up resources after connection loss (与 v1 相同逻辑，使用传输层)
func (c *Client) cleanup() {
	logger.Debug("Starting cleanup after connection loss", "client_id", c.getClientID())

	// 🆕 停止传输层连接
	if c.conn != nil {
		logger.Debug("Stopping transport connection during cleanup", "client_id", c.getClientID())
		if err := c.conn.Close(); err != nil {
			logger.Debug("Error closing client connection during stop", "err", err)
		}
		logger.Debug("Transport connection stopped", "client_id", c.getClientID())
	}

	// 获取连接数量 (使用 ConnectionManager)
	connectionCount := c.connMgr.GetConnectionCount()

	// 关闭所有连接 (使用 ConnectionManager)
	if connectionCount > 0 {
		logger.Debug("Closing connections during cleanup", "client_id", c.getClientID(), "connection_count", connectionCount)
		c.connMgr.CloseAllConnections()
		c.connMgr.CloseAllMessageChannels()
	}

	logger.Debug("Cleanup completed", "client_id", c.getClientID(), "connections_closed", connectionCount)
}

// closeAllConnections closes all active connections (与 v1 相同)
func (c *Client) closeAllConnections() {
	c.connMgr.CloseAllConnections()
	c.connMgr.CloseAllMessageChannels()
}

// handleConnection 处理单个客户端连接的数据传输 (与 v1 相同)
func (c *Client) handleConnection(connID string) {
	logger.Debug("Starting connection handler", "client_id", c.getClientID(), "conn_id", connID)

	// 获取连接 (使用 ConnectionManager)
	conn, exists := c.connMgr.GetConnection(connID)
	if !exists {
		logger.Error("Connection not found in connection handler", "client_id", c.getClientID(), "conn_id", connID)
		return
	}

	// 使用缓冲区读取数据，提高性能 (与 v1 相同)
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

		// 设置读取超时，带上下文感知 (与 v1 相同)
		deadline := time.Now().Add(protocol.DefaultReadTimeout)
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			logger.Debug("Failed to set read deadline", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		}

		// 从本地连接读取数据 (与 v1 相同)
		n, err := conn.Read(buffer)
		readCount++

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 读取超时，继续 (与 v1 相同)
				continue
			}

			// 优雅地记录连接关闭 (与 v1 相同)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "connection reset by peer") ||
				err == io.EOF {
				logger.Debug("Local connection closed gracefully", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			} else {
				logger.Error("Error reading from local connection", "client_id", c.getClientID(), "conn_id", connID, "err", err, "total_bytes", totalBytes)
			}

			// 发送关闭消息到网关 (与 v1 相同)
			c.writeCloseMessage(connID)

			// 清理连接 (使用 ConnectionManager)
			c.cleanupConnection(connID)
			return
		}

		if n > 0 {
			totalBytes += n

			// 采样日志，减少日志量
			if monitoring.ShouldLogData() && n > 1000 {
				logger.Debug("Read data from local connection", "client_id", c.getClientID(), "conn_id", connID, "bytes", n, "total_bytes", totalBytes)
			}

			// 🆕 发送数据到网关（使用二进制协议）
			if err := c.writeDataMessage(connID, buffer[:n]); err != nil {
				logger.Error("Failed to send data to gateway", "client_id", c.getClientID(), "conn_id", connID, "bytes", n, "err", err)
				c.cleanupConnection(connID)
				return
			}
		}
	}
}

// cleanupConnection 清理连接并发送关闭消息 (使用 ConnectionManager)
func (c *Client) cleanupConnection(connID string) {
	logger.Debug("Cleaning up connection", "client_id", c.getClientID(), "conn_id", connID)

	// 使用 ConnectionManager 清理连接
	c.connMgr.CleanupConnection(connID)

	logger.Debug("Connection cleaned up", "client_id", c.getClientID(), "conn_id", connID)
}
