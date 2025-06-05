// Package client provides v2 client implementation for AnyProxy.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"

	// Import gRPC transport for side effects (registration)
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/grpc"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/quic"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/websocket"
)

// Client represents the proxy client (基于 v1 设计)
type Client struct {
	config     *config.ClientConfig
	transport  transport.Transport  // 🆕 唯一的新增抽象
	conn       transport.Connection // 🆕 传输层连接
	actualID   string               // 🆕 实际使用的客户端 ID (带随机后缀)
	connsMu    sync.RWMutex
	conns      map[string]net.Conn
	msgChans   map[string]chan map[string]interface{} // 与 v1 相同的消息通道
	msgChansMu sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewClient creates a new proxy client (与 v1 相似，但支持传输层选择)
func NewClient(cfg *config.ClientConfig, transportType string) (*Client, error) {
	logger.Info("Creating new client", "client_id", cfg.ClientID, "gateway_addr", cfg.GatewayAddr, "group_id", cfg.GroupID, "transport_type", transportType, "allowed_hosts_count", len(cfg.AllowedHosts), "forbidden_hosts_count", len(cfg.ForbiddenHosts), "open_ports_count", len(cfg.OpenPorts), "auth_enabled", cfg.AuthUsername != "")

	// 记录安全策略详细信息
	if len(cfg.ForbiddenHosts) > 0 {
		logger.Info("🚫 SECURITY POLICY - Forbidden hosts configured", "client_id", cfg.ClientID, "forbidden_hosts", cfg.ForbiddenHosts, "count", len(cfg.ForbiddenHosts))
	}

	if len(cfg.AllowedHosts) > 0 {
		logger.Info("✅ SECURITY POLICY - Allowed hosts configured", "client_id", cfg.ClientID, "allowed_hosts", cfg.AllowedHosts, "count", len(cfg.AllowedHosts))
	} else {
		logger.Warn("⚠️ SECURITY POLICY - No allowed hosts configured, all non-forbidden hosts will be allowed", "client_id", cfg.ClientID)
	}

	// 记录端口转发配置
	if len(cfg.OpenPorts) > 0 {
		logger.Info("🔌 PORT FORWARDING - Configured ports", "client_id", cfg.ClientID, "port_count", len(cfg.OpenPorts))
		for i, port := range cfg.OpenPorts {
			logger.Info("  Port forwarding entry", "index", i, "remote_port", port.RemotePort, "local_target", fmt.Sprintf("%s:%d", port.LocalHost, port.LocalPort), "protocol", port.Protocol)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	// 🆕 创建传输层 - 唯一的新增逻辑
	transportImpl := transport.CreateTransport(transportType, &transport.AuthConfig{
		Username: cfg.AuthUsername,
		Password: cfg.AuthPassword,
	})
	if transportImpl == nil {
		cancel()
		return nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}

	client := &Client{
		config:    cfg,
		transport: transportImpl,
		conns:     make(map[string]net.Conn),
		msgChans:  make(map[string]chan map[string]interface{}),
		ctx:       ctx,
		cancel:    cancel,
	}

	logger.Debug("Client initialization completed", "client_id", cfg.ClientID, "transport_type", transportType)

	return client, nil
}

// Start starts the client with automatic reconnection (与 v1 相同)
func (c *Client) Start() error {
	logger.Info("Starting proxy client", "client_id", c.getClientID(), "gateway_addr", c.config.GatewayAddr, "group_id", c.config.GroupID)

	// 启动主连接循环 (与 v1 相同)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.connectionLoop()
	}()

	logger.Info("Client started successfully", "client_id", c.getClientID())

	return nil
}

// Stop stops the client gracefully (与 v1 相同)
func (c *Client) Stop() error {
	logger.Info("Initiating graceful client shutdown", "client_id", c.getClientID())

	// Step 1: 取消上下文 (与 v1 相同)
	logger.Debug("Cancelling client context", "client_id", c.getClientID())
	c.cancel()

	// Step 2: 获取连接数量 (与 v1 相同)
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	if connectionCount > 0 {
		logger.Info("Waiting for active connections to finish", "client_id", c.getClientID(), "connection_count", connectionCount)
	}

	// 等待现有连接完成 (与 v1 相同)
	select {
	case <-c.ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}

	// Step 3: 🆕 停止传输层连接
	if c.conn != nil {
		logger.Debug("Stopping transport connection during cleanup", "client_id", c.getClientID())
		if err := c.conn.Close(); err != nil {
			logger.Debug("Error closing client connection during stop", "err", err)
		}
		logger.Debug("Transport connection stopped", "client_id", c.getClientID())
	}

	// Step 4: 关闭所有连接 (与 v1 相同)
	logger.Debug("Closing all connections", "client_id", c.getClientID(), "connection_count", connectionCount)
	c.closeAllConnections()
	if connectionCount > 0 {
		logger.Debug("All connections closed", "client_id", c.getClientID())
	}

	// Step 5: 等待所有goroutine完成 (与 v1 相同)
	logger.Debug("Waiting for all goroutines to finish", "client_id", c.getClientID())
	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("All client goroutines finished gracefully", "client_id", c.getClientID())
	case <-time.After(3 * time.Second):
		logger.Warn("Timeout waiting for client goroutines to finish", "client_id", c.getClientID())
	}

	logger.Info("Client shutdown completed", "client_id", c.getClientID(), "connections_closed", connectionCount)

	return nil
}

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

			// 等待重试 (与 v1 相同)
			select {
			case <-c.ctx.Done():
				logger.Debug("Connection retry cancelled due to context", "client_id", c.getClientID())
				return
			case <-time.After(backoff):
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

	// 获取连接数量 (与 v1 相同)
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	// 关闭所有连接 (与 v1 相同)
	if connectionCount > 0 {
		logger.Debug("Closing connections during cleanup", "client_id", c.getClientID(), "connection_count", connectionCount)
		c.closeAllConnections()
	}

	logger.Debug("Cleanup completed", "client_id", c.getClientID(), "connections_closed", connectionCount)
}

// closeAllConnections closes all active connections (与 v1 相同)
func (c *Client) closeAllConnections() {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()

	connectionCount := len(c.conns)
	if connectionCount == 0 {
		logger.Debug("No connections to close", "client_id", c.getClientID())
		return
	}

	logger.Debug("Closing all active connections", "client_id", c.getClientID(), "connection_count", connectionCount)

	closedCount := 0
	for connID, conn := range c.conns {
		if err := conn.Close(); err != nil {
			logger.Debug("Error closing connection (expected during shutdown)", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		} else {
			closedCount++
		}
	}
	c.conns = make(map[string]net.Conn)

	// 关闭所有消息通道 (与 v1 相同)
	c.msgChansMu.Lock()
	channelCount := len(c.msgChans)
	for connID, msgChan := range c.msgChans {
		close(msgChan)
		delete(c.msgChans, connID)
	}
	c.msgChansMu.Unlock()

	logger.Debug("All connections and channels closed", "client_id", c.getClientID(), "connections_closed", closedCount, "channels_closed", channelCount)
}

// connect establishes a connection to the gateway (🆕 使用传输层抽象，但逻辑与 v1 相同)
func (c *Client) connect() error {
	logger.Debug("Establishing connection to gateway", "client_id", c.getClientID(), "gateway_addr", c.config.GatewayAddr)

	// 生成唯一的客户端ID (与 v1 相同)
	clientID := c.generateClientID()

	// 🆕 创建 TLS 配置 (从 v1 迁移)
	var tlsConfig *tls.Config
	if c.config.GatewayTLSCert != "" || strings.HasPrefix(c.config.GatewayAddr, "wss://") {
		logger.Debug("Creating TLS configuration", "client_id", clientID)
		var err error
		tlsConfig, err = c.createTLSConfig()
		if err != nil {
			logger.Error("Failed to create TLS configuration", "client_id", clientID, "gateway_addr", c.config.GatewayAddr, "err", err)
			return fmt.Errorf("failed to create TLS configuration: %v", err)
		}
		logger.Debug("TLS configuration created successfully", "client_id", clientID)
	}

	// 🆕 创建传输层客户端配置
	transportConfig := &transport.ClientConfig{
		ClientID:   clientID,
		GroupID:    c.config.GroupID,
		Username:   c.config.AuthUsername,
		Password:   c.config.AuthPassword,
		TLSCert:    c.config.GatewayTLSCert,
		TLSConfig:  tlsConfig, // 🆕 传递 TLS 配置
		SkipVerify: false,     // 根据需要配置
	}

	logger.Debug("Transport configuration created", "client_id", clientID, "group_id", c.config.GroupID, "auth_enabled", c.config.AuthUsername != "", "tls_enabled", tlsConfig != nil)

	// 🆕 使用传输层进行连接
	conn, err := c.transport.DialWithConfig(c.config.GatewayAddr, transportConfig)
	if err != nil {
		logger.Error("Failed to connect via transport layer", "client_id", clientID, "gateway_addr", c.config.GatewayAddr, "err", err)
		return fmt.Errorf("failed to connect via transport: %v", err)
	}

	c.conn = conn
	c.actualID = clientID // 🆕 保存实际使用的客户端 ID
	logger.Info("Transport connection established successfully", "client_id", clientID, "group_id", c.config.GroupID, "remote_addr", conn.RemoteAddr())

	// 发送端口转发请求 (与 v1 相同)
	if len(c.config.OpenPorts) > 0 {
		logger.Debug("Sending port forwarding request", "client_id", clientID, "port_count", len(c.config.OpenPorts))
		if err := c.sendPortForwardingRequest(); err != nil {
			logger.Error("Failed to send port forwarding request", "client_id", clientID, "err", err)
			// 继续执行，端口转发是可选的
		}
	} else {
		logger.Debug("No port forwarding configured", "client_id", clientID)
	}

	return nil
}

// generateClientID generates a unique client ID (与 v1 相同)
func (c *Client) generateClientID() string {
	generatedID := fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
	logger.Debug("Generated unique client ID", "base_client_id", c.config.ClientID, "generated_client_id", generatedID)
	return generatedID
}

// getClientID 获取日志使用的客户端 ID
func (c *Client) getClientID() string {
	if c.actualID != "" {
		return c.actualID
	}
	return c.config.ClientID
}

// handleMessages 处理来自网关的消息 (从 v1 迁移，适配传输层)
func (c *Client) handleMessages() {
	logger.Debug("Starting message handler for gateway messages", "client_id", c.getClientID())
	messageCount := 0

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Message handler stopping due to context cancellation", "client_id", c.getClientID(), "messages_processed", messageCount)
			return
		default:
		}

		// 🆕 直接读取 JSON 消息，简化代码
		var msg map[string]interface{}
		if err := c.conn.ReadJSON(&msg); err != nil {
			logger.Error("Transport read error", "client_id", c.getClientID(), "messages_processed", messageCount, "err", err)
			// 连接失败，退出以触发重连
			return
		}

		messageCount++

		// 基于类型处理消息 (与 v1 相同)
		msgType, ok := msg["type"].(string)
		if !ok {
			logger.Error("Invalid message format from gateway - missing type field", "client_id", c.getClientID(), "message_count", messageCount, "message_fields", getMessageFields(msg))
			continue
		}

		// 记录消息处理（但不记录高频数据消息）(与 v1 相同)
		if msgType != common.MsgTypeData {
			logger.Debug("Processing gateway message", "client_id", c.getClientID(), "message_type", msgType, "message_count", messageCount)
		}

		switch msgType {
		case common.MsgTypeConnect, common.MsgTypeData, common.MsgTypeClose:
			// 将所有消息路由到每个连接的通道 (与 v1 相同)
			c.routeMessage(msg)
		case "port_forward_response":
			// 直接处理端口转发响应 (与 v1 相同)
			logger.Debug("Received port forwarding response", "client_id", c.getClientID())
			c.handlePortForwardResponse(msg)
		default:
			logger.Warn("Unknown message type from gateway", "client_id", c.getClientID(), "message_type", msgType, "message_count", messageCount)
		}
	}
}

// routeMessage 将消息路由到适当连接的消息通道 (与 v1 相同)
func (c *Client) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in message from gateway", "client_id", c.getClientID(), "message_fields", getMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// 对于连接消息，首先创建通道 (与 v1 相同)
	if msgType == common.MsgTypeConnect {
		logger.Debug("Creating message channel for new connection request", "client_id", c.getClientID(), "conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// 连接不存在，忽略消息 (与 v1 相同)
		logger.Debug("Ignoring message for non-existent connection", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		return
	}

	// 发送消息到连接的通道（非阻塞，带上下文感知）(与 v1 相同)
	select {
	case msgChan <- msg:
		// 成功路由，不记录高频数据消息
		if msgType != common.MsgTypeData {
			logger.Debug("Message routed to connection handler", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		}
	case <-c.ctx.Done():
		logger.Debug("Message routing cancelled due to context", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		return
	default:
		logger.Warn("Message channel full for connection, dropping message", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
	}
}

// createMessageChannel 为连接创建消息通道 (与 v1 相同)
func (c *Client) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// 检查通道是否已经存在
	if _, exists := c.msgChans[connID]; exists {
		logger.Debug("Message channel already exists for connection", "client_id", c.getClientID(), "conn_id", connID)
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // 缓冲100条消息
	c.msgChans[connID] = msgChan

	logger.Debug("Created message channel for connection", "client_id", c.getClientID(), "conn_id", connID, "buffer_size", 100)

	// 为此连接启动消息处理器 (与 v1 相同)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages 按顺序处理特定连接的消息 (与 v1 相同)
func (c *Client) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
	logger.Debug("Starting connection message processor", "client_id", c.getClientID(), "conn_id", connID)

	messagesProcessed := 0

	defer func() {
		logger.Debug("Connection message processor finished", "client_id", c.getClientID(), "conn_id", connID, "messages_processed", messagesProcessed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection message processor stopping due to context", "client_id", c.getClientID(), "conn_id", connID, "messages_processed", messagesProcessed)
			return
		case msg, ok := <-msgChan:
			if !ok {
				logger.Debug("Message channel closed for connection", "client_id", c.getClientID(), "conn_id", connID, "messages_processed", messagesProcessed)
				return
			}

			messagesProcessed++
			msgType, _ := msg["type"].(string)

			switch msgType {
			case common.MsgTypeConnect:
				c.handleConnectMessage(msg)
			case common.MsgTypeData:
				c.handleDataMessage(msg)
			case common.MsgTypeClose:
				logger.Debug("Received close message, stopping connection processor", "client_id", c.getClientID(), "conn_id", connID, "messages_processed", messagesProcessed)
				c.handleCloseMessage(msg)
				return // 连接关闭，停止处理
			default:
				logger.Warn("Unknown message type in connection processor", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
			}
		}
	}
}

// handleConnectMessage 处理来自网关的连接消息 (与 v1 相同)
func (c *Client) handleConnectMessage(msg map[string]interface{}) {
	// 提取连接信息
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in connect message", "client_id", c.getClientID(), "message_fields", getMessageFields(msg))
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		logger.Error("Invalid network in connect message", "client_id", c.getClientID(), "conn_id", connID, "message_fields", getMessageFields(msg))
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		logger.Error("Invalid address in connect message", "client_id", c.getClientID(), "conn_id", connID, "message_fields", getMessageFields(msg))
		return
	}

	logger.Info("Processing connect request from gateway", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		errorMsg := fmt.Sprintf("Connection denied - host '%s' is forbidden", address)
		logger.Error("❌ CONNECTION REJECTED - FORBIDDEN HOST", "client_id", c.getClientID(), "conn_id", connID, "address", address, "reason", "Host is in forbidden list or not in allowed list", "allowed_hosts", c.config.AllowedHosts, "forbidden_hosts", c.config.ForbiddenHosts)

		if err := c.sendConnectResponse(connID, false, errorMsg); err != nil {
			logger.Error("Failed to send connect response for forbidden host", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		}
		return
	}
	logger.Debug("Connection allowed by host filtering rules", "client_id", c.getClientID(), "conn_id", connID, "address", address)

	// 建立到目标的连接 (与 v1 相同)
	logger.Debug("Establishing connection to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()

	connectStart := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	connectDuration := time.Since(connectStart)

	if err != nil {
		logger.Error("Failed to establish connection to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration, "err", err)
		if sendErr := c.sendConnectResponse(connID, false, err.Error()); sendErr != nil {
			logger.Error("Failed to send connect response for connection error", "client_id", c.getClientID(), "conn_id", connID, "original_error", err, "send_error", sendErr)
		}
		return
	}

	logger.Info("Successfully connected to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration)

	// 注册连接 (与 v1 相同)
	c.connsMu.Lock()
	c.conns[connID] = conn
	connectionCount := len(c.conns)
	c.connsMu.Unlock()

	logger.Debug("Connection registered", "client_id", c.getClientID(), "conn_id", connID, "total_connections", connectionCount)

	// 发送成功响应 (与 v1 相同)
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		logger.Error("Error sending connect_response to gateway", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		c.cleanupConnection(connID)
		return
	}

	// 开始处理连接 (与 v1 相同)
	logger.Debug("Starting connection handler", "client_id", c.getClientID(), "conn_id", connID)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleConnection(connID)
	}()
}

// sendConnectResponse 发送连接响应到网关 (适配传输层)
func (c *Client) sendConnectResponse(connID string, success bool, errorMsg string) error {
	response := map[string]interface{}{
		"type":    common.MsgTypeConnectResponse,
		"id":      connID,
		"success": success,
		"error":   errorMsg,
	}

	logger.Debug("Sending connect response to gateway", "client_id", c.getClientID(), "conn_id", connID, "success", success, "error_message", errorMsg)

	err := c.conn.WriteJSON(response)
	if err != nil {
		logger.Error("Failed to write connect response to transport", "client_id", c.getClientID(), "conn_id", connID, "success", success, "err", err)
	} else {
		logger.Debug("Connect response sent successfully", "client_id", c.getClientID(), "conn_id", connID, "success", success)
	}

	return err
}

// handleConnection 从目标连接读取数据并发送到网关 (与 v1 相同，适配传输层)
func (c *Client) handleConnection(connID string) {
	logger.Debug("Starting connection handler", "client_id", c.getClientID(), "conn_id", connID)

	// 获取连接
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		logger.Warn("Connection handler started for unknown connection", "client_id", c.getClientID(), "conn_id", connID)
		return
	}

	// 增加缓冲区大小以获得更好的性能 (与 v1 相同)
	buffer := make([]byte, 32*1024) // 32KB缓冲区匹配网关
	totalBytes := 0
	readCount := 0

	defer func() {
		logger.Debug("Connection handler finished", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_operations", readCount)
	}()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection handler stopping due to context cancellation", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes)
			return
		default:
		}

		// Set read deadline based on context - use longer timeout for proxy connections
		deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			logger.Debug("Failed to set read deadline", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		}

		n, err := conn.Read(buffer)
		readCount++

		if n > 0 {
			totalBytes += n
			// 只记录较大的传输以减少噪音 (与 v1 相同)
			if totalBytes%100000 == 0 || n > 10000 {
				logger.Debug("Client read data from target connection", "client_id", c.getClientID(), "conn_id", connID, "bytes_this_read", n, "total_bytes", totalBytes, "read_count", readCount)
			}

			// 将二进制数据编码为base64字符串 (与 v1 相同)
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			// 🆕 使用传输层发送数据
			dataMsg := map[string]interface{}{
				"type": common.MsgTypeData,
				"id":   connID,
				"data": encodedData,
			}

			writeErr := c.conn.WriteJSON(dataMsg)
			if writeErr != nil {
				logger.Error("Error writing data to transport", "client_id", c.getClientID(), "conn_id", connID, "data_bytes", n, "total_bytes", totalBytes, "err", writeErr)
				c.cleanupConnection(connID)
				return
			}

			// 只记录较大的传输 (与 v1 相同)
			if n > 10000 {
				logger.Debug("Client successfully sent large data chunk to gateway", "client_id", c.getClientID(), "conn_id", connID, "bytes", n, "total_bytes", totalBytes)
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查超时是否由于上下文取消 (与 v1 相同)
				select {
				case <-c.ctx.Done():
					logger.Debug("Connection handler stopping due to context during timeout", "client_id", c.getClientID(), "conn_id", connID)
					return
				default:
					continue // 如果上下文仍然有效，则在超时时继续
				}
			}

			// 优雅地处理连接关闭错误 (与 v1 相同)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				logger.Debug("Target connection closed during read operation", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			} else if err != io.EOF {
				logger.Error("Error reading from target connection", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount, "err", err)
			} else {
				logger.Debug("Target connection closed (EOF)", "client_id", c.getClientID(), "conn_id", connID, "total_bytes", totalBytes, "read_count", readCount)
			}

			// 🆕 发送关闭消息到网关
			closeMsg := map[string]interface{}{
				"type": common.MsgTypeClose,
				"id":   connID,
			}

			closeErr := c.conn.WriteJSON(closeMsg)
			if closeErr != nil {
				logger.Debug("Error sending close message to gateway", "client_id", c.getClientID(), "conn_id", connID, "err", closeErr)
			} else {
				logger.Debug("Sent close message to gateway", "client_id", c.getClientID(), "conn_id", connID)
			}

			c.cleanupConnection(connID)
			return
		}
	}
}

// isConnectionAllowed 检查到给定地址的连接是否被允许 (与 v1 相同)
func (c *Client) isConnectionAllowed(address string) bool {
	host := address
	if idx := strings.LastIndex(address, ":"); idx > 0 {
		host = address[:idx]
	}

	logger.Debug("Checking connection permissions", "client_id", c.getClientID(), "address", address, "extracted_host", host, "allowed_hosts_count", len(c.config.AllowedHosts), "forbidden_hosts_count", len(c.config.ForbiddenHosts))

	// 首先检查禁止的主机 (与 v1 相同)
	for _, forbidden := range c.config.ForbiddenHosts {
		re := regexp.MustCompile(forbidden)
		if re.MatchString(host) {
			logger.Debug("Connection rejected by forbidden regex pattern", "client_id", c.getClientID(), "host", host, "forbidden_pattern", forbidden)
			return false
		}

		if strings.HasSuffix(host, forbidden) {
			logger.Debug("Connection rejected by forbidden suffix", "client_id", c.getClientID(), "host", host, "forbidden_suffix", forbidden)
			return false
		}
	}

	// 如果没有指定允许的主机，则允许所有（除了禁止的）(与 v1 相同)
	if len(c.config.AllowedHosts) == 0 {
		logger.Debug("Connection allowed - no allowed hosts restrictions", "client_id", c.getClientID(), "host", host)
		return true
	}

	// 检查允许的主机 (与 v1 相同)
	for _, allowed := range c.config.AllowedHosts {
		re := regexp.MustCompile(allowed)
		if re.MatchString(host) {
			logger.Debug("Connection allowed by regex pattern", "client_id", c.getClientID(), "host", host, "allowed_pattern", allowed)
			return true
		}

		if strings.HasSuffix(host, allowed) {
			logger.Debug("Connection allowed by suffix", "client_id", c.getClientID(), "host", host, "allowed_suffix", allowed)
			return true
		}
	}

	logger.Debug("Connection rejected - not in allowed hosts", "client_id", c.getClientID(), "host", host, "allowed_hosts", c.config.AllowedHosts)
	return false
}

// handleDataMessage 处理来自网关的数据消息 (与 v1 相同)
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// 提取消息信息
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in data message", "client_id", c.getClientID(), "message_fields", getMessageFields(msg))
		return
	}

	dataStr, ok := msg["data"].(string)
	if !ok {
		logger.Error("Invalid data format in data message", "client_id", c.getClientID(), "conn_id", connID, "data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// 将base64字符串解码回[]byte (与 v1 相同)
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		logger.Error("Failed to decode base64 data", "client_id", c.getClientID(), "conn_id", connID, "data_length", len(dataStr), "err", err)
		return
	}

	// 只记录较大的传输以减少噪音 (与 v1 相同)
	if len(data) > 10000 {
		logger.Debug("Client received large data chunk from gateway", "client_id", c.getClientID(), "conn_id", connID, "bytes", len(data))
	}

	// 获取连接 (与 v1 相同)
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		logger.Warn("Data message for unknown connection", "client_id", c.getClientID(), "conn_id", connID, "data_bytes", len(data))
		return
	}

	// Write data to the connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(30 * time.Second) // Increased from 5s to 30s for better proxy performance
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		logger.Debug("Failed to set write deadline", "client_id", c.getClientID(), "conn_id", connID, "err", err)
	}

	n, err := conn.Write(data)
	if err != nil {
		logger.Error("Failed to write data to target connection", "client_id", c.getClientID(), "conn_id", connID, "data_bytes", len(data), "written_bytes", n, "err", err)
		c.cleanupConnection(connID)
		return
	}

	// 只记录较大的传输 (与 v1 相同)
	if n > 10000 {
		logger.Debug("Client successfully wrote large data chunk to target connection", "client_id", c.getClientID(), "conn_id", connID, "bytes", n)
	}
}

// handleCloseMessage 处理来自网关的关闭消息 (与 v1 相同)
func (c *Client) handleCloseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in close message", "client_id", c.getClientID(), "message_fields", getMessageFields(msg))
		return
	}

	logger.Info("Received close message from gateway", "client_id", c.getClientID(), "conn_id", connID)
	c.cleanupConnection(connID)
}

// cleanupConnection 清理连接 (与 v1 相同)
func (c *Client) cleanupConnection(connID string) {
	logger.Debug("Initiating connection cleanup", "client_id", c.getClientID(), "conn_id", connID)

	c.connsMu.Lock()
	conn, exists := c.conns[connID]
	if exists {
		delete(c.conns, connID)
	}
	remainingConnections := len(c.conns)
	c.connsMu.Unlock()

	// 清理消息通道 (与 v1 相同)
	c.msgChansMu.Lock()
	if msgChan, exists := c.msgChans[connID]; exists {
		delete(c.msgChans, connID)
		close(msgChan)
		logger.Debug("Message channel closed and removed", "client_id", c.getClientID(), "conn_id", connID)
	}
	c.msgChansMu.Unlock()

	if exists && conn != nil {
		if err := conn.Close(); err != nil {
			logger.Debug("Error closing target connection (expected during shutdown)", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		} else {
			logger.Debug("Target connection closed successfully", "client_id", c.getClientID(), "conn_id", connID)
		}

		logger.Info("Connection cleaned up successfully", "client_id", c.getClientID(), "conn_id", connID, "remaining_connections", remainingConnections)
	} else {
		logger.Debug("Connection cleanup requested for non-existent connection", "client_id", c.getClientID(), "conn_id", connID)
	}
}

// sendPortForwardingRequest 发送端口转发请求到网关 (从 v1 完整迁移)
func (c *Client) sendPortForwardingRequest() error {
	if len(c.config.OpenPorts) == 0 {
		logger.Debug("No ports configured for forwarding", "client_id", c.getClientID())
		return nil
	}

	logger.Info("Sending port forwarding request to gateway", "client_id", c.getClientID(), "port_count", len(c.config.OpenPorts))

	// Log details of each port configuration
	for i, openPort := range c.config.OpenPorts {
		logger.Debug("Port forwarding configuration", "client_id", c.getClientID(), "port_index", i, "remote_port", openPort.RemotePort, "local_port", openPort.LocalPort, "local_host", openPort.LocalHost, "protocol", openPort.Protocol)
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
		"type":       common.MsgTypePortForwardReq,
		"open_ports": openPorts,
	}

	// 🆕 使用传输层发送请求
	err := c.conn.WriteJSON(request)
	if err != nil {
		logger.Error("Failed to send port forwarding request", "client_id", c.getClientID(), "port_count", len(c.config.OpenPorts), "err", err)
	} else {
		logger.Debug("Port forwarding request sent successfully", "client_id", c.getClientID(), "port_count", len(c.config.OpenPorts))
	}

	return err
}

// handlePortForwardResponse 处理来自网关的端口转发响应 (与 v1 相同)
func (c *Client) handlePortForwardResponse(msg map[string]interface{}) {
	// 提取响应信息
	success, ok := msg["success"].(bool)
	if !ok {
		logger.Error("Invalid success status in port forwarding response", "client_id", c.getClientID(), "message_fields", getMessageFields(msg))
		return
	}

	message, _ := msg["message"].(string)

	if success {
		logger.Info("Port forwarding request successful", "client_id", c.getClientID(), "message", message, "port_count", len(c.config.OpenPorts))
	} else {
		logger.Error("Port forwarding request failed", "client_id", c.getClientID(), "message", message, "port_count", len(c.config.OpenPorts))
	}
}

// getMessageFields 获取安全的消息字段名称用于日志记录 (与 v1 相同)
func getMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}

// createTLSConfig creates a TLS configuration for the client (从 v1 完整迁移)
func (c *Client) createTLSConfig() (*tls.Config, error) {
	logger.Debug("Creating TLS configuration", "client_id", c.getClientID())

	// 基本TLS配置 (与 v1 相同)
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	logger.Debug("Base TLS configuration created", "min_version", "TLS1.2", "max_version", "TLS1.3")

	// 如果提供了自定义CA证书 (与 v1 相同)
	if c.config.GatewayTLSCert != "" {
		logger.Debug("Loading custom gateway TLS certificate", "cert_file", c.config.GatewayTLSCert)

		certData, err := os.ReadFile(c.config.GatewayTLSCert)
		if err != nil {
			logger.Error("Failed to read gateway TLS certificate file", "client_id", c.getClientID(), "cert_file", c.config.GatewayTLSCert, "err", err)
			return nil, fmt.Errorf("failed to read gateway TLS certificate: %v", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(certData) {
			logger.Error("Failed to parse gateway TLS certificate", "client_id", c.getClientID(), "cert_file", c.config.GatewayTLSCert)
			return nil, fmt.Errorf("failed to parse gateway TLS certificate")
		}

		tlsConfig.RootCAs = caCertPool
		logger.Debug("Custom TLS certificate loaded successfully", "cert_file", c.config.GatewayTLSCert)
	} else {
		// 使用系统默认的CA证书 (与 v1 相同)
		logger.Debug("Using system default TLS certificates", "client_id", c.getClientID())
	}

	return tlsConfig, nil
}
