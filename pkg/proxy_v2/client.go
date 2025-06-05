package proxy_v2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"

	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/grpc"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/quic"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/websocket"
)

const (
	writeBufSize = 1000
)

// Client represents the proxy client (基于 v1 设计)
type Client struct {
	config     *config.ClientConfig
	transport  transport.Transport  // 🆕 唯一的新增抽象
	conn       transport.Connection // 🆕 传输层连接
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
	slog.Info("Creating new client",
		"client_id", cfg.ClientID,
		"gateway_addr", cfg.GatewayAddr,
		"group_id", cfg.GroupID,
		"transport_type", transportType,
		"allowed_hosts_count", len(cfg.AllowedHosts),
		"forbidden_hosts_count", len(cfg.ForbiddenHosts),
		"open_ports_count", len(cfg.OpenPorts),
		"auth_enabled", cfg.AuthUsername != "")

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

	slog.Debug("Client initialization completed",
		"client_id", cfg.ClientID,
		"transport_type", transportType)

	return client, nil
}

// Start starts the client with automatic reconnection (与 v1 相同)
func (c *Client) Start() error {
	slog.Info("Starting proxy client",
		"client_id", c.config.ClientID,
		"gateway_addr", c.config.GatewayAddr,
		"group_id", c.config.GroupID)

	startTime := time.Now()

	// 启动主连接循环 (与 v1 相同)
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

// Stop stops the client gracefully (与 v1 相同)
func (c *Client) Stop() error {
	slog.Info("Initiating graceful client shutdown", "client_id", c.config.ClientID)
	stopTime := time.Now()

	// Step 1: 取消上下文 (与 v1 相同)
	slog.Debug("Cancelling client context", "client_id", c.config.ClientID)
	c.cancel()

	// Step 2: 获取连接数量 (与 v1 相同)
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	if connectionCount > 0 {
		slog.Info("Waiting for active connections to finish",
			"client_id", c.config.ClientID,
			"connection_count", connectionCount)
	}

	// 等待现有连接完成 (与 v1 相同)
	select {
	case <-c.ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}

	// Step 3: 🆕 停止传输层连接
	if c.conn != nil {
		slog.Debug("Stopping transport connection during cleanup", "client_id", c.config.ClientID)
		c.conn.Close()
		slog.Debug("Transport connection stopped", "client_id", c.config.ClientID)
	}

	// Step 4: 关闭所有连接 (与 v1 相同)
	slog.Debug("Closing all connections",
		"client_id", c.config.ClientID,
		"connection_count", connectionCount)
	c.closeAllConnections()
	if connectionCount > 0 {
		slog.Debug("All connections closed", "client_id", c.config.ClientID)
	}

	// Step 5: 等待所有goroutine完成 (与 v1 相同)
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

// connectionLoop handles connection and reconnection logic (与 v1 相同，但使用传输层)
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

		// 尝试连接 (🆕 使用传输层抽象)
		connectStart := time.Now()
		if err := c.connect(); err != nil {
			connectDuration := time.Since(connectStart)
			slog.Error("Failed to connect to gateway",
				"client_id", c.config.ClientID,
				"attempt", connectionAttempts,
				"connect_duration", connectDuration,
				"error", err,
				"retrying_in", backoff)

			// 等待重试 (与 v1 相同)
			select {
			case <-c.ctx.Done():
				slog.Debug("Connection retry cancelled due to context",
					"client_id", c.config.ClientID)
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
		connectDuration := time.Since(connectStart)
		backoff = 1 * time.Second
		slog.Info("Successfully connected to gateway",
			"client_id", c.config.ClientID,
			"attempt", connectionAttempts,
			"connect_duration", connectDuration,
			"gateway_addr", c.config.GatewayAddr)

		// 处理消息 (与 v1 相同)
		messageStart := time.Now()
		c.handleMessages()
		messageDuration := time.Since(messageStart)

		// 检查是否停止 (与 v1 相同)
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection loop ending due to context cancellation",
				"client_id", c.config.ClientID,
				"message_handling_duration", messageDuration)
			return
		default:
		}

		// 连接丢失，清理并重试 (与 v1 相同)
		slog.Info("Connection to gateway lost, cleaning up and retrying...",
			"client_id", c.config.ClientID,
			"message_handling_duration", messageDuration,
			"total_attempts", connectionAttempts)
		c.cleanup()
	}
}

// cleanup cleans up resources after connection loss (与 v1 相同逻辑，使用传输层)
func (c *Client) cleanup() {
	slog.Debug("Starting cleanup after connection loss", "client_id", c.config.ClientID)
	cleanupStart := time.Now()

	// 🆕 停止传输层连接
	if c.conn != nil {
		slog.Debug("Stopping transport connection during cleanup", "client_id", c.config.ClientID)
		c.conn.Close()
		slog.Debug("Transport connection stopped", "client_id", c.config.ClientID)
	}

	// 获取连接数量 (与 v1 相同)
	c.connsMu.RLock()
	connectionCount := len(c.conns)
	c.connsMu.RUnlock()

	// 关闭所有连接 (与 v1 相同)
	if connectionCount > 0 {
		slog.Debug("Closing connections during cleanup",
			"client_id", c.config.ClientID,
			"connection_count", connectionCount)
		c.closeAllConnections()
	}

	elapsed := time.Since(cleanupStart)
	slog.Debug("Cleanup completed",
		"client_id", c.config.ClientID,
		"cleanup_duration", elapsed,
		"connections_closed", connectionCount)
}

// closeAllConnections closes all active connections (与 v1 相同)
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

	// 关闭所有消息通道 (与 v1 相同)
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

// connect establishes a connection to the gateway (🆕 使用传输层抽象，但逻辑与 v1 相同)
func (c *Client) connect() error {
	slog.Debug("Establishing connection to gateway",
		"client_id", c.config.ClientID,
		"gateway_addr", c.config.GatewayAddr)

	// 生成唯一的客户端ID (与 v1 相同)
	clientID := c.generateClientID()

	// 🆕 创建 TLS 配置 (从 v1 迁移)
	var tlsConfig *tls.Config
	if c.config.GatewayTLSCert != "" || strings.HasPrefix(c.config.GatewayAddr, "wss://") {
		slog.Debug("Creating TLS configuration", "client_id", clientID)
		var err error
		tlsConfig, err = c.createTLSConfig()
		if err != nil {
			slog.Error("Failed to create TLS configuration",
				"client_id", clientID,
				"gateway_addr", c.config.GatewayAddr,
				"error", err)
			return fmt.Errorf("failed to create TLS configuration: %v", err)
		}
		slog.Debug("TLS configuration created successfully", "client_id", clientID)
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

	slog.Debug("Transport configuration created",
		"client_id", clientID,
		"group_id", c.config.GroupID,
		"auth_enabled", c.config.AuthUsername != "",
		"tls_enabled", tlsConfig != nil)

	// 🆕 使用传输层进行连接
	conn, err := c.transport.DialWithConfig(c.config.GatewayAddr, transportConfig)
	if err != nil {
		slog.Error("Failed to connect via transport layer",
			"client_id", clientID,
			"gateway_addr", c.config.GatewayAddr,
			"error", err)
		return fmt.Errorf("failed to connect via transport: %v", err)
	}

	c.conn = conn
	slog.Info("Transport connection established successfully",
		"client_id", clientID,
		"group_id", c.config.GroupID,
		"remote_addr", conn.RemoteAddr())

	// 发送端口转发请求 (与 v1 相同)
	if len(c.config.OpenPorts) > 0 {
		slog.Debug("Sending port forwarding request",
			"client_id", clientID,
			"port_count", len(c.config.OpenPorts))
		if err := c.sendPortForwardingRequest(); err != nil {
			slog.Error("Failed to send port forwarding request",
				"client_id", clientID,
				"error", err)
			// 继续执行，端口转发是可选的
		}
	} else {
		slog.Debug("No port forwarding configured", "client_id", clientID)
	}

	return nil
}

// generateClientID generates a unique client ID (与 v1 相同)
func (c *Client) generateClientID() string {
	generatedID := fmt.Sprintf("%s-%s", c.config.ClientID, xid.New().String())
	slog.Debug("Generated unique client ID",
		"base_client_id", c.config.ClientID,
		"generated_client_id", generatedID)
	return generatedID
}

// handleMessages 处理来自网关的消息 (从 v1 迁移，适配传输层)
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

		// 🆕 直接读取 JSON 消息，简化代码
		var msg map[string]interface{}
		if err := c.conn.ReadJSON(&msg); err != nil {
			slog.Error("Transport read error",
				"client_id", c.config.ClientID,
				"messages_processed", messageCount,
				"error", err)
			// 连接失败，退出以触发重连
			return
		}

		messageCount++

		// 定期记录消息统计 (与 v1 相同)
		if messageCount%100 == 0 || time.Since(lastLogTime) > 30*time.Second {
			slog.Debug("Message processing statistics",
				"client_id", c.config.ClientID,
				"messages_processed", messageCount)
			lastLogTime = time.Now()
		}

		// 基于类型处理消息 (与 v1 相同)
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from gateway - missing type field",
				"client_id", c.config.ClientID,
				"message_count", messageCount,
				"message_fields", getMessageFields(msg))
			continue
		}

		// 记录消息处理（但不记录高频数据消息）(与 v1 相同)
		if msgType != "data" {
			slog.Debug("Processing gateway message",
				"client_id", c.config.ClientID,
				"message_type", msgType,
				"message_count", messageCount)
		}

		switch msgType {
		case "connect", "data", "close":
			// 将所有消息路由到每个连接的通道 (与 v1 相同)
			c.routeMessage(msg)
		case "port_forward_response":
			// 直接处理端口转发响应 (与 v1 相同)
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

// routeMessage 将消息路由到适当连接的消息通道 (与 v1 相同)
func (c *Client) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message from gateway",
			"client_id", c.config.ClientID,
			"message_fields", getMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// 对于连接消息，首先创建通道 (与 v1 相同)
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
		// 连接不存在，忽略消息 (与 v1 相同)
		slog.Debug("Ignoring message for non-existent connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"message_type", msgType)
		return
	}

	// 发送消息到连接的通道（非阻塞，带上下文感知）(与 v1 相同)
	select {
	case msgChan <- msg:
		// 成功路由，不记录高频数据消息
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

// createMessageChannel 为连接创建消息通道 (与 v1 相同)
func (c *Client) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// 检查通道是否已经存在
	if _, exists := c.msgChans[connID]; exists {
		slog.Debug("Message channel already exists for connection",
			"client_id", c.config.ClientID,
			"conn_id", connID)
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // 缓冲100条消息
	c.msgChans[connID] = msgChan

	slog.Debug("Created message channel for connection",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"buffer_size", 100)

	// 为此连接启动消息处理器 (与 v1 相同)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages 按顺序处理特定连接的消息 (与 v1 相同)
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
				return // 连接关闭，停止处理
			default:
				slog.Warn("Unknown message type in connection processor",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"message_type", msgType)
			}
		}
	}
}

// handleConnectMessage 处理来自网关的连接消息 (与 v1 相同)
func (c *Client) handleConnectMessage(msg map[string]interface{}) {
	// 提取连接信息
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

	// 检查连接是否被允许 (与 v1 相同)
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

	// 建立到目标的连接 (与 v1 相同)
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

	// 注册连接 (与 v1 相同)
	c.connsMu.Lock()
	c.conns[connID] = conn
	connectionCount := len(c.conns)
	c.connsMu.Unlock()

	slog.Debug("Connection registered",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"total_connections", connectionCount)

	// 发送成功响应 (与 v1 相同)
	if err := c.sendConnectResponse(connID, true, ""); err != nil {
		slog.Error("Error sending connect_response to gateway",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"error", err)
		c.cleanupConnection(connID)
		return
	}

	// 开始处理连接 (与 v1 相同)
	slog.Debug("Starting connection handler",
		"client_id", c.config.ClientID,
		"conn_id", connID)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleConnection(connID)
	}()
}

// sendConnectResponse 发送连接响应到网关 (适配传输层)
func (c *Client) sendConnectResponse(connID string, success bool, errorMsg string) error {
	response := map[string]interface{}{
		"type":    "connect_response",
		"id":      connID,
		"success": success,
		"error":   errorMsg,
	}

	slog.Debug("Sending connect response to gateway",
		"client_id", c.config.ClientID,
		"conn_id", connID,
		"success", success,
		"error_message", errorMsg)

	err := c.conn.WriteJSON(response)
	if err != nil {
		slog.Error("Failed to write connect response to transport",
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

// handleConnection 从目标连接读取数据并发送到网关 (与 v1 相同，适配传输层)
func (c *Client) handleConnection(connID string) {
	slog.Debug("Starting connection handler",
		"client_id", c.config.ClientID,
		"conn_id", connID)

	// 获取连接
	c.connsMu.RLock()
	conn, ok := c.conns[connID]
	c.connsMu.RUnlock()
	if !ok {
		slog.Warn("Connection handler started for unknown connection",
			"client_id", c.config.ClientID,
			"conn_id", connID)
		return
	}

	// 增加缓冲区大小以获得更好的性能 (与 v1 相同)
	buffer := make([]byte, 32*1024) // 32KB缓冲区匹配网关
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

		// 基于上下文设置读取截止时间 (与 v1 相同)
		deadline := time.Now().Add(30 * time.Second) // 增加到30秒以获得更好的代理性能
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		conn.SetReadDeadline(deadline)

		n, err := conn.Read(buffer)
		readCount++

		if n > 0 {
			totalBytes += n
			// 只记录较大的传输以减少噪音 (与 v1 相同)
			if totalBytes%100000 == 0 || n > 10000 {
				slog.Debug("Client read data from target connection",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"bytes_this_read", n,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// 将二进制数据编码为base64字符串 (与 v1 相同)
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			// 🆕 使用传输层发送数据
			dataMsg := map[string]interface{}{
				"type": "data",
				"id":   connID,
				"data": encodedData,
			}

			writeErr := c.conn.WriteJSON(dataMsg)
			if writeErr != nil {
				slog.Error("Error writing data to transport",
					"client_id", c.config.ClientID,
					"conn_id", connID,
					"data_bytes", n,
					"total_bytes", totalBytes,
					"error", writeErr)
				c.cleanupConnection(connID)
				return
			}

			// 只记录较大的传输 (与 v1 相同)
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
				// 检查超时是否由于上下文取消 (与 v1 相同)
				select {
				case <-c.ctx.Done():
					slog.Debug("Connection handler stopping due to context during timeout",
						"client_id", c.config.ClientID,
						"conn_id", connID)
					return
				default:
					continue // 如果上下文仍然有效，则在超时时继续
				}
			}

			// 优雅地处理连接关闭错误 (与 v1 相同)
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

			// 🆕 发送关闭消息到网关
			closeMsg := map[string]interface{}{
				"type": "close",
				"id":   connID,
			}

			closeErr := c.conn.WriteJSON(closeMsg)
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

// isConnectionAllowed 检查到给定地址的连接是否被允许 (与 v1 相同)
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

	// 首先检查禁止的主机 (与 v1 相同)
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

	// 如果没有指定允许的主机，则允许所有（除了禁止的）(与 v1 相同)
	if len(c.config.AllowedHosts) == 0 {
		slog.Debug("Connection allowed - no allowed hosts restrictions",
			"client_id", c.config.ClientID,
			"host", host)
		return true
	}

	// 检查允许的主机 (与 v1 相同)
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

// handleDataMessage 处理来自网关的数据消息 (与 v1 相同)
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// 提取消息信息
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

	// 将base64字符串解码回[]byte (与 v1 相同)
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"data_length", len(dataStr),
			"error", err)
		return
	}

	// 只记录较大的传输以减少噪音 (与 v1 相同)
	if len(data) > 10000 {
		slog.Debug("Client received large data chunk from gateway",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"bytes", len(data))
	}

	// 获取连接 (与 v1 相同)
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

	// 将数据写入连接，带上下文感知 (与 v1 相同)
	deadline := time.Now().Add(30 * time.Second) // 增加到30秒以获得更好的代理性能
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

	// 只记录较大的传输 (与 v1 相同)
	if n > 10000 {
		slog.Debug("Client successfully wrote large data chunk to target connection",
			"client_id", c.config.ClientID,
			"conn_id", connID,
			"bytes", n)
	}
}

// handleCloseMessage 处理来自网关的关闭消息 (与 v1 相同)
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

// cleanupConnection 清理连接 (与 v1 相同)
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

	// 清理消息通道 (与 v1 相同)
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

// sendPortForwardingRequest 发送端口转发请求到网关 (从 v1 完整迁移)
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

	// 🆕 使用传输层发送请求
	err := c.conn.WriteJSON(request)
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

// handlePortForwardResponse 处理来自网关的端口转发响应 (与 v1 相同)
func (c *Client) handlePortForwardResponse(msg map[string]interface{}) {
	// 提取响应信息
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
	slog.Debug("Creating TLS configuration", "client_id", c.config.ClientID)

	// 🚨 修复：正确设置 ServerName，与 v1 保持一致
	serverName := strings.Split(c.config.GatewayAddr, ":")[0]
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName, // 🆕 从 v1 迁移
	}

	slog.Debug("Base TLS configuration created",
		"client_id", c.config.ClientID,
		"server_name", serverName, // 🆕 添加日志
		"min_version", "TLS 1.2")

	// Load custom certificate if specified
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
