package client

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/monitoring"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/protocol"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/utils"
)

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

		// 🆕 读取消息（使用二进制格式）
		msg, err := c.readNextMessage()
		if err != nil {
			logger.Error("Transport read error", "client_id", c.getClientID(), "messages_processed", messageCount, "err", err)
			// 连接失败，退出以触发重连
			return
		}

		messageCount++

		// 基于类型处理消息 (与 v1 相同)
		msgType, ok := msg["type"].(string)
		if !ok {
			logger.Error("Invalid message format from gateway", "client_id", c.getClientID(), "message_count", messageCount, "message_fields", utils.GetMessageFields(msg))
			continue
		}

		// 记录消息处理（但不记录高频数据消息）(与 v1 相同)
		if msgType != protocol.MsgTypeData {
			logger.Debug("Processing gateway message", "client_id", c.getClientID(), "message_type", msgType, "message_count", messageCount)
		}

		switch msgType {
		case protocol.MsgTypeConnect, protocol.MsgTypeData, protocol.MsgTypeClose:
			// 将所有消息路由到每个连接的通道 (与 v1 相同)
			c.routeMessage(msg)
		case protocol.MsgTypePortForwardResp:
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
		logger.Error("Invalid connection ID in message from gateway", "client_id", c.getClientID(), "message_fields", utils.GetMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// 对于连接消息，首先创建通道 (与 v1 相同)
	if msgType == protocol.MsgTypeConnect {
		logger.Debug("Creating message channel for new connection request", "client_id", c.getClientID(), "conn_id", connID)
		c.createMessageChannel(connID)
	}

	msgChan, exists := c.connMgr.GetMessageChannel(connID)
	if !exists {
		// 连接不存在，忽略消息 (与 v1 相同)
		logger.Debug("Ignoring message for non-existent connection", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		return
	}

	// 发送消息到连接的通道（非阻塞，带上下文感知）(与 v1 相同)
	select {
	case msgChan <- msg:
		// 成功路由，不记录高频数据消息
		if msgType != protocol.MsgTypeData {
			logger.Debug("Message routed to connection handler", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		}
	case <-c.ctx.Done():
		logger.Debug("Message routing cancelled due to context", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType)
		return
	default:
		// 修复：当通道满时关闭连接，而不是静默丢弃消息
		logger.Error("Message channel full for connection, closing connection to prevent protocol inconsistency", "client_id", c.getClientID(), "conn_id", connID, "message_type", msgType, "channel_size", len(msgChan), "channel_cap", cap(msgChan))
		// 异步清理连接，避免死锁
		go c.cleanupConnection(connID)
		return
	}
}

// createMessageChannel 为连接创建消息通道 (与 v1 相同)
func (c *Client) createMessageChannel(connID string) {
	msgChan := c.connMgr.CreateMessageChannel(connID, protocol.DefaultMessageChannelSize)

	logger.Debug("Created message channel for connection", "client_id", c.getClientID(), "conn_id", connID, "buffer_size", protocol.DefaultMessageChannelSize)

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
			case protocol.MsgTypeConnect:
				c.handleConnectMessage(msg)
			case protocol.MsgTypeData:
				c.handleDataMessage(msg)
			case protocol.MsgTypeClose:
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
		logger.Error("Invalid connection ID in connect message", "client_id", c.getClientID(), "message_fields", utils.GetMessageFields(msg))
		return
	}

	network, ok := msg["network"].(string)
	if !ok {
		logger.Error("Invalid network in connect message", "client_id", c.getClientID(), "conn_id", connID, "message_fields", utils.GetMessageFields(msg))
		return
	}

	address, ok := msg["address"].(string)
	if !ok {
		logger.Error("Invalid address in connect message", "client_id", c.getClientID(), "conn_id", connID, "message_fields", utils.GetMessageFields(msg))
		return
	}

	logger.Info("Processing connect request from gateway", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address)

	// Check if the connection is allowed
	if !c.isConnectionAllowed(address) {
		errorMsg := fmt.Sprintf("Connection denied - host '%s' is forbidden", address)
		logger.Error("Connection rejected - forbidden host", "client_id", c.getClientID(), "conn_id", connID, "address", address, "reason", "Host is in forbidden list or not in allowed list", "allowed_hosts", c.config.AllowedHosts, "forbidden_hosts", c.config.ForbiddenHosts)

		if err := c.sendConnectResponse(connID, false, errorMsg); err != nil {
			logger.Error("Failed to send connect response for forbidden host", "client_id", c.getClientID(), "conn_id", connID, "err", err)
		}
		return
	}
	logger.Debug("Connection allowed by host filtering rules", "client_id", c.getClientID(), "conn_id", connID, "address", address)

	// 建立到目标的连接 (与 v1 相同)
	logger.Debug("Establishing connection to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address)

	var d net.Dialer
	ctx, cancel := context.WithTimeout(c.ctx, protocol.DefaultConnectTimeout)
	defer cancel()

	connectStart := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	connectDuration := time.Since(connectStart)

	if err != nil {
		logger.Error("Failed to establish connection to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration, "err", err)
		if sendErr := c.sendConnectResponse(connID, false, err.Error()); sendErr != nil {
			logger.Error("Failed to send connect response for connection error", "client_id", c.getClientID(), "conn_id", connID, "original_error", err, "send_error", sendErr)
		}
		// 更新失败指标
		monitoring.IncrementErrors()
		return
	}

	logger.Info("Successfully connected to target", "client_id", c.getClientID(), "conn_id", connID, "network", network, "address", address, "connect_duration", connectDuration)

	// 注册连接 (使用 ConnectionManager)
	c.connMgr.AddConnection(connID, conn)
	connectionCount := c.connMgr.GetConnectionCount()

	// 更新指标
	monitoring.IncrementActiveConnections()

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

// sendConnectResponse 发送连接响应到网关 (使用二进制格式)
func (c *Client) sendConnectResponse(connID string, success bool, errorMsg string) error {
	logger.Debug("Sending connect response to gateway", "client_id", c.getClientID(), "conn_id", connID, "success", success, "error_message", errorMsg)

	err := c.writeConnectResponse(connID, success, errorMsg)
	if err != nil {
		logger.Error("Failed to write connect response to transport", "client_id", c.getClientID(), "conn_id", connID, "success", success, "err", err)
	} else {
		logger.Debug("Connect response sent successfully", "client_id", c.getClientID(), "conn_id", connID, "success", success)
	}

	return err
}

// handleDataMessage 处理来自网关的数据消息 (与 v1 相同)
func (c *Client) handleDataMessage(msg map[string]interface{}) {
	// 提取消息信息
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in data message", "client_id", c.getClientID(), "message_fields", utils.GetMessageFields(msg))
		return
	}

	var data []byte

	// 首先尝试直接获取字节数据（二进制协议）
	if rawData, ok := msg["data"].([]byte); ok {
		data = rawData
	} else if dataStr, ok := msg["data"].(string); ok {
		// 兼容旧的 base64 格式
		decoded, err := base64.StdEncoding.DecodeString(dataStr)
		if err != nil {
			logger.Error("Failed to decode base64 data", "client_id", c.getClientID(), "conn_id", connID, "data_length", len(dataStr), "err", err)
			return
		}
		data = decoded
	} else {
		logger.Error("Invalid data format in data message", "client_id", c.getClientID(), "conn_id", connID, "data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// 只记录较大的传输以减少噪音 (与 v1 相同)
	if len(data) > 10000 {
		logger.Debug("Client received large data chunk from gateway", "client_id", c.getClientID(), "conn_id", connID, "bytes", len(data))
	}

	// 获取连接 (使用 ConnectionManager)
	conn, ok := c.connMgr.GetConnection(connID)
	if !ok {
		logger.Warn("Data message for unknown connection", "client_id", c.getClientID(), "conn_id", connID, "data_bytes", len(data))
		return
	}

	// Write data to the connection with context awareness - use longer timeout for proxy connections
	deadline := time.Now().Add(protocol.DefaultWriteTimeout)
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
		logger.Error("Invalid connection ID in close message", "client_id", c.getClientID(), "message_fields", utils.GetMessageFields(msg))
		return
	}

	logger.Info("Received close message from gateway", "client_id", c.getClientID(), "conn_id", connID)
	c.cleanupConnection(connID)
}
