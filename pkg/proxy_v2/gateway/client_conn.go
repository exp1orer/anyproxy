// Package gateway provides v2 gateway implementation for AnyProxy.
package gateway

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// ClientConn 客户端连接 (基于 v1，但连接类型改为传输层抽象)
type ClientConn struct {
	ID             string
	GroupID        string
	Conn           transport.Connection // 🆕 使用传输层连接
	ConnsMu        sync.RWMutex
	Conns          map[string]*Conn
	msgChans       map[string]chan map[string]interface{}
	msgChansMu     sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	stopOnce       sync.Once
	wg             sync.WaitGroup
	portForwardMgr *PortForwardManager
}

// Conn 连接结构 (与 v1 相同)
type Conn struct {
	ID        string
	LocalConn net.Conn
	Done      chan struct{}
	once      sync.Once
}

// Stop stops the client connection and cleans up resources.
func (c *ClientConn) Stop() {
	c.stopOnce.Do(func() {
		logger.Info("Initiating graceful client stop", "client_id", c.ID)

		// Step 1: 取消上下文 (与 v1 相同)
		logger.Debug("Cancelling client context", "client_id", c.ID)
		c.cancel()

		// Step 2: 获取连接数量 (与 v1 相同)
		c.ConnsMu.RLock()
		connectionCount := len(c.Conns)
		c.ConnsMu.RUnlock()

		if connectionCount > 0 {
			logger.Info("Waiting for active connections to finish", "client_id", c.ID, "connection_count", connectionCount)
		}

		// 等待连接完成当前操作 (与 v1 相同)
		gracefulWait := func(duration time.Duration) {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(duration):
				return
			}
		}
		gracefulWait(500 * time.Millisecond)

		// Step 3: 🆕 关闭传输层连接
		if c.Conn != nil {
			logger.Debug("Closing transport connection", "client_id", c.ID)
			if err := c.Conn.Close(); err != nil {
				logger.Debug("Error closing transport connection", "client_id", c.ID, "err", err)
			}
			logger.Debug("Transport connection closed", "client_id", c.ID)
		}

		// Step 4: 关闭所有代理连接 (与 v1 相同)
		logger.Debug("Closing all proxy connections", "client_id", c.ID, "connection_count", connectionCount)
		c.ConnsMu.Lock()
		for connID := range c.Conns {
			c.closeConnectionUnsafe(connID)
		}
		c.ConnsMu.Unlock()
		if connectionCount > 0 {
			logger.Debug("All proxy connections closed", "client_id", c.ID)
		}

		// Step 5: 关闭所有消息通道 (与 v1 相同)
		c.msgChansMu.Lock()
		channelCount := len(c.msgChans)
		for connID, msgChan := range c.msgChans {
			close(msgChan)
			delete(c.msgChans, connID)
		}
		c.msgChansMu.Unlock()
		if channelCount > 0 {
			logger.Debug("Closed message channels", "client_id", c.ID, "channel_count", channelCount)
		}

		// Step 6: 等待所有goroutine完成 (与 v1 相同)
		logger.Debug("Waiting for client goroutines to finish", "client_id", c.ID)
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			logger.Debug("All client goroutines finished gracefully", "client_id", c.ID)
		case <-time.After(2 * time.Second):
			logger.Warn("Timeout waiting for client goroutines to finish", "client_id", c.ID)
		}

		logger.Info("Client stop completed", "client_id", c.ID, "connections_closed", connectionCount, "channels_closed", channelCount)
	})
}

func (c *ClientConn) dialNetwork(network, addr string) (net.Conn, error) {
	// 生成连接ID (与 v1 相同)
	connID := xid.New().String()
	logger.Debug("Creating new network connection", "client_id", c.ID, "conn_id", connID, "network", network, "address", addr)

	// 创建管道连接客户端和代理 (与 v1 相同)
	pipe1, pipe2 := net.Pipe()

	// 创建代理连接 (与 v1 相同)
	proxyConn := &Conn{
		ID:        connID,
		Done:      make(chan struct{}),
		LocalConn: pipe2,
	}

	// 注册连接 (与 v1 相同)
	c.ConnsMu.Lock()
	c.Conns[connID] = proxyConn
	connCount := len(c.Conns)
	c.ConnsMu.Unlock()

	logger.Debug("Connection registered", "client_id", c.ID, "conn_id", connID, "total_connections", connCount)

	// 🆕 发送连接请求到客户端 (适配传输层)
	connectMsg := map[string]interface{}{
		"type":    "connect",
		"id":      connID,
		"network": network,
		"address": addr,
	}

	err := c.Conn.WriteJSON(connectMsg)
	if err != nil {
		logger.Error("Failed to send connect message to client", "client_id", c.ID, "conn_id", connID, "err", err)
		c.closeConnection(connID)
		return nil, err
	}

	logger.Debug("Connect message sent to client", "client_id", c.ID, "conn_id", connID, "network", network, "address", addr)

	// 启动连接处理 (与 v1 相同)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleConnection(proxyConn)
	}()

	// 🚨 修复：返回包装后的连接，与 v1 保持一致 (重要的地址信息包装)
	return common.NewConnWrapper(pipe1, network, addr), nil
}

// handleMessage 处理来自客户端的消息 (从 v1 迁移，适配传输层)
func (c *ClientConn) handleMessage() {
	logger.Debug("Starting message handler for client", "client_id", c.ID)
	messageCount := 0

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Message handler stopping due to context cancellation", "client_id", c.ID, "messages_processed", messageCount)
			return
		default:
		}

		// 🆕 直接读取 JSON 消息，简化代码
		var msg map[string]interface{}
		if err := c.Conn.ReadJSON(&msg); err != nil {
			logger.Error("Transport read error", "client_id", c.ID, "messages_processed", messageCount, "err", err)
			return
		}

		messageCount++

		// 处理消息类型 (与 v1 相同)
		msgType, ok := msg["type"].(string)
		if !ok {
			logger.Error("Invalid message format from client - missing or invalid type field", "client_id", c.ID, "message_count", messageCount, "message_fields", gatewayGetMessageFields(msg))
			continue
		}

		// 记录消息处理（但不记录高频数据消息）(与 v1 相同)
		if msgType != common.MsgTypeData {
			logger.Debug("Processing message", "client_id", c.ID, "message_type", msgType, "message_count", messageCount)
		}

		switch msgType {
		case common.MsgTypeConnectResponse, common.MsgTypeData, common.MsgTypeClose:
			// 将所有消息路由到每个连接的通道 (与 v1 相同)
			c.routeMessage(msg)
		case common.MsgTypePortForwardReq:
			// 直接处理端口转发请求 (与 v1 相同)
			logger.Info("Received port forwarding request", "client_id", c.ID)
			c.handlePortForwardRequest(msg)
		default:
			logger.Warn("Unknown message type received", "client_id", c.ID, "message_type", msgType, "message_count", messageCount)
		}
	}
}

// 以下方法从 v1 复制，保持逻辑不变

// routeMessage 将消息路由到适当连接的消息通道 (与 v1 相同)
func (c *ClientConn) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in message - missing or wrong type", "client_id", c.ID, "message_fields", gatewayGetMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// 对于 connect_response 消息，如果需要，首先创建通道 (与 v1 相同)
	if msgType == "connect_response" {
		logger.Debug("Creating message channel for connect response", "client_id", c.ID, "conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// 连接不存在，忽略消息 (与 v1 相同)
		logger.Debug("Ignoring message for non-existent connection", "client_id", c.ID, "conn_id", connID, "message_type", msgType)
		return
	}

	// 发送消息到连接的通道（非阻塞，带上下文感知）(与 v1 相同)
	select {
	case msgChan <- msg:
		// 成功路由，不记录高频数据消息 (与 v1 相同)
		if msgType != common.MsgTypeData {
			logger.Debug("Message routed successfully", "client_id", c.ID, "conn_id", connID, "message_type", msgType)
		}
	case <-c.ctx.Done():
		logger.Debug("Message routing cancelled due to context", "client_id", c.ID, "conn_id", connID, "message_type", msgType)
		return
	default:
		logger.Warn("Message channel full for connection", "client_id", c.ID, "conn_id", connID, "message_type", msgType)
	}
}

// createMessageChannel 为连接创建消息通道 (与 v1 相同)
func (c *ClientConn) createMessageChannel(connID string) {
	c.msgChansMu.Lock()
	defer c.msgChansMu.Unlock()

	// 检查通道是否已经存在 (与 v1 相同)
	if _, exists := c.msgChans[connID]; exists {
		return
	}

	msgChan := make(chan map[string]interface{}, 100) // 缓冲100条消息
	c.msgChans[connID] = msgChan

	// 为此连接启动消息处理器 (与 v1 相同)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processConnectionMessages(connID, msgChan)
	}()
}

// processConnectionMessages 按顺序处理特定连接的消息 (与 v1 相同)
func (c *ClientConn) processConnectionMessages(_ string, msgChan chan map[string]interface{}) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case msg, ok := <-msgChan:
			if !ok {
				return
			}

			msgType, _ := msg["type"].(string)
			switch msgType {
			case common.MsgTypeConnectResponse:
				c.handleConnectResponseMessage(msg)
			case common.MsgTypeData:
				c.handleDataMessage(msg)
			case common.MsgTypeClose:
				c.handleCloseMessage(msg)
				return // 连接关闭，停止处理
			}
		}
	}
}

// handleDataMessage 处理来自客户端的数据消息 (与 v1 相同)
func (c *ClientConn) handleDataMessage(msg map[string]interface{}) {
	// 提取连接ID和数据 (与 v1 相同)
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in data message", "client_id", c.ID, "message_fields", gatewayGetMessageFields(msg))
		return
	}

	// WebSocket JSON消息将二进制数据编码为base64字符串 (与 v1 相同)
	dataStr, ok := msg["data"].(string)
	if !ok {
		logger.Error("Invalid data format in data message", "client_id", c.ID, "conn_id", connID, "data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// 将base64字符串解码回[]byte (与 v1 相同)
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		logger.Error("Failed to decode base64 data", "client_id", c.ID, "conn_id", connID, "data_length", len(dataStr), "err", err)
		return
	}

	// 只记录较大的传输以减少噪音 (与 v1 相同)
	if len(data) > 10000 {
		logger.Debug("Gateway received large data chunk", "client_id", c.ID, "conn_id", connID, "bytes", len(data))
	}

	// 安全获取连接 (与 v1 相同)
	c.ConnsMu.RLock()
	proxyConn, ok := c.Conns[connID]
	c.ConnsMu.RUnlock()
	if !ok {
		logger.Warn("Data message for unknown connection", "client_id", c.ID, "conn_id", connID, "data_bytes", len(data))
		return
	}

	// 将数据写入本地连接，带上下文感知 (与 v1 相同)
	deadline := time.Now().Add(30 * time.Second) // 增加到30秒以获得更好的代理性能
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := proxyConn.LocalConn.SetWriteDeadline(deadline); err != nil {
		logger.Debug("Failed to set write deadline", "client_id", c.ID, "conn_id", connID, "err", err)
	}

	n, err := proxyConn.LocalConn.Write(data)
	if err != nil {
		logger.Error("Failed to write data to local connection", "client_id", c.ID, "conn_id", connID, "data_bytes", len(data), "written_bytes", n, "err", err)
		c.closeConnection(connID)
		return
	}

	// 只记录较大的传输 (与 v1 相同)
	if n > 10000 {
		logger.Debug("Gateway successfully wrote large data chunk to local connection", "client_id", c.ID, "conn_id", connID, "bytes", n)
	}
}

// handleCloseMessage 处理来自客户端的关闭消息 (与 v1 相同)
func (c *ClientConn) handleCloseMessage(msg map[string]interface{}) {
	// 提取连接ID (与 v1 相同)
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in close message", "client_id", c.ID, "message_fields", gatewayGetMessageFields(msg))
		return
	}

	logger.Info("Received close message from client", "client_id", c.ID, "conn_id", connID)
	c.closeConnection(connID)
}

// closeConnection 关闭连接并清理资源 (与 v1 相同)
func (c *ClientConn) closeConnection(connID string) {
	// 原子地从客户端的连接映射中移除 (与 v1 相同)
	c.ConnsMu.Lock()
	proxyConn, exists := c.Conns[connID]
	if exists {
		delete(c.Conns, connID)
	}
	c.ConnsMu.Unlock()

	// 清理消息通道 (与 v1 相同)
	c.msgChansMu.Lock()
	if msgChan, exists := c.msgChans[connID]; exists {
		delete(c.msgChans, connID)
		close(msgChan)
	}
	c.msgChansMu.Unlock()

	// 只有在连接存在的情况下才进行清理 (与 v1 相同)
	if !exists {
		logger.Debug("Connection already removed", "conn_id", connID, "client_id", c.ID)
		return
	}

	// 发信号停止连接（非阻塞，幂等）(与 v1 相同)
	select {
	case <-proxyConn.Done:
		// 已经关闭，继续清理
	default:
		close(proxyConn.Done)
	}

	// 关闭本地连接 (与 v1 相同)
	logger.Debug("Closing local connection", "conn_id", proxyConn.ID)
	err := proxyConn.LocalConn.Close()
	if err != nil {
		logger.Debug("Connection close error (expected during shutdown)", "conn_id", proxyConn.ID, "err", err)
	}

	logger.Debug("Connection closed and cleaned up", "conn_id", proxyConn.ID, "client_id", c.ID)
}

// closeConnectionUnsafe 不安全地关闭连接（调用者必须持有锁）(与 v1 相同)
func (c *ClientConn) closeConnectionUnsafe(connID string) {
	proxyConn, exists := c.Conns[connID]
	if !exists {
		return
	}

	delete(c.Conns, connID)

	// 发信号停止连接
	select {
	case <-proxyConn.Done:
		// 已经关闭
	default:
		close(proxyConn.Done)
	}

	// 关闭实际连接
	proxyConn.once.Do(func() {
		if err := proxyConn.LocalConn.Close(); err != nil {
			logger.Debug("Connection close error during unsafe close", "conn_id", proxyConn.ID, "err", err)
		}
	})
}

// handleConnectResponseMessage 处理来自客户端的连接响应消息 (与 v1 相同逻辑)
func (c *ClientConn) handleConnectResponseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		logger.Error("Invalid connection ID in connect response", "client_id", c.ID, "message_fields", gatewayGetMessageFields(msg))
		return
	}

	success, ok := msg["success"].(bool)
	if !ok {
		logger.Error("Invalid success field in connect response", "client_id", c.ID, "conn_id", connID, "message_fields", gatewayGetMessageFields(msg))
		return
	}

	if success {
		logger.Debug("Client successfully connected to target", "client_id", c.ID, "conn_id", connID)
	} else {
		errorMsg, _ := msg["error"].(string)

		// 根据错误类型使用不同的日志级别和格式
		if strings.Contains(strings.ToLower(errorMsg), "forbidden") || strings.Contains(strings.ToLower(errorMsg), "denied") {
			logger.Error("❌ CONNECTION BLOCKED BY CLIENT SECURITY POLICY", "client_id", c.ID, "conn_id", connID, "error", errorMsg, "action", "Connection rejected by client due to security policy")
		} else if strings.Contains(strings.ToLower(errorMsg), "timeout") {
			logger.Warn("⏱️ CONNECTION TIMEOUT", "client_id", c.ID, "conn_id", connID, "error", errorMsg, "action", "Connection timed out")
		} else {
			logger.Error("❗ CONNECTION FAILED", "client_id", c.ID, "conn_id", connID, "error", errorMsg, "action", "Client failed to establish connection")
		}

		c.closeConnection(connID)
	}
}

// handleConnection 处理代理连接的数据传输 (与 v1 相同)
func (c *ClientConn) handleConnection(proxyConn *Conn) {
	logger.Debug("Starting connection handler", "client_id", c.ID, "conn_id", proxyConn.ID)

	// 增加缓冲区大小以获得更好的性能 (与 v1 相同)
	buffer := make([]byte, 32*1024) // 32KB缓冲区匹配网关
	totalBytes := 0
	readCount := 0
	startTime := time.Now()

	defer func() {
		elapsed := time.Since(startTime)
		logger.Debug("Connection handler finished", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes, "read_operations", readCount, "duration", elapsed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			logger.Debug("Connection handler stopping due to context cancellation", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes)
			return
		case <-proxyConn.Done:
			logger.Debug("Connection handler stopping - connection marked as done", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes)
			return
		default:
		}

		// 基于上下文设置读取截止时间 (与 v1 相同)
		deadline := time.Now().Add(30 * time.Second)
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := proxyConn.LocalConn.SetReadDeadline(deadline); err != nil {
			logger.Debug("Failed to set read deadline", "client_id", c.ID, "conn_id", proxyConn.ID, "error", err)
		}

		n, err := proxyConn.LocalConn.Read(buffer)
		readCount++

		if n > 0 {
			totalBytes += n
			// 只记录较大的传输以减少噪音 (与 v1 相同)
			if totalBytes%100000 == 0 || n > 10000 {
				logger.Debug("Gateway read data from local connection", "client_id", c.ID, "conn_id", proxyConn.ID, "bytes_this_read", n, "total_bytes", totalBytes, "read_count", readCount)
			}

			// 将二进制数据编码为base64字符串 (与 v1 相同)
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			// 🆕 使用传输层发送数据
			dataMsg := map[string]interface{}{
				"type": common.MsgTypeData,
				"id":   proxyConn.ID,
				"data": encodedData,
			}

			writeErr := c.Conn.WriteJSON(dataMsg)
			if writeErr != nil {
				logger.Error("Error writing data to client via transport", "client_id", c.ID, "conn_id", proxyConn.ID, "data_bytes", n, "total_bytes", totalBytes, "error", writeErr)
				c.closeConnection(proxyConn.ID)
				return
			}

			// 只记录较大的传输 (与 v1 相同)
			if n > 10000 {
				logger.Debug("Gateway successfully sent large data chunk to client", "client_id", c.ID, "conn_id", proxyConn.ID, "bytes", n, "total_bytes", totalBytes)
			}
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// 检查超时是否由于上下文取消 (与 v1 相同)
				select {
				case <-c.ctx.Done():
					logger.Debug("Connection handler stopping due to context during timeout", "client_id", c.ID, "conn_id", proxyConn.ID)
					return
				case <-proxyConn.Done:
					logger.Debug("Connection handler stopping - done channel during timeout", "client_id", c.ID, "conn_id", proxyConn.ID)
					return
				default:
					continue // 如果上下文仍然有效，则继续超时
				}
			}

			// 优雅地处理连接关闭错误 (与 v1 相同)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				logger.Debug("Local connection closed during read operation", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes, "read_count", readCount)
			} else if err != io.EOF {
				logger.Error("Error reading from local connection", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes, "read_count", readCount, "error", err)
			} else {
				logger.Debug("Local connection closed (EOF)", "client_id", c.ID, "conn_id", proxyConn.ID, "total_bytes", totalBytes, "read_count", readCount)
			}

			// 🆕 发送关闭消息到客户端
			closeMsg := map[string]interface{}{
				"type": common.MsgTypeClose,
				"id":   proxyConn.ID,
			}

			closeErr := c.Conn.WriteJSON(closeMsg)
			if closeErr != nil {
				logger.Debug("Error sending close message to client", "client_id", c.ID, "conn_id", proxyConn.ID, "error", closeErr)
			} else {
				logger.Debug("Sent close message to client", "client_id", c.ID, "conn_id", proxyConn.ID)
			}

			c.closeConnection(proxyConn.ID)
			return
		}
	}
}

// handlePortForwardRequest 处理端口转发请求 (从 v1 完整迁移)
func (c *ClientConn) handlePortForwardRequest(msg map[string]interface{}) {
	// Extract open ports from the message
	openPortsInterface, ok := msg["open_ports"]
	if !ok {
		logger.Error("No open_ports in port_forward_request", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Missing open_ports field")
		return
	}

	// Convert to []config.OpenPort
	openPortsSlice, ok := openPortsInterface.([]interface{})
	if !ok {
		logger.Error("Invalid open_ports format", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Invalid open_ports format")
		return
	}

	var openPorts []config.OpenPort
	for _, portInterface := range openPortsSlice {
		portMap, ok := portInterface.(map[string]interface{})
		if !ok {
			logger.Error("Invalid port configuration format", "client_id", c.ID)
			continue
		}

		// Extract port configuration
		remotePort, ok := portMap["remote_port"].(float64) // JSON numbers are float64
		if !ok {
			logger.Error("Invalid remote_port", "client_id", c.ID)
			continue
		}

		localPort, ok := portMap["local_port"].(float64)
		if !ok {
			logger.Error("Invalid local_port", "client_id", c.ID)
			continue
		}

		localHost, ok := portMap["local_host"].(string)
		if !ok {
			logger.Error("Invalid local_host", "client_id", c.ID)
			continue
		}

		protocol, ok := portMap["protocol"].(string)
		if !ok {
			protocol = "tcp" // Default to TCP
		}

		openPorts = append(openPorts, config.OpenPort{
			RemotePort: int(remotePort),
			LocalPort:  int(localPort),
			LocalHost:  localHost,
			Protocol:   protocol,
		})
	}

	if len(openPorts) == 0 {
		logger.Info("No valid ports to open", "client_id", c.ID)
		c.sendPortForwardResponse(true, "No ports to open")
		return
	}

	// Attempt to open the ports
	err := c.portForwardMgr.OpenPorts(c, openPorts)
	if err != nil {
		logger.Error("Failed to open ports", "client_id", c.ID, "err", err)
		c.sendPortForwardResponse(false, err.Error())
		return
	}

	logger.Info("Successfully opened ports", "client_id", c.ID, "port_count", len(openPorts))
	c.sendPortForwardResponse(true, "Ports opened successfully")
}

// sendPortForwardResponse 发送端口转发响应 (适配传输层)
func (c *ClientConn) sendPortForwardResponse(success bool, message string) {
	response := map[string]interface{}{
		"type":    "port_forward_response",
		"success": success,
		"message": message,
	}

	if err := c.Conn.WriteJSON(response); err != nil {
		logger.Error("Failed to send port forward response", "client_id", c.ID, "err", err)
	}
}

// gatewayGetMessageFields 获取安全的消息字段名称用于日志记录 (与 v1 相同)
func gatewayGetMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}
