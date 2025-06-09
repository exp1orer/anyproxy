package connection

import (
	"net"
	"sync"

	"github.com/buhuipao/anyproxy/pkg/logger"
)

// ConnectionManager 统一的连接管理器
type ConnectionManager struct {
	mu       sync.RWMutex
	conns    map[string]net.Conn
	msgChans map[string]chan map[string]interface{}
	clientID string // 用于日志
}

// NewConnectionManager 创建新的连接管理器
func NewConnectionManager(clientID string) *ConnectionManager {
	return &ConnectionManager{
		conns:    make(map[string]net.Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		clientID: clientID,
	}
}

// AddConnection 添加连接
func (cm *ConnectionManager) AddConnection(connID string, conn net.Conn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.conns[connID] = conn
	connectionCount := len(cm.conns)
	logger.Debug("Connection added to manager", "client_id", cm.clientID, "conn_id", connID, "total_connections", connectionCount)
}

// GetConnection 获取连接
func (cm *ConnectionManager) GetConnection(connID string) (net.Conn, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	conn, exists := cm.conns[connID]
	return conn, exists
}

// RemoveConnection 移除连接
func (cm *ConnectionManager) RemoveConnection(connID string) (net.Conn, bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	conn, exists := cm.conns[connID]
	if exists {
		delete(cm.conns, connID)
		logger.Debug("Connection removed from manager", "client_id", cm.clientID, "conn_id", connID, "remaining_connections", len(cm.conns))
	}
	return conn, exists
}

// GetConnectionCount 获取连接数量
func (cm *ConnectionManager) GetConnectionCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.conns)
}

// GetAllConnections 获取所有连接的副本
func (cm *ConnectionManager) GetAllConnections() map[string]net.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// 创建副本以避免并发问题
	connsCopy := make(map[string]net.Conn, len(cm.conns))
	for k, v := range cm.conns {
		connsCopy[k] = v
	}
	return connsCopy
}

// CloseAllConnections 关闭所有连接
func (cm *ConnectionManager) CloseAllConnections() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	connectionCount := len(cm.conns)
	if connectionCount == 0 {
		logger.Debug("No connections to close", "client_id", cm.clientID)
		return
	}

	logger.Debug("Closing all connections", "client_id", cm.clientID, "connection_count", connectionCount)

	closedCount := 0
	for connID, conn := range cm.conns {
		if err := conn.Close(); err != nil {
			logger.Debug("Error closing connection (expected during shutdown)", "client_id", cm.clientID, "conn_id", connID, "err", err)
		} else {
			closedCount++
		}
		delete(cm.conns, connID)
	}

	logger.Debug("All connections closed", "client_id", cm.clientID, "connections_closed", closedCount)
}

// CreateMessageChannel 创建消息通道
func (cm *ConnectionManager) CreateMessageChannel(connID string, bufferSize int) chan map[string]interface{} {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// 检查通道是否已经存在
	if msgChan, exists := cm.msgChans[connID]; exists {
		logger.Debug("Message channel already exists", "client_id", cm.clientID, "conn_id", connID)
		return msgChan
	}

	msgChan := make(chan map[string]interface{}, bufferSize)
	cm.msgChans[connID] = msgChan

	logger.Debug("Created message channel", "client_id", cm.clientID, "conn_id", connID, "buffer_size", bufferSize)
	return msgChan
}

// GetMessageChannel 获取消息通道
func (cm *ConnectionManager) GetMessageChannel(connID string) (chan map[string]interface{}, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	msgChan, exists := cm.msgChans[connID]
	return msgChan, exists
}

// RemoveMessageChannel 移除并关闭消息通道
func (cm *ConnectionManager) RemoveMessageChannel(connID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if msgChan, exists := cm.msgChans[connID]; exists {
		delete(cm.msgChans, connID)
		close(msgChan)
		logger.Debug("Message channel removed and closed", "client_id", cm.clientID, "conn_id", connID)
	}
}

// CloseAllMessageChannels 关闭所有消息通道
func (cm *ConnectionManager) CloseAllMessageChannels() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	channelCount := len(cm.msgChans)
	if channelCount == 0 {
		return
	}

	for connID, msgChan := range cm.msgChans {
		close(msgChan)
		delete(cm.msgChans, connID)
	}

	logger.Debug("All message channels closed", "client_id", cm.clientID, "channel_count", channelCount)
}

// CleanupConnection 清理连接和相关资源
func (cm *ConnectionManager) CleanupConnection(connID string) {
	// 移除并关闭连接
	if conn, exists := cm.RemoveConnection(connID); exists && conn != nil {
		if err := conn.Close(); err != nil {
			logger.Debug("Error closing connection (expected during cleanup)", "client_id", cm.clientID, "conn_id", connID, "err", err)
		}
	}

	// 移除消息通道
	cm.RemoveMessageChannel(connID)

	logger.Debug("Connection cleaned up", "client_id", cm.clientID, "conn_id", connID)
}

// GetMessageChannelCount 获取消息通道数
func (cm *ConnectionManager) GetMessageChannelCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return len(cm.msgChans)
}
