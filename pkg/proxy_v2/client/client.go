// Package client provides v2 client implementation for AnyProxy.
package client

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sync"
	"time"

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
	config           *config.ClientConfig
	transport        transport.Transport  // 🆕 唯一的新增抽象
	conn             transport.Connection // 🆕 传输层连接
	actualID         string               // 🆕 实际使用的客户端 ID (带随机后缀)
	replicaIdx       int                  // 修复：副本索引，用于生成唯一 ID
	connsMu          sync.RWMutex
	conns            map[string]net.Conn
	msgChans         map[string]chan map[string]interface{} // 与 v1 相同的消息通道
	msgChansMu       sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	forbiddenHostsRe []*regexp.Regexp // 修复：预编译的禁止主机正则表达式
	allowedHostsRe   []*regexp.Regexp // 修复：预编译的允许主机正则表达式
}

// NewClient creates a new proxy client (与 v1 相似，但支持传输层选择)
func NewClient(cfg *config.ClientConfig, transportType string, replicaIdx int) (*Client, error) {
	logger.Info("Creating new client", "client_id", cfg.ClientID, "replica_idx", replicaIdx, "gateway_addr", cfg.GatewayAddr, "group_id", cfg.GroupID, "transport_type", transportType, "allowed_hosts_count", len(cfg.AllowedHosts), "forbidden_hosts_count", len(cfg.ForbiddenHosts), "open_ports_count", len(cfg.OpenPorts), "auth_enabled", cfg.AuthUsername != "")

	// 记录安全策略详细信息
	if len(cfg.ForbiddenHosts) > 0 {
		logger.Info("Security policy: forbidden hosts configured", "client_id", cfg.ClientID, "forbidden_hosts", cfg.ForbiddenHosts, "count", len(cfg.ForbiddenHosts))
	}

	if len(cfg.AllowedHosts) > 0 {
		logger.Info("Security policy: allowed hosts configured", "client_id", cfg.ClientID, "allowed_hosts", cfg.AllowedHosts, "count", len(cfg.AllowedHosts))
	} else {
		logger.Warn("Security policy: no allowed hosts configured, all non-forbidden hosts will be allowed", "client_id", cfg.ClientID)
	}

	// 记录端口转发配置
	if len(cfg.OpenPorts) > 0 {
		logger.Info("Port forwarding configured", "client_id", cfg.ClientID, "port_count", len(cfg.OpenPorts))
		for i, port := range cfg.OpenPorts {
			logger.Debug("  Port forwarding entry", "index", i, "remote_port", port.RemotePort, "local_target", fmt.Sprintf("%s:%d", port.LocalHost, port.LocalPort), "protocol", port.Protocol)
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

	// 生成唯一的客户端ID (与 v1 相同)

	client := &Client{
		config:     cfg,
		transport:  transportImpl,
		replicaIdx: replicaIdx, // 修复：设置副本索引
		conns:      make(map[string]net.Conn),
		msgChans:   make(map[string]chan map[string]interface{}),
		ctx:        ctx,
		cancel:     cancel,
	}

	// 修复：预编译正则表达式以提高性能
	if err := client.compileHostPatterns(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to compile host patterns: %v", err)
	}

	logger.Debug("Client initialization completed", "client_id", cfg.ClientID, "transport_type", transportType)

	return client, nil
}

// Start starts the client with automatic reconnection (与 v1 相同)
func (c *Client) Start() error {
	logger.Info("Starting proxy client", "client_id", c.getClientID(), "gateway_addr", c.config.GatewayAddr, "group_id", c.config.GroupID)

	// 启动性能指标报告器（每30秒报告一次）
	common.StartMetricsReporter(30 * time.Second)

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
	case <-time.After(common.DefaultShutdownTimeout):
		logger.Warn("Timeout waiting for client goroutines to finish", "client_id", c.getClientID())
	}

	// 停止指标报告器
	common.StopMetricsReporter()

	logger.Info("Client shutdown completed", "client_id", c.getClientID(), "connections_closed", connectionCount)

	return nil
}
