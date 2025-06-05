package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/proxy_protocols"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"

	// Import gRPC transport for side effects (registration)
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/grpc"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/quic"
	_ "github.com/buhuipao/anyproxy/pkg/proxy_v2/transport/websocket"
)

// Gateway represents the proxy gateway server (基于 v1 设计)
type Gateway struct {
	config         *config.GatewayConfig
	transport      transport.Transport   // 🆕 唯一的新增抽象
	proxies        []common.GatewayProxy // 保持 v1 接口
	clientsMu      sync.RWMutex
	clients        map[string]*ClientConn
	groups         map[string]map[string]struct{}
	portForwardMgr *PortForwardManager
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
}

// NewGateway creates a new proxy gateway (与 v1 相似)
func NewGateway(cfg *config.Config, transportType string) (*Gateway, error) {
	logger.Info("Creating new gateway", "listen_addr", cfg.Gateway.ListenAddr, "http_proxy_enabled", cfg.Proxy.HTTP.ListenAddr != "", "socks5_proxy_enabled", cfg.Proxy.SOCKS5.ListenAddr != "", "transport_type", transportType, "auth_enabled", cfg.Gateway.AuthUsername != "")

	ctx, cancel := context.WithCancel(context.Background())

	// 🆕 创建传输层 - 唯一的新增逻辑
	transportImpl := transport.CreateTransport(transportType, &transport.AuthConfig{
		Username: cfg.Gateway.AuthUsername,
		Password: cfg.Gateway.AuthPassword,
	})
	if transportImpl == nil {
		cancel()
		return nil, fmt.Errorf("failed to create transport: %s", transportType)
	}

	gateway := &Gateway{
		config:         &cfg.Gateway,
		transport:      transportImpl,
		clients:        make(map[string]*ClientConn),
		groups:         make(map[string]map[string]struct{}),
		portForwardMgr: NewPortForwardManager(),
		ctx:            ctx,
		cancel:         cancel,
	}

	// 初始化默认组 (与 v1 相同)
	gateway.groups[""] = make(map[string]struct{})
	logger.Debug("Initialized default group for gateway")

	// 创建自定义拨号函数 (与 v1 相同)
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 从上下文提取用户信息 (与 v1 相同)
		var groupID string
		if userCtx, ok := ctx.Value("user").(*common.UserContext); ok {
			logger.Debug("Dial function received user context", "group_id", userCtx.GroupID, "network", network, "address", addr)
			groupID = userCtx.GroupID
		} else {
			logger.Debug("Dial function using default group", "network", network, "address", addr)
		}

		// 获取客户端 (与 v1 相同)
		client, err := gateway.getClientByGroup(groupID)
		if err != nil {
			logger.Error("Failed to get client by group for dial", "group_id", groupID, "network", network, "address", addr, "err", err)
			return nil, err
		}
		logger.Debug("Successfully selected client for dial", "client_id", client.ID, "group_id", groupID, "network", network, "address", addr)
		return client.dialNetwork(network, addr)
	}

	// 创建代理实例 (与 v1 相同的逻辑)
	var proxies []common.GatewayProxy

	// 创建 HTTP 代理 (与 v1 相同)
	if cfg.Proxy.HTTP.ListenAddr != "" {
		logger.Info("Configuring HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
		httpProxy, err := proxy_protocols.NewHTTPProxyWithAuth(&cfg.Proxy.HTTP, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			cancel()
			logger.Error("Failed to create HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr, "err", err)
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		proxies = append(proxies, httpProxy)
		logger.Info("HTTP proxy configured successfully", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
	}

	// 创建 SOCKS5 代理 (与 v1 相同)
	if cfg.Proxy.SOCKS5.ListenAddr != "" {
		logger.Info("Configuring SOCKS5 proxy", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
		socks5Proxy, err := proxy_protocols.NewSOCKS5ProxyWithAuth(&cfg.Proxy.SOCKS5, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			cancel()
			logger.Error("Failed to create SOCKS5 proxy", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr, "err", err)
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %v", err)
		}
		proxies = append(proxies, socks5Proxy)
		logger.Info("SOCKS5 proxy configured successfully", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
	}

	// 确保至少配置一个代理 (与 v1 相同)
	if len(proxies) == 0 {
		cancel()
		logger.Error("No proxy configured - at least one proxy type must be enabled", "http_addr", cfg.Proxy.HTTP.ListenAddr, "socks5_addr", cfg.Proxy.SOCKS5.ListenAddr)
		return nil, fmt.Errorf("no proxy configured: please configure at least one of HTTP or SOCKS5 proxy")
	}

	gateway.proxies = proxies
	logger.Info("Gateway created successfully", "proxy_count", len(proxies), "listen_addr", cfg.Gateway.ListenAddr)

	return gateway, nil
}

// extractGroupFromUsername 提取组ID (与 v1 相同)
func (g *Gateway) extractGroupFromUsername(username string) string {
	logger.Info("extractGroupFromUsername", "username", username)
	parts := strings.Split(username, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}

// Start starts the gateway (与 v1 相似，但使用传输层抽象)
func (g *Gateway) Start() error {
	logger.Info("Starting gateway server", "listen_addr", g.config.ListenAddr, "proxy_count", len(g.proxies))

	// 🆕 检查并配置 TLS (从 v1 迁移)
	var tlsConfig *tls.Config
	if g.config.TLSCert != "" && g.config.TLSKey != "" {
		logger.Debug("Loading TLS certificates", "cert_file", g.config.TLSCert, "key_file", g.config.TLSKey)

		// 加载 TLS 证书和密钥 (与 v1 相同)
		cert, err := tls.LoadX509KeyPair(g.config.TLSCert, g.config.TLSKey)
		if err != nil {
			logger.Error("Failed to load TLS certificate", "cert_file", g.config.TLSCert, "key_file", g.config.TLSKey, "err", err)
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}
		logger.Debug("TLS certificates loaded successfully")

		// 配置 TLS (与 v1 相同)
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		logger.Debug("TLS configuration created", "min_version", "TLS 1.2")
	}

	// 🆕 启动传输层服务器 - 支持 TLS (从 v1 迁移)
	logger.Info("Starting transport server for client connections")
	if tlsConfig != nil {
		logger.Info("Starting secure transport server (HTTPS/WSS)")
		if err := g.transport.ListenAndServeWithTLS(g.config.ListenAddr, g.handleConnection, tlsConfig); err != nil {
			logger.Error("Failed to start secure transport server", "listen_addr", g.config.ListenAddr, "err", err)
			return err
		}
		logger.Info("Secure transport server started successfully", "listen_addr", g.config.ListenAddr)
	} else {
		logger.Info("Starting transport server (HTTP/WS)")
		if err := g.transport.ListenAndServe(g.config.ListenAddr, g.handleConnection); err != nil {
			logger.Error("Failed to start transport server", "listen_addr", g.config.ListenAddr, "err", err)
			return err
		}
		logger.Info("Transport server started successfully", "listen_addr", g.config.ListenAddr)
	}

	// 启动所有代理服务器 (与 v1 相同)
	logger.Info("Starting proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		logger.Debug("Starting proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Start(); err != nil {
			logger.Error("Failed to start proxy server", "index", i, "type", fmt.Sprintf("%T", proxy), "err", err)
			// 停止已启动的代理
			logger.Warn("Stopping previously started proxies due to failure", "stopping_count", i)
			for j := 0; j < i; j++ {
				if stopErr := g.proxies[j].Stop(); stopErr != nil {
					logger.Error("Failed to stop proxy during cleanup", "index", j, "err", stopErr)
				}
			}
			return fmt.Errorf("failed to start proxy %d: %v", i, err)
		}
		logger.Debug("Proxy server started successfully", "index", i, "type", fmt.Sprintf("%T", proxy))
	}

	logger.Info("Gateway started successfully", "transport_addr", g.config.ListenAddr, "proxy_count", len(g.proxies))

	return nil
}

// Stop stops the gateway gracefully (与 v1 相同)
func (g *Gateway) Stop() error {
	logger.Info("Initiating graceful gateway shutdown...")

	// Step 1: 取消上下文 (与 v1 相同)
	logger.Debug("Signaling all goroutines to stop")
	g.cancel()

	// Step 2: 🆕 停止传输层服务器
	logger.Info("Shutting down transport server")
	if err := g.transport.Close(); err != nil {
		logger.Error("Error shutting down transport server", "err", err)
	} else {
		logger.Info("Transport server shutdown completed")
	}

	// Step 3: 停止所有代理服务器 (与 v1 相同)
	logger.Info("Stopping proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		logger.Debug("Stopping proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Stop(); err != nil {
			logger.Error("Error stopping proxy server", "index", i, "type", fmt.Sprintf("%T", proxy), "err", err)
		} else {
			logger.Debug("Proxy server stopped successfully", "index", i)
		}
	}
	logger.Info("All proxy servers stopped")

	// Step 4: 停止端口转发管理器 (与 v1 相同)
	logger.Debug("Stopping port forwarding manager")
	g.portForwardMgr.Stop()
	logger.Debug("Port forwarding manager stopped")

	// Step 5: 等待客户端处理完成 (与 v1 相同)
	logger.Info("Waiting for clients to finish processing...")
	select {
	case <-g.ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}

	// Step 6: 停止所有客户端连接 (与 v1 相同)
	g.clientsMu.RLock()
	clientCount := len(g.clients)
	g.clientsMu.RUnlock()

	if clientCount > 0 {
		logger.Info("Stopping client connections", "client_count", clientCount)
		g.clientsMu.RLock()
		for clientID, client := range g.clients {
			logger.Debug("Stopping client connection", "client_id", clientID)
			client.Stop()
		}
		g.clientsMu.RUnlock()
		logger.Info("All client connections stopped")
	} else {
		logger.Debug("No active client connections to stop")
	}

	// Step 7: 等待所有goroutine完成 (与 v1 相同)
	logger.Debug("Waiting for all goroutines to finish...")
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All gateway goroutines finished gracefully")
	case <-time.After(8 * time.Second):
		logger.Warn("Timeout waiting for gateway goroutines to finish")
	}

	logger.Info("Gateway shutdown completed", "final_client_count", clientCount)

	return nil
}

// handleConnection 处理传输层连接 (🆕 适配传输层抽象，但逻辑与 v1 相同)
func (g *Gateway) handleConnection(conn transport.Connection) {
	// 从连接中提取客户端信息（现在是接口的正式部分）
	clientID := conn.GetClientID()
	groupID := conn.GetGroupID()

	logger.Info("Client connected", "client_id", clientID, "group_id", groupID, "remote_addr", conn.RemoteAddr())

	// 创建客户端连接上下文
	ctx, cancel := context.WithCancel(g.ctx)

	// 创建客户端连接 (类似 v1 的 ClientConn)
	client := &ClientConn{
		ID:             clientID,
		GroupID:        groupID,
		Conn:           conn, // 🆕 使用传输层连接
		Conns:          make(map[string]*Conn),
		msgChans:       make(map[string]chan map[string]interface{}),
		ctx:            ctx,
		cancel:         cancel,
		portForwardMgr: g.portForwardMgr,
	}

	g.addClient(client)

	// 🚨 修复：直接处理消息，阻塞直到连接关闭
	// 这确保BiStream方法不会过早返回
	defer func() {
		client.Stop()
		g.removeClient(client.ID)
		logger.Info("Client disconnected and cleaned up", "client_id", client.ID, "group_id", client.GroupID)
	}()

	// 处理客户端消息 - 这会阻塞直到连接关闭
	client.handleMessage()
}

// addClient adds a client to the gateway (与 v1 相同)
func (g *Gateway) addClient(client *ClientConn) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	// 检查是否已存在客户端
	if existingClient, exists := g.clients[client.ID]; exists {
		logger.Warn("Replacing existing client connection", "client_id", client.ID, "old_group_id", existingClient.GroupID, "new_group_id", client.GroupID)
		existingClient.Stop()
	}

	g.clients[client.ID] = client
	if _, ok := g.groups[client.GroupID]; !ok {
		g.groups[client.GroupID] = make(map[string]struct{})
		logger.Debug("Created new group", "group_id", client.GroupID)
	}
	g.groups[client.GroupID][client.ID] = struct{}{}

	groupSize := len(g.groups[client.GroupID])
	totalClients := len(g.clients)
	logger.Debug("Client added successfully", "client_id", client.ID, "group_id", client.GroupID, "group_size", groupSize, "total_clients", totalClients)
}

// removeClient removes a client from the gateway (与 v1 相同)
func (g *Gateway) removeClient(clientID string) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	client, exists := g.clients[clientID]
	if !exists {
		logger.Debug("Attempted to remove non-existent client", "client_id", clientID)
		return
	}

	// 🚨 修复：添加缺失的端口清理调用（与 v1 保持一致）
	logger.Debug("Closing port forwarding for client", "client_id", clientID)
	g.portForwardMgr.CloseClientPorts(clientID)

	delete(g.clients, clientID)
	delete(g.groups[client.GroupID], clientID)

	if len(g.groups[client.GroupID]) == 0 && client.GroupID != "" {
		delete(g.groups, client.GroupID)
		logger.Debug("Removed empty group", "group_id", client.GroupID)
	}

	remainingClients := len(g.clients)
	logger.Info("Client removed successfully", "client_id", clientID, "group_id", client.GroupID, "remaining_clients", remainingClients)
}

// getClientByGroup 根据组获取客户端 (与 v1 相同)
func (g *Gateway) getClientByGroup(groupID string) (*ClientConn, error) {
	g.clientsMu.RLock()
	defer g.clientsMu.RUnlock()

	clients, exists := g.groups[groupID]
	if !exists || len(clients) == 0 {
		return nil, fmt.Errorf("no clients available in group: %s", groupID)
	}

	// 简单的轮询选择
	for clientID := range clients {
		if client, exists := g.clients[clientID]; exists {
			return client, nil
		}
	}

	return nil, fmt.Errorf("no healthy clients available in group: %s", groupID)
}
