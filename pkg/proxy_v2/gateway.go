package proxy_v2

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/proxy_protocols"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"

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
	slog.Info("Creating new gateway",
		"listen_addr", cfg.Gateway.ListenAddr,
		"http_proxy_enabled", cfg.Proxy.HTTP.ListenAddr != "",
		"socks5_proxy_enabled", cfg.Proxy.SOCKS5.ListenAddr != "",
		"transport_type", transportType,
		"auth_enabled", cfg.Gateway.AuthUsername != "")

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
	slog.Debug("Initialized default group for gateway")

	// 创建自定义拨号函数 (与 v1 相同)
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// 从上下文提取用户信息 (与 v1 相同)
		var groupID string
		if userCtx, ok := ctx.Value("user").(*common.UserContext); ok {
			slog.Debug("Dial function received user context",
				"group_id", userCtx.GroupID,
				"network", network,
				"address", addr)
			groupID = userCtx.GroupID
		} else {
			slog.Debug("Dial function using default group",
				"network", network,
				"address", addr)
		}

		// 获取客户端 (与 v1 相同)
		client, err := gateway.getClientByGroup(groupID)
		if err != nil {
			slog.Error("Failed to get client by group for dial",
				"group_id", groupID,
				"network", network,
				"address", addr,
				"error", err)
			return nil, err
		}
		slog.Debug("Successfully selected client for dial",
			"client_id", client.ID,
			"group_id", groupID,
			"network", network,
			"address", addr)
		return client.dialNetwork(network, addr)
	}

	// 创建代理实例 (与 v1 相同的逻辑)
	var proxies []common.GatewayProxy

	// 创建 HTTP 代理 (与 v1 相同)
	if cfg.Proxy.HTTP.ListenAddr != "" {
		slog.Info("Configuring HTTP proxy", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
		httpProxy, err := proxy_protocols.NewHTTPProxyWithAuth(&cfg.Proxy.HTTP, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			cancel()
			slog.Error("Failed to create HTTP proxy",
				"listen_addr", cfg.Proxy.HTTP.ListenAddr,
				"error", err)
			return nil, fmt.Errorf("failed to create HTTP proxy: %v", err)
		}
		proxies = append(proxies, httpProxy)
		slog.Info("HTTP proxy configured successfully", "listen_addr", cfg.Proxy.HTTP.ListenAddr)
	}

	// 创建 SOCKS5 代理 (与 v1 相同)
	if cfg.Proxy.SOCKS5.ListenAddr != "" {
		slog.Info("Configuring SOCKS5 proxy", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
		socks5Proxy, err := proxy_protocols.NewSOCKS5ProxyWithAuth(&cfg.Proxy.SOCKS5, dialFn, gateway.extractGroupFromUsername)
		if err != nil {
			cancel()
			slog.Error("Failed to create SOCKS5 proxy",
				"listen_addr", cfg.Proxy.SOCKS5.ListenAddr,
				"error", err)
			return nil, fmt.Errorf("failed to create SOCKS5 proxy: %v", err)
		}
		proxies = append(proxies, socks5Proxy)
		slog.Info("SOCKS5 proxy configured successfully", "listen_addr", cfg.Proxy.SOCKS5.ListenAddr)
	}

	// 确保至少配置一个代理 (与 v1 相同)
	if len(proxies) == 0 {
		cancel()
		slog.Error("No proxy configured - at least one proxy type must be enabled",
			"http_addr", cfg.Proxy.HTTP.ListenAddr,
			"socks5_addr", cfg.Proxy.SOCKS5.ListenAddr)
		return nil, fmt.Errorf("no proxy configured: please configure at least one of HTTP or SOCKS5 proxy")
	}

	gateway.proxies = proxies
	slog.Info("Gateway created successfully",
		"proxy_count", len(proxies),
		"listen_addr", cfg.Gateway.ListenAddr)

	return gateway, nil
}

// extractGroupFromUsername 提取组ID (与 v1 相同)
func (g *Gateway) extractGroupFromUsername(username string) string {
	slog.Info("extractGroupFromUsername", "username", username)
	parts := strings.Split(username, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[1:], ".")
	}
	return ""
}

// Start starts the gateway (与 v1 相似，但使用传输层抽象)
func (g *Gateway) Start() error {
	slog.Info("Starting gateway server",
		"listen_addr", g.config.ListenAddr,
		"proxy_count", len(g.proxies))

	startTime := time.Now()

	// 🆕 检查并配置 TLS (从 v1 迁移)
	var tlsConfig *tls.Config
	if g.config.TLSCert != "" && g.config.TLSKey != "" {
		slog.Debug("Loading TLS certificates",
			"cert_file", g.config.TLSCert,
			"key_file", g.config.TLSKey)

		// 加载 TLS 证书和密钥 (与 v1 相同)
		cert, err := tls.LoadX509KeyPair(g.config.TLSCert, g.config.TLSKey)
		if err != nil {
			slog.Error("Failed to load TLS certificate",
				"cert_file", g.config.TLSCert,
				"key_file", g.config.TLSKey,
				"error", err)
			return fmt.Errorf("failed to load TLS certificate: %v", err)
		}
		slog.Debug("TLS certificates loaded successfully")

		// 配置 TLS (与 v1 相同)
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		slog.Debug("TLS configuration created", "min_version", "TLS 1.2")
	}

	// 🆕 启动传输层服务器 - 支持 TLS (从 v1 迁移)
	slog.Info("Starting transport server for client connections")
	if tlsConfig != nil {
		slog.Info("Starting secure transport server (HTTPS/WSS)")
		if err := g.transport.ListenAndServeWithTLS(g.config.ListenAddr, g.handleConnection, tlsConfig); err != nil {
			slog.Error("Failed to start secure transport server",
				"listen_addr", g.config.ListenAddr,
				"error", err)
			return err
		}
		slog.Info("Secure transport server started successfully", "listen_addr", g.config.ListenAddr)
	} else {
		slog.Info("Starting transport server (HTTP/WS)")
		if err := g.transport.ListenAndServe(g.config.ListenAddr, g.handleConnection); err != nil {
			slog.Error("Failed to start transport server",
				"listen_addr", g.config.ListenAddr,
				"error", err)
			return err
		}
		slog.Info("Transport server started successfully", "listen_addr", g.config.ListenAddr)
	}

	// 启动所有代理服务器 (与 v1 相同)
	slog.Info("Starting proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		slog.Debug("Starting proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Start(); err != nil {
			slog.Error("Failed to start proxy server",
				"index", i,
				"type", fmt.Sprintf("%T", proxy),
				"error", err)
			// 停止已启动的代理
			slog.Warn("Stopping previously started proxies due to failure", "stopping_count", i)
			for j := 0; j < i; j++ {
				if stopErr := g.proxies[j].Stop(); stopErr != nil {
					slog.Error("Failed to stop proxy during cleanup", "index", j, "error", stopErr)
				}
			}
			return fmt.Errorf("failed to start proxy %d: %v", i, err)
		}
		slog.Debug("Proxy server started successfully", "index", i, "type", fmt.Sprintf("%T", proxy))
	}

	elapsed := time.Since(startTime)
	slog.Info("Gateway started successfully",
		"startup_duration", elapsed,
		"transport_addr", g.config.ListenAddr,
		"proxy_count", len(g.proxies))

	return nil
}

// Stop stops the gateway gracefully (与 v1 相同)
func (g *Gateway) Stop() error {
	slog.Info("Initiating graceful gateway shutdown...")
	stopTime := time.Now()

	// Step 1: 取消上下文 (与 v1 相同)
	slog.Debug("Signaling all goroutines to stop")
	g.cancel()

	// Step 2: 🆕 停止传输层服务器
	slog.Info("Shutting down transport server")
	if err := g.transport.Close(); err != nil {
		slog.Error("Error shutting down transport server", "error", err)
	} else {
		slog.Info("Transport server shutdown completed")
	}

	// Step 3: 停止所有代理服务器 (与 v1 相同)
	slog.Info("Stopping proxy servers", "count", len(g.proxies))
	for i, proxy := range g.proxies {
		slog.Debug("Stopping proxy server", "index", i, "type", fmt.Sprintf("%T", proxy))
		if err := proxy.Stop(); err != nil {
			slog.Error("Error stopping proxy server",
				"index", i,
				"type", fmt.Sprintf("%T", proxy),
				"error", err)
		} else {
			slog.Debug("Proxy server stopped successfully", "index", i)
		}
	}
	slog.Info("All proxy servers stopped")

	// Step 4: 停止端口转发管理器 (与 v1 相同)
	slog.Debug("Stopping port forwarding manager")
	g.portForwardMgr.Stop()
	slog.Debug("Port forwarding manager stopped")

	// Step 5: 等待客户端处理完成 (与 v1 相同)
	slog.Info("Waiting for clients to finish processing...")
	select {
	case <-g.ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}

	// Step 6: 停止所有客户端连接 (与 v1 相同)
	g.clientsMu.RLock()
	clientCount := len(g.clients)
	g.clientsMu.RUnlock()

	if clientCount > 0 {
		slog.Info("Stopping client connections", "client_count", clientCount)
		g.clientsMu.RLock()
		for clientID, client := range g.clients {
			slog.Debug("Stopping client connection", "client_id", clientID)
			client.Stop()
		}
		g.clientsMu.RUnlock()
		slog.Info("All client connections stopped")
	} else {
		slog.Debug("No active client connections to stop")
	}

	// Step 7: 等待所有goroutine完成 (与 v1 相同)
	slog.Debug("Waiting for all goroutines to finish...")
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("All gateway goroutines finished gracefully")
	case <-time.After(8 * time.Second):
		slog.Warn("Timeout waiting for gateway goroutines to finish")
	}

	elapsed := time.Since(stopTime)
	slog.Info("Gateway shutdown completed",
		"shutdown_duration", elapsed,
		"final_client_count", clientCount)

	return nil
}

// handleConnection 处理传输层连接 (🆕 适配传输层抽象，但逻辑与 v1 相同)
func (g *Gateway) handleConnection(conn transport.Connection) {
	// 从连接中提取客户端信息（现在是接口的正式部分）
	clientID := conn.GetClientID()
	groupID := conn.GetGroupID()

	slog.Info("Client connected",
		"client_id", clientID,
		"group_id", groupID,
		"remote_addr", conn.RemoteAddr())

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
		slog.Info("Client disconnected and cleaned up",
			"client_id", client.ID,
			"group_id", client.GroupID)
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
		slog.Warn("Replacing existing client connection",
			"client_id", client.ID,
			"old_group_id", existingClient.GroupID,
			"new_group_id", client.GroupID)
		existingClient.Stop()
	}

	g.clients[client.ID] = client
	if _, ok := g.groups[client.GroupID]; !ok {
		g.groups[client.GroupID] = make(map[string]struct{})
		slog.Debug("Created new group", "group_id", client.GroupID)
	}
	g.groups[client.GroupID][client.ID] = struct{}{}

	groupSize := len(g.groups[client.GroupID])
	totalClients := len(g.clients)
	slog.Debug("Client added successfully",
		"client_id", client.ID,
		"group_id", client.GroupID,
		"group_size", groupSize,
		"total_clients", totalClients)
}

// removeClient removes a client from the gateway (与 v1 相同)
func (g *Gateway) removeClient(clientID string) {
	g.clientsMu.Lock()
	defer g.clientsMu.Unlock()

	client, exists := g.clients[clientID]
	if !exists {
		slog.Debug("Attempted to remove non-existent client", "client_id", clientID)
		return
	}

	// 🚨 修复：添加缺失的端口清理调用（与 v1 保持一致）
	slog.Debug("Closing port forwarding for client", "client_id", clientID)
	g.portForwardMgr.CloseClientPorts(clientID)

	delete(g.clients, clientID)
	delete(g.groups[client.GroupID], clientID)

	if len(g.groups[client.GroupID]) == 0 && client.GroupID != "" {
		delete(g.groups, client.GroupID)
		slog.Debug("Removed empty group", "group_id", client.GroupID)
	}

	remainingClients := len(g.clients)
	slog.Info("Client removed successfully",
		"client_id", clientID,
		"group_id", client.GroupID,
		"remaining_clients", remainingClients)
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

// getRandomClient 返回一个随机可用的客户端 (从 v1 完整迁移)
func (g *Gateway) getRandomClient() (*ClientConn, error) {
	g.clientsMu.RLock()
	defer g.clientsMu.RUnlock()

	if len(g.clients) == 0 {
		return nil, fmt.Errorf("no clients available")
	}

	// 简单的选择第一个可用客户端（实际实现可以更复杂）
	for _, client := range g.clients {
		return client, nil
	}

	return nil, fmt.Errorf("no healthy clients available")
}

/* -------------------------------------------------------------------------------------------- */
/* -------------------------------- Port Forward ---------------------------------------------- */
/* -------------------------------------------------------------------------------------------- */

// PortForwardManager 端口转发管理器 (从 v1 完整迁移)
type PortForwardManager struct {
	// Map of client ID to their forwarded ports
	clientPorts map[string]map[int]*PortListener
	// Map of port to client ID (for conflict detection)
	portOwners map[int]string
	mutex      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// PortListener 端口监听器 (从 v1 完整迁移)
type PortListener struct {
	Port       int
	Protocol   string
	ClientID   string
	LocalHost  string
	LocalPort  int
	Listener   net.Listener   // For TCP
	PacketConn net.PacketConn // For UDP
	Client     *ClientConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func NewPortForwardManager() *PortForwardManager {
	slog.Info("Creating new port forwarding manager")

	ctx, cancel := context.WithCancel(context.Background())
	manager := &PortForwardManager{
		clientPorts: make(map[string]map[int]*PortListener),
		portOwners:  make(map[int]string),
		ctx:         ctx,
		cancel:      cancel,
	}

	slog.Debug("Port forwarding manager initialized successfully",
		"client_ports_capacity", len(manager.clientPorts),
		"port_owners_capacity", len(manager.portOwners))

	return manager
}

// OpenPorts 为客户端开启端口转发 (从 v1 完整迁移)
func (pm *PortForwardManager) OpenPorts(client *ClientConn, openPorts []config.OpenPort) error {
	openStart := time.Now()

	if client == nil {
		slog.Error("Port opening failed: client cannot be nil")
		return fmt.Errorf("client cannot be nil")
	}

	slog.Info("Opening ports for client",
		"client_id", client.ID,
		"port_count", len(openPorts))

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if manager is shutting down
	select {
	case <-pm.ctx.Done():
		slog.Warn("Port opening rejected: manager is shutting down",
			"client_id", client.ID)
		return fmt.Errorf("port forward manager is shutting down")
	default:
	}

	// Initialize client ports map if it doesn't exist
	if pm.clientPorts[client.ID] == nil {
		pm.clientPorts[client.ID] = make(map[int]*PortListener)
		slog.Debug("Initialized port map for new client", "client_id", client.ID)
	}

	var errors []error
	successfulPorts := []*PortListener{}
	conflictPorts := []int{}
	duplicatePorts := []int{}

	// Log details of each port request
	for i, openPort := range openPorts {
		slog.Debug("Processing port request",
			"client_id", client.ID,
			"port_index", i,
			"remote_port", openPort.RemotePort,
			"local_host", openPort.LocalHost,
			"local_port", openPort.LocalPort,
			"protocol", openPort.Protocol)
	}

	for _, openPort := range openPorts {
		// Check if port is already in use
		if existingClientID, exists := pm.portOwners[openPort.RemotePort]; exists {
			if existingClientID != client.ID {
				conflictPorts = append(conflictPorts, openPort.RemotePort)
				slog.Warn("Port conflict detected",
					"client_id", client.ID,
					"port", openPort.RemotePort,
					"existing_owner", existingClientID)
				errors = append(errors, fmt.Errorf("port %d already in use by client %s", openPort.RemotePort, existingClientID))
				continue
			}
			// Same client requesting same port - skip
			duplicatePorts = append(duplicatePorts, openPort.RemotePort)
			slog.Info("Port already opened by same client",
				"port", openPort.RemotePort,
				"client_id", client.ID)
			continue
		}

		// Create port listener
		slog.Debug("Creating port listener",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"protocol", openPort.Protocol)

		createStart := time.Now()
		portListener, err := pm.createPortListener(client, openPort)
		createDuration := time.Since(createStart)

		if err != nil {
			slog.Error("Failed to create port listener",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"protocol", openPort.Protocol,
				"create_duration", createDuration,
				"error", err)
			errors = append(errors, fmt.Errorf("failed to open port %d: %v", openPort.RemotePort, err))
			continue
		}

		// Register the port
		pm.clientPorts[client.ID][openPort.RemotePort] = portListener
		pm.portOwners[openPort.RemotePort] = client.ID
		successfulPorts = append(successfulPorts, portListener)

		slog.Info("Port forwarding created successfully",
			"client_id", client.ID,
			"remote_port", openPort.RemotePort,
			"local_host", openPort.LocalHost,
			"local_port", openPort.LocalPort,
			"protocol", openPort.Protocol,
			"create_duration", createDuration)
	}

	// Start listening on successful ports
	slog.Debug("Starting listeners for successful ports",
		"client_id", client.ID,
		"successful_count", len(successfulPorts))

	for i, portListener := range successfulPorts {
		slog.Debug("Starting port listener",
			"client_id", client.ID,
			"port", portListener.Port,
			"listener_index", i)

		pm.wg.Add(1)
		go func(pl *PortListener) {
			defer pm.wg.Done()
			pm.handlePortListener(pl)
		}(portListener)
	}

	elapsed := time.Since(openStart)

	// If we have any errors, return them
	if len(errors) > 0 {
		slog.Error("Port opening completed with errors",
			"client_id", client.ID,
			"requested_ports", len(openPorts),
			"successful_ports", len(successfulPorts),
			"error_count", len(errors),
			"conflict_ports", conflictPorts,
			"duplicate_ports", duplicatePorts,
			"duration", elapsed)
		return fmt.Errorf("failed to open some ports: %v", errors)
	}

	slog.Info("All ports opened successfully",
		"client_id", client.ID,
		"successful_ports", len(successfulPorts),
		"duplicate_ports", len(duplicatePorts),
		"total_requested", len(openPorts),
		"duration", elapsed)

	return nil
}

// createPortListener 创建端口监听器 (从 v1 完整迁移)
func (pm *PortForwardManager) createPortListener(client *ClientConn, openPort config.OpenPort) (*PortListener, error) {
	slog.Debug("Creating port listener",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"protocol", openPort.Protocol,
		"local_target", fmt.Sprintf("%s:%d", openPort.LocalHost, openPort.LocalPort))

	// Support both TCP and UDP
	if openPort.Protocol != "tcp" && openPort.Protocol != "udp" {
		slog.Error("Unsupported protocol for port forwarding",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"protocol", openPort.Protocol,
			"supported_protocols", []string{"tcp", "udp"})
		return nil, fmt.Errorf("protocol %s not supported, only TCP and UDP are supported", openPort.Protocol)
	}

	ctx, cancel := context.WithCancel(pm.ctx)
	addr := fmt.Sprintf(":%d", openPort.RemotePort)
	portListener := &PortListener{
		Port:      openPort.RemotePort,
		Protocol:  openPort.Protocol,
		ClientID:  client.ID,
		LocalHost: openPort.LocalHost,
		LocalPort: openPort.LocalPort,
		Client:    client,
		ctx:       ctx,
		cancel:    cancel,
	}

	slog.Debug("Port listener structure created",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"bind_addr", addr)

	if openPort.Protocol == "tcp" {
		// Create TCP listener
		slog.Debug("Creating TCP listener",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"bind_addr", addr)

		listenStart := time.Now()
		listener, err := net.Listen("tcp", addr)
		listenDuration := time.Since(listenStart)

		if err != nil {
			slog.Error("Failed to create TCP listener",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"bind_addr", addr,
				"listen_duration", listenDuration,
				"error", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on TCP port %d: %v", openPort.RemotePort, err)
		}
		portListener.Listener = listener

		slog.Debug("TCP listener created successfully",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"listen_duration", listenDuration,
			"local_addr", listener.Addr())
	} else { // UDP
		// Create UDP listener
		slog.Debug("Creating UDP packet connection",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"bind_addr", addr)

		listenStart := time.Now()
		packetConn, err := net.ListenPacket("udp", addr)
		listenDuration := time.Since(listenStart)

		if err != nil {
			slog.Error("Failed to create UDP packet connection",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"bind_addr", addr,
				"listen_duration", listenDuration,
				"error", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on UDP port %d: %v", openPort.RemotePort, err)
		}
		portListener.PacketConn = packetConn

		slog.Debug("UDP packet connection created successfully",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"listen_duration", listenDuration,
			"local_addr", packetConn.LocalAddr())
	}

	slog.Debug("Port listener created successfully",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"protocol", openPort.Protocol,
		"local_target", fmt.Sprintf("%s:%d", openPort.LocalHost, openPort.LocalPort))

	return portListener, nil
}

// handlePortListener 处理端口监听器 (从 v1 完整迁移)
func (pm *PortForwardManager) handlePortListener(portListener *PortListener) {
	defer func() {
		// Cancel the port listener context
		portListener.cancel()

		// Close the appropriate connection based on protocol
		if portListener.Protocol == "tcp" && portListener.Listener != nil {
			portListener.Listener.Close()
		} else if portListener.PacketConn != nil {
			portListener.PacketConn.Close()
		}

		slog.Info("Port listener stopped", "port", portListener.Port, "client_id", portListener.ClientID)
	}()

	slog.Info("Started listening for port forwarding",
		"port", portListener.Port,
		"protocol", portListener.Protocol,
		"client_id", portListener.ClientID,
		"local_target", net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort)))

	if portListener.Protocol == "tcp" {
		pm.handleTCPPortListener(portListener)
	} else {
		pm.handleUDPPortListener(portListener)
	}
}

// handleTCPPortListener 处理 TCP 端口监听 (从 v1 完整迁移)
func (pm *PortForwardManager) handleTCPPortListener(portListener *PortListener) {
	// Create channels for async operations
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	// Start accepting connections in a separate goroutine
	go func() {
		defer close(connCh)
		defer close(errCh)

		for {
			conn, err := portListener.Listener.Accept()
			if err != nil {
				select {
				case errCh <- err:
				case <-portListener.ctx.Done():
				}
				return
			}

			select {
			case connCh <- conn:
			case <-portListener.ctx.Done():
				conn.Close()
				return
			}
		}
	}()

	for {
		select {
		case <-portListener.ctx.Done():
			return
		case conn, ok := <-connCh:
			if !ok {
				return
			}
			// Handle the connection asynchronously
			pm.wg.Add(1)
			go func(incomingConn net.Conn) {
				defer pm.wg.Done()
				pm.handleForwardedConnection(portListener, incomingConn)
			}(conn)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			// Check if the error is due to listener being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("Port listener closed", "port", portListener.Port)
				return
			}
			slog.Error("Error accepting connection on forwarded port", "port", portListener.Port, "error", err)
			return
		}
	}
}

// handleUDPPortListener 处理 UDP 端口监听 (从 v1 完整迁移)
func (pm *PortForwardManager) handleUDPPortListener(portListener *PortListener) {
	buffer := make([]byte, 65536) // Maximum UDP packet size

	// Create channels for async operations
	type udpPacket struct {
		data []byte
		addr net.Addr
	}
	packetCh := make(chan udpPacket, 10)
	errCh := make(chan error, 1)

	// Start reading packets in a separate goroutine
	go func() {
		defer close(packetCh)
		defer close(errCh)

		for {
			n, addr, err := portListener.PacketConn.ReadFrom(buffer)
			if err != nil {
				select {
				case errCh <- err:
				case <-portListener.ctx.Done():
				}
				return
			}

			// Make a copy of the data
			data := make([]byte, n)
			copy(data, buffer[:n])

			select {
			case packetCh <- udpPacket{data: data, addr: addr}:
			case <-portListener.ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-portListener.ctx.Done():
			return
		case packet, ok := <-packetCh:
			if !ok {
				return
			}
			// Handle the UDP packet asynchronously
			pm.wg.Add(1)
			go func(data []byte, clientAddr net.Addr) {
				defer pm.wg.Done()
				pm.handleUDPPacket(portListener, data, clientAddr)
			}(packet.data, packet.addr)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			// Check if the error is due to connection being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("UDP port listener closed", "port", portListener.Port)
				return
			}
			slog.Error("Error reading UDP packet on forwarded port", "port", portListener.Port, "error", err)
			return
		}
	}
}

// handleUDPPacket 处理单个 UDP 数据包 (从 v1 完整迁移)
func (pm *PortForwardManager) handleUDPPacket(portListener *PortListener, data []byte, clientAddr net.Addr) {
	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	slog.Debug("New UDP packet to forwarded port",
		"port", portListener.Port,
		"client_id", portListener.ClientID,
		"target", targetAddr,
		"client_addr", clientAddr,
		"data_size", len(data))

	// Create UDP connection to target with context
	ctx, cancel := context.WithTimeout(portListener.ctx, 30*time.Second)
	defer cancel()

	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		slog.Error("Failed to create UDP connection to target",
			"port", portListener.Port,
			"client_id", portListener.ClientID,
			"target", targetAddr,
			"error", err)
		return
	}
	defer targetConn.Close()

	// Send data to target
	_, err = targetConn.Write(data)
	if err != nil {
		slog.Error("Failed to send UDP data to target",
			"port", portListener.Port,
			"error", err)
		return
	}

	// Read response from target with context deadline
	responseBuffer := make([]byte, 65536)
	n, err := targetConn.Read(responseBuffer)
	if err != nil {
		// Timeout or other error - UDP is connectionless, so this might be expected
		slog.Debug("No response from UDP target", "port", portListener.Port, "error", err)
		return
	}

	// Send response back to client
	_, err = portListener.PacketConn.WriteTo(responseBuffer[:n], clientAddr)
	if err != nil {
		slog.Error("Failed to send UDP response to client",
			"port", portListener.Port,
			"error", err)
		return
	}

	slog.Debug("UDP packet forwarded successfully",
		"port", portListener.Port,
		"response_size", n)
}

// handleForwardedConnection 处理转发的连接 (从 v1 完整迁移)
func (pm *PortForwardManager) handleForwardedConnection(portListener *PortListener, incomingConn net.Conn) {
	defer incomingConn.Close()

	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	slog.Info("New connection to forwarded port",
		"port", portListener.Port,
		"client_id", portListener.ClientID,
		"target", targetAddr,
		"remote_addr", incomingConn.RemoteAddr())

	// Use the client's dialNetwork method to create connection - this reuses existing logic
	clientConn, err := portListener.Client.dialNetwork("tcp", targetAddr)
	if err != nil {
		slog.Error("Failed to connect to target via client",
			"port", portListener.Port,
			"client_id", portListener.ClientID,
			"target", targetAddr,
			"error", err)
		return
	}
	defer clientConn.Close()

	// Create context for the connection with timeout
	ctx, cancel := context.WithTimeout(portListener.ctx, 30*time.Minute)
	defer cancel()

	// Start bidirectional data transfer
	pm.transferData(ctx, incomingConn, clientConn, portListener.Port)
}

// transferData 处理双向数据传输 (从 v1 完整迁移)
func (pm *PortForwardManager) transferData(ctx context.Context, conn1, conn2 net.Conn, port int) {
	var wg sync.WaitGroup

	// Copy from conn1 to conn2
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyDataWithContext(ctx, conn1, conn2, "incoming->client", port)
	}()

	// Copy from conn2 to conn1
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyDataWithContext(ctx, conn2, conn1, "client->incoming", port)
	}()

	// Wait for completion or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Debug("Port forwarding connection finished", "port", port)
	case <-ctx.Done():
		slog.Debug("Port forwarding connection cancelled", "port", port)
	}
}

// copyDataWithContext 在连接间复制数据 (从 v1 完整迁移)
func (pm *PortForwardManager) copyDataWithContext(ctx context.Context, dst, src net.Conn, direction string, port int) {
	buffer := make([]byte, 32*1024) // 32KB buffer to match other components
	totalBytes := int64(0)

	for {
		// Check context before each operation
		select {
		case <-ctx.Done():
			slog.Debug("Data copy cancelled by context", "direction", direction, "port", port, "transferred_bytes", totalBytes)
			return
		default:
		}

		// Set read timeout based on context
		if deadline, ok := ctx.Deadline(); ok {
			src.SetReadDeadline(deadline)
		} else {
			src.SetReadDeadline(time.Now().Add(30 * time.Second))
		}

		n, err := src.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)

			// Set write timeout based on context
			if deadline, ok := ctx.Deadline(); ok {
				dst.SetWriteDeadline(deadline)
			} else {
				dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			}

			_, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				slog.Error("Port forward write error",
					"direction", direction,
					"port", port,
					"error", writeErr,
					"transferred_bytes", totalBytes)
				return
			}
		}

		if err != nil {
			if err != net.ErrClosed {
				slog.Debug("Port forward connection closed",
					"direction", direction,
					"port", port,
					"error", err,
					"transferred_bytes", totalBytes)
			}
			return
		}
	}
}

// CloseClientPorts 关闭客户端的所有端口 (从 v1 完整迁移)
func (pm *PortForwardManager) CloseClientPorts(clientID string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		return
	}

	slog.Info("Closing all ports for client", "client_id", clientID, "port_count", len(clientPortMap))

	// Close all port listeners for this client
	for port, portListener := range clientPortMap {
		// Remove from port owners
		delete(pm.portOwners, port)

		// Cancel the port listener context - this will gracefully stop all operations
		portListener.cancel()

		slog.Info("Closed port forwarding", "client_id", clientID, "port", port)
	}

	// Remove the client from clientPorts
	delete(pm.clientPorts, clientID)
}

func (pm *PortForwardManager) Stop() {
	stopStart := time.Now()
	slog.Info("Stopping port forwarding manager")

	// Cancel the context to stop all port listeners
	pm.cancel()

	// Get count of active ports for logging
	pm.mutex.RLock()
	totalPorts := len(pm.portOwners)
	totalClients := len(pm.clientPorts)
	pm.mutex.RUnlock()

	slog.Debug("Waiting for all port forwarding operations to complete",
		"total_ports", totalPorts,
		"total_clients", totalClients)

	// Wait for all goroutines to finish
	done := make(chan struct{})
	go func() {
		pm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Debug("All port forwarding goroutines finished gracefully")
	case <-time.After(5 * time.Second):
		slog.Warn("Timeout waiting for port forwarding goroutines to finish")
	}

	// Clear all data structures
	pm.mutex.Lock()
	pm.clientPorts = make(map[string]map[int]*PortListener)
	pm.portOwners = make(map[int]string)
	pm.mutex.Unlock()

	elapsed := time.Since(stopStart)
	slog.Info("Port forwarding manager stopped",
		"stop_duration", elapsed,
		"ports_closed", totalPorts,
		"clients_affected", totalClients)
}

// GetClientPorts 获取客户端的端口列表 (从 v1 完整迁移)
func (pm *PortForwardManager) GetClientPorts(clientID string) []int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		slog.Debug("No ports found for client", "client_id", clientID)
		return nil
	}

	ports := make([]int, 0, len(clientPortMap))
	for port := range clientPortMap {
		ports = append(ports, port)
	}

	slog.Debug("Retrieved client ports",
		"client_id", clientID,
		"port_count", len(ports),
		"ports", ports)

	return ports
}

/* -------------------------------------------------------------------------------------------- */
/* ------------------------------- ClientConn ------------------------------------------------ */
/* -------------------------------------------------------------------------------------------- */

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

// ClientConn 方法实现 (从 v1 迁移，适配传输层抽象)
func (c *ClientConn) Stop() {
	c.stopOnce.Do(func() {
		slog.Info("Initiating graceful client stop", "client_id", c.ID)
		stopStartTime := time.Now()

		// Step 1: 取消上下文 (与 v1 相同)
		slog.Debug("Cancelling client context", "client_id", c.ID)
		c.cancel()

		// Step 2: 获取连接数量 (与 v1 相同)
		c.ConnsMu.RLock()
		connectionCount := len(c.Conns)
		c.ConnsMu.RUnlock()

		if connectionCount > 0 {
			slog.Info("Waiting for active connections to finish",
				"client_id", c.ID,
				"connection_count", connectionCount)
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
			slog.Debug("Closing transport connection", "client_id", c.ID)
			c.Conn.Close()
			slog.Debug("Transport connection closed", "client_id", c.ID)
		}

		// Step 4: 关闭所有代理连接 (与 v1 相同)
		slog.Debug("Closing all proxy connections",
			"client_id", c.ID,
			"connection_count", connectionCount)
		c.ConnsMu.Lock()
		for connID := range c.Conns {
			c.closeConnectionUnsafe(connID)
		}
		c.ConnsMu.Unlock()
		if connectionCount > 0 {
			slog.Debug("All proxy connections closed", "client_id", c.ID)
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
			slog.Debug("Closed message channels",
				"client_id", c.ID,
				"channel_count", channelCount)
		}

		// Step 6: 等待所有goroutine完成 (与 v1 相同)
		slog.Debug("Waiting for client goroutines to finish", "client_id", c.ID)
		done := make(chan struct{})
		go func() {
			c.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			slog.Debug("All client goroutines finished gracefully", "client_id", c.ID)
		case <-time.After(2 * time.Second):
			slog.Warn("Timeout waiting for client goroutines to finish", "client_id", c.ID)
		}

		elapsed := time.Since(stopStartTime)
		slog.Info("Client stop completed",
			"client_id", c.ID,
			"stop_duration", elapsed,
			"connections_closed", connectionCount,
			"channels_closed", channelCount)
	})
}

func (c *ClientConn) dialNetwork(network, addr string) (net.Conn, error) {
	// 生成连接ID (与 v1 相同)
	connID := xid.New().String()
	slog.Debug("Creating new network connection",
		"client_id", c.ID,
		"conn_id", connID,
		"network", network,
		"address", addr)

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

	slog.Debug("Connection registered",
		"client_id", c.ID,
		"conn_id", connID,
		"total_connections", connCount)

	// 🆕 发送连接请求到客户端 (适配传输层)
	connectMsg := map[string]interface{}{
		"type":    "connect",
		"id":      connID,
		"network": network,
		"address": addr,
	}

	err := c.Conn.WriteJSON(connectMsg)
	if err != nil {
		slog.Error("Failed to send connect message to client",
			"client_id", c.ID,
			"conn_id", connID,
			"error", err)
		c.closeConnection(connID)
		return nil, err
	}

	slog.Debug("Connect message sent to client",
		"client_id", c.ID,
		"conn_id", connID,
		"network", network,
		"address", addr)

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
	slog.Debug("Starting message handler for client", "client_id", c.ID)
	messageCount := 0

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Message handler stopping due to context cancellation",
				"client_id", c.ID,
				"messages_processed", messageCount)
			return
		default:
		}

		// 🆕 直接读取 JSON 消息，简化代码
		var msg map[string]interface{}
		if err := c.Conn.ReadJSON(&msg); err != nil {
			slog.Error("Transport read error",
				"client_id", c.ID,
				"messages_processed", messageCount,
				"error", err)
			return
		}

		messageCount++

		// 处理消息类型 (与 v1 相同)
		msgType, ok := msg["type"].(string)
		if !ok {
			slog.Error("Invalid message format from client - missing or invalid type field",
				"client_id", c.ID,
				"message_count", messageCount,
				"message_fields", gatewayGetMessageFields(msg))
			continue
		}

		// 记录消息处理（但不记录高频数据消息）(与 v1 相同)
		if msgType != "data" {
			slog.Debug("Processing message",
				"client_id", c.ID,
				"message_type", msgType,
				"message_count", messageCount)
		}

		switch msgType {
		case "connect_response", "data", "close":
			// 将所有消息路由到每个连接的通道 (与 v1 相同)
			c.routeMessage(msg)
		case "port_forward_request":
			// 直接处理端口转发请求 (与 v1 相同)
			slog.Info("Received port forwarding request", "client_id", c.ID)
			c.handlePortForwardRequest(msg)
		default:
			slog.Warn("Unknown message type received",
				"client_id", c.ID,
				"message_type", msgType,
				"message_count", messageCount)
		}
	}
}

// 以下方法从 v1 复制，保持逻辑不变

// routeMessage 将消息路由到适当连接的消息通道 (与 v1 相同)
func (c *ClientConn) routeMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in message - missing or wrong type",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	msgType, _ := msg["type"].(string)

	// 对于 connect_response 消息，如果需要，首先创建通道 (与 v1 相同)
	if msgType == "connect_response" {
		slog.Debug("Creating message channel for connect response",
			"client_id", c.ID,
			"conn_id", connID)
		c.createMessageChannel(connID)
	}

	c.msgChansMu.RLock()
	msgChan, exists := c.msgChans[connID]
	c.msgChansMu.RUnlock()

	if !exists {
		// 连接不存在，忽略消息 (与 v1 相同)
		slog.Debug("Ignoring message for non-existent connection",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
		return
	}

	// 发送消息到连接的通道（非阻塞，带上下文感知）(与 v1 相同)
	select {
	case msgChan <- msg:
		// 成功路由，不记录高频数据消息 (与 v1 相同)
		if msgType != "data" {
			slog.Debug("Message routed successfully",
				"client_id", c.ID,
				"conn_id", connID,
				"message_type", msgType)
		}
	case <-c.ctx.Done():
		slog.Debug("Message routing cancelled due to context",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
		return
	default:
		slog.Warn("Message channel full for connection",
			"client_id", c.ID,
			"conn_id", connID,
			"message_type", msgType)
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
func (c *ClientConn) processConnectionMessages(connID string, msgChan chan map[string]interface{}) {
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
			case "connect_response":
				c.handleConnectResponseMessage(msg)
			case "data":
				c.handleDataMessage(msg)
			case "close":
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
		slog.Error("Invalid connection ID in data message",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	// WebSocket JSON消息将二进制数据编码为base64字符串 (与 v1 相同)
	dataStr, ok := msg["data"].(string)
	if !ok {
		slog.Error("Invalid data format in data message",
			"client_id", c.ID,
			"conn_id", connID,
			"data_type", fmt.Sprintf("%T", msg["data"]))
		return
	}

	// 将base64字符串解码回[]byte (与 v1 相同)
	data, err := base64.StdEncoding.DecodeString(dataStr)
	if err != nil {
		slog.Error("Failed to decode base64 data",
			"client_id", c.ID,
			"conn_id", connID,
			"data_length", len(dataStr),
			"error", err)
		return
	}

	// 只记录较大的传输以减少噪音 (与 v1 相同)
	if len(data) > 10000 {
		slog.Debug("Gateway received large data chunk",
			"client_id", c.ID,
			"conn_id", connID,
			"bytes", len(data))
	}

	// 安全获取连接 (与 v1 相同)
	c.ConnsMu.RLock()
	proxyConn, ok := c.Conns[connID]
	c.ConnsMu.RUnlock()
	if !ok {
		slog.Warn("Data message for unknown connection",
			"client_id", c.ID,
			"conn_id", connID,
			"data_bytes", len(data))
		return
	}

	// 将数据写入本地连接，带上下文感知 (与 v1 相同)
	deadline := time.Now().Add(30 * time.Second) // 增加到30秒以获得更好的代理性能
	if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	proxyConn.LocalConn.SetWriteDeadline(deadline)

	n, err := proxyConn.LocalConn.Write(data)
	if err != nil {
		slog.Error("Failed to write data to local connection",
			"client_id", c.ID,
			"conn_id", connID,
			"data_bytes", len(data),
			"written_bytes", n,
			"error", err)
		c.closeConnection(connID)
		return
	}

	// 只记录较大的传输 (与 v1 相同)
	if n > 10000 {
		slog.Debug("Gateway successfully wrote large data chunk to local connection",
			"client_id", c.ID,
			"conn_id", connID,
			"bytes", n)
	}
}

// handleCloseMessage 处理来自客户端的关闭消息 (与 v1 相同)
func (c *ClientConn) handleCloseMessage(msg map[string]interface{}) {
	// 提取连接ID (与 v1 相同)
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in close message",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	slog.Info("Received close message from client",
		"client_id", c.ID,
		"conn_id", connID)
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
		slog.Debug("Connection already removed", "conn_id", connID, "client_id", c.ID)
		return
	}

	// 发信号停止连接（非阻塞，幂等）(与 v1 相同)
	select {
	case <-proxyConn.Done:
		// 已经关闭，继续清理
	default:
		close(proxyConn.Done)
	}

	// 关闭实际连接（使用sync.Once确保只关闭一次）(与 v1 相同)
	proxyConn.once.Do(func() {
		slog.Debug("Closing local connection", "conn_id", proxyConn.ID)
		if err := proxyConn.LocalConn.Close(); err != nil {
			// 不记录关闭错误，因为在关闭期间是预期的
			slog.Debug("Connection close error (expected during shutdown)", "conn_id", proxyConn.ID, "error", err)
		}
	})

	slog.Debug("Connection closed and cleaned up", "conn_id", proxyConn.ID, "client_id", c.ID)
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
			slog.Debug("Connection close error during unsafe close", "conn_id", proxyConn.ID, "error", err)
		}
	})
}

// handleConnectResponseMessage 处理来自客户端的连接响应消息 (与 v1 相同逻辑)
func (c *ClientConn) handleConnectResponseMessage(msg map[string]interface{}) {
	connID, ok := msg["id"].(string)
	if !ok {
		slog.Error("Invalid connection ID in connect response",
			"client_id", c.ID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	success, ok := msg["success"].(bool)
	if !ok {
		slog.Error("Invalid success field in connect response",
			"client_id", c.ID,
			"conn_id", connID,
			"message_fields", gatewayGetMessageFields(msg))
		return
	}

	if success {
		slog.Debug("Client successfully connected to target",
			"client_id", c.ID,
			"conn_id", connID)
	} else {
		errorMsg, _ := msg["error"].(string)
		slog.Error("Client failed to connect to target",
			"client_id", c.ID,
			"conn_id", connID,
			"error", errorMsg)
		c.closeConnection(connID)
	}
}

// handleConnection 处理代理连接的数据传输 (与 v1 相同)
func (c *ClientConn) handleConnection(proxyConn *Conn) {
	slog.Debug("Starting connection handler",
		"client_id", c.ID,
		"conn_id", proxyConn.ID)

	// 增加缓冲区大小以获得更好的性能 (与 v1 相同)
	buffer := make([]byte, 32*1024) // 32KB缓冲区匹配网关
	totalBytes := 0
	readCount := 0
	startTime := time.Now()

	defer func() {
		elapsed := time.Since(startTime)
		slog.Debug("Connection handler finished",
			"client_id", c.ID,
			"conn_id", proxyConn.ID,
			"total_bytes", totalBytes,
			"read_operations", readCount,
			"duration", elapsed)
	}()

	for {
		select {
		case <-c.ctx.Done():
			slog.Debug("Connection handler stopping due to context cancellation",
				"client_id", c.ID,
				"conn_id", proxyConn.ID,
				"total_bytes", totalBytes)
			return
		case <-proxyConn.Done:
			slog.Debug("Connection handler stopping - connection marked as done",
				"client_id", c.ID,
				"conn_id", proxyConn.ID,
				"total_bytes", totalBytes)
			return
		default:
		}

		// 基于上下文设置读取截止时间 (与 v1 相同)
		deadline := time.Now().Add(30 * time.Second)
		if ctxDeadline, ok := c.ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		proxyConn.LocalConn.SetReadDeadline(deadline)

		n, err := proxyConn.LocalConn.Read(buffer)
		readCount++

		if n > 0 {
			totalBytes += n
			// 只记录较大的传输以减少噪音 (与 v1 相同)
			if totalBytes%100000 == 0 || n > 10000 {
				slog.Debug("Gateway read data from local connection",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"bytes_this_read", n,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// 将二进制数据编码为base64字符串 (与 v1 相同)
			encodedData := base64.StdEncoding.EncodeToString(buffer[:n])

			// 🆕 使用传输层发送数据
			dataMsg := map[string]interface{}{
				"type": "data",
				"id":   proxyConn.ID,
				"data": encodedData,
			}

			writeErr := c.Conn.WriteJSON(dataMsg)
			if writeErr != nil {
				slog.Error("Error writing data to client via transport",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"data_bytes", n,
					"total_bytes", totalBytes,
					"error", writeErr)
				c.closeConnection(proxyConn.ID)
				return
			}

			// 只记录较大的传输 (与 v1 相同)
			if n > 10000 {
				slog.Debug("Gateway successfully sent large data chunk to client",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
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
						"client_id", c.ID,
						"conn_id", proxyConn.ID)
					return
				case <-proxyConn.Done:
					slog.Debug("Connection handler stopping - done channel during timeout",
						"client_id", c.ID,
						"conn_id", proxyConn.ID)
					return
				default:
					continue // 如果上下文仍然有效，则继续超时
				}
			}

			// 优雅地处理连接关闭错误 (与 v1 相同)
			if strings.Contains(err.Error(), "use of closed network connection") ||
				strings.Contains(err.Error(), "read/write on closed pipe") ||
				strings.Contains(err.Error(), "connection reset by peer") {
				slog.Debug("Local connection closed during read operation",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			} else if err != io.EOF {
				slog.Error("Error reading from local connection",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"total_bytes", totalBytes,
					"read_count", readCount,
					"error", err)
			} else {
				slog.Debug("Local connection closed (EOF)",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"total_bytes", totalBytes,
					"read_count", readCount)
			}

			// 🆕 发送关闭消息到客户端
			closeMsg := map[string]interface{}{
				"type": "close",
				"id":   proxyConn.ID,
			}

			closeErr := c.Conn.WriteJSON(closeMsg)
			if closeErr != nil {
				slog.Debug("Error sending close message to client",
					"client_id", c.ID,
					"conn_id", proxyConn.ID,
					"error", closeErr)
			} else {
				slog.Debug("Sent close message to client",
					"client_id", c.ID,
					"conn_id", proxyConn.ID)
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
		slog.Error("No open_ports in port_forward_request", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Missing open_ports field")
		return
	}

	// Convert to []config.OpenPort
	openPortsSlice, ok := openPortsInterface.([]interface{})
	if !ok {
		slog.Error("Invalid open_ports format", "client_id", c.ID)
		c.sendPortForwardResponse(false, "Invalid open_ports format")
		return
	}

	var openPorts []config.OpenPort
	for _, portInterface := range openPortsSlice {
		portMap, ok := portInterface.(map[string]interface{})
		if !ok {
			slog.Error("Invalid port configuration format", "client_id", c.ID)
			continue
		}

		// Extract port configuration
		remotePort, ok := portMap["remote_port"].(float64) // JSON numbers are float64
		if !ok {
			slog.Error("Invalid remote_port", "client_id", c.ID)
			continue
		}

		localPort, ok := portMap["local_port"].(float64)
		if !ok {
			slog.Error("Invalid local_port", "client_id", c.ID)
			continue
		}

		localHost, ok := portMap["local_host"].(string)
		if !ok {
			slog.Error("Invalid local_host", "client_id", c.ID)
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
		slog.Info("No valid ports to open", "client_id", c.ID)
		c.sendPortForwardResponse(true, "No ports to open")
		return
	}

	// Attempt to open the ports
	err := c.portForwardMgr.OpenPorts(c, openPorts)
	if err != nil {
		slog.Error("Failed to open ports", "client_id", c.ID, "error", err)
		c.sendPortForwardResponse(false, err.Error())
		return
	}

	slog.Info("Successfully opened ports", "client_id", c.ID, "port_count", len(openPorts))
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
		slog.Error("Failed to send port forward response", "client_id", c.ID, "error", err)
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
