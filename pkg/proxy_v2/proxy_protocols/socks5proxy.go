package proxy_protocols // nolint:revive // Package name intentionally uses underscore to avoid conflict with main proxy package

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/things-go/go-socks5"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common"
)

// SOCKS5Proxy SOCKS5代理实现 (基于 v1 设计)
type SOCKS5Proxy struct {
	config         *config.SOCKS5Config
	server         *socks5.Server
	dialFunc       func(ctx context.Context, network, addr string) (net.Conn, error)
	groupExtractor func(string) string
	listener       net.Listener
}

// NewSOCKS5ProxyWithAuth creates a new SOCKS5 proxy with authentication (与 v1 相同)
func NewSOCKS5ProxyWithAuth(config *config.SOCKS5Config, dialFn func(context.Context, string, string) (net.Conn, error), groupExtractor func(string) string) (common.GatewayProxy, error) {
	logger.Info("Creating SOCKS5 proxy", "listen_addr", config.ListenAddr, "auth_enabled", config.AuthUsername != "")

	proxy := &SOCKS5Proxy{
		config:         config,
		dialFunc:       dialFn,
		groupExtractor: groupExtractor,
	}

	// 配置认证方法 (与 v1 相同)
	socks5Auths := []socks5.Authenticator{}

	if config.AuthUsername != "" && config.AuthPassword != "" {
		logger.Debug("Configuring SOCKS5 authentication", "auth_username", config.AuthUsername)

		// 使用内置的 UserPassAuthenticator 和自定义凭证存储 (与 v1 相同)
		credStore := &GroupBasedCredentialStore{
			ConfigUsername: config.AuthUsername,
			ConfigPassword: config.AuthPassword,
		}
		socks5Auths = append(socks5Auths, socks5.UserPassAuthenticator{
			Credentials: credStore,
		})
		logger.Debug("SOCKS5 user/password authentication configured", "auth_username", config.AuthUsername)
	} else {
		logger.Debug("No authentication configured for SOCKS5 proxy")
	}

	// 创建包装的拨号函数，支持组信息提取 (与 v1 相同)
	wrappedDialFunc := func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
		// 在请求开始时就生成 connID，贯穿整个请求生命周期
		connID := common.GenerateConnID()

		clientAddr := "unknown"
		if request != nil {
			clientAddr = request.RemoteAddr.String()
		}
		logger.Info("SOCKS5 dial request received", "conn_id", connID, "network", network, "address", addr, "client", clientAddr)

		// 将 connID 添加到 context 中
		ctx = common.WithConnID(ctx, connID)

		var userCtx *common.UserContext

		// 从请求的 AuthContext 中提取用户信息 (与 v1 相同)
		if request.AuthContext != nil && request.AuthContext.Payload != nil {
			if username, exists := request.AuthContext.Payload["username"]; exists {
				groupID := ""
				if groupExtractor != nil {
					groupID = groupExtractor(username)
					logger.Debug("Extracted group ID from SOCKS5 username", "conn_id", connID, "username", username, "group_id", groupID)
				}
				userCtx = &common.UserContext{
					Username: username,
					GroupID:  groupID,
				}
				logger.Info("SOCKS5 user context extracted from authentication", "conn_id", connID, "username", username, "group_id", groupID, "target_addr", addr)
			} else {
				logger.Debug("No username found in SOCKS5 authentication context", "conn_id", connID)
			}
		}

		// 如果没有提取到用户上下文，创建默认的 (与 v1 相同)
		if userCtx == nil {
			userCtx = &common.UserContext{
				Username: "socks5-user", // SOCKS5 的默认用户名
				GroupID:  "",            // 默认组
			}
			logger.Debug("Using default user context for SOCKS5 request", "conn_id", connID, "default_username", userCtx.Username, "target_addr", addr)
		}

		// 将用户上下文添加到 context (与 v1 相同)
		type userContextKey string
		const userKey userContextKey = "user"
		ctx = context.WithValue(ctx, userKey, userCtx)

		logger.Debug("Calling dial function for SOCKS5 request", "conn_id", connID, "network", network, "address", addr, "username", userCtx.Username, "group_id", userCtx.GroupID)

		conn, err := dialFn(ctx, network, addr)

		if err != nil {
			logger.Error("SOCKS5 dial failed", "conn_id", connID, "network", network, "address", addr, "username", userCtx.Username, "group_id", userCtx.GroupID, "err", err)
			return nil, err
		}

		// 连接已经建立，不需要再从 ConnWrapper 获取 ID，因为我们已经有了

		logger.Info("SOCKS5 dial successful", "conn_id", connID, "network", network, "address", addr, "username", userCtx.Username, "group_id", userCtx.GroupID)

		// 🆕 使用 ConnWrapper 包装连接以提供正确的地址信息
		wrappedConn := common.NewConnWrapper(conn, network, addr)
		return wrappedConn, nil
	}

	logger.Debug("Configuring SOCKS5 server", "listen_addr", config.ListenAddr, "auth_methods_count", len(socks5Auths))

	// 创建 SOCKS5 服务器 (与 v1 相同)
	server := socks5.NewServer(
		socks5.WithAuthMethods(socks5Auths),
		socks5.WithDialAndRequest(wrappedDialFunc),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)

	proxy.server = server
	logger.Info("SOCKS5 proxy created successfully", "listen_addr", config.ListenAddr)
	return proxy, nil
}

// Start starts the SOCKS5 proxy server (与 v1 相同)
func (p *SOCKS5Proxy) Start() error {
	logger.Info("Starting SOCKS5 proxy server", "listen_addr", p.config.ListenAddr)

	// 创建监听器 (与 v1 相同)
	logger.Debug("Creating TCP listener for SOCKS5", "address", p.config.ListenAddr)
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		logger.Error("Failed to create TCP listener for SOCKS5 proxy", "listen_addr", p.config.ListenAddr, "err", err)
		return fmt.Errorf("failed to listen on %s: %v", p.config.ListenAddr, err)
	}
	p.listener = listener
	logger.Debug("TCP listener created successfully for SOCKS5", "listen_addr", p.config.ListenAddr)

	// 在单独的 goroutine 中启动 SOCKS5 服务器 (与 v1 相同)
	go func() {
		logger.Info("SOCKS5 server starting to serve requests", "listen_addr", p.config.ListenAddr)
		if err := p.server.Serve(listener); err != nil {
			logger.Error("SOCKS5 server terminated unexpectedly", "listen_addr", p.config.ListenAddr, "err", err)
		} else {
			logger.Info("SOCKS5 server stopped", "listen_addr", p.config.ListenAddr)
		}
	}()

	logger.Info("SOCKS5 proxy server started successfully", "listen_addr", p.config.ListenAddr)

	return nil
}

// Stop stops the SOCKS5 proxy server (与 v1 相同)
func (p *SOCKS5Proxy) Stop() error {
	logger.Info("Initiating SOCKS5 proxy server shutdown", "listen_addr", p.config.ListenAddr)

	if p.listener != nil {
		logger.Debug("Closing SOCKS5 listener", "listen_addr", p.config.ListenAddr)
		err := p.listener.Close()

		if err != nil {
			logger.Error("Error closing SOCKS5 listener", "listen_addr", p.config.ListenAddr, "err", err)
			return err
		}

		logger.Info("SOCKS5 proxy server shutdown completed", "listen_addr", p.config.ListenAddr)
		return nil
	}

	logger.Debug("SOCKS5 listener was nil, nothing to close", "listen_addr", p.config.ListenAddr)
	return nil
}

// GetListenAddr returns the listen address (与 v1 相同)
func (p *SOCKS5Proxy) GetListenAddr() string {
	return p.config.ListenAddr
}

// GroupBasedCredentialStore implements CredentialStore interface with support for group-based usernames (与 v1 相同)
type GroupBasedCredentialStore struct {
	ConfigUsername string
	ConfigPassword string
}

// Valid implements the CredentialStore interface (与 v1 相同)
// Supports usernames in format "username.group_id" by extracting the base username for authentication
func (g *GroupBasedCredentialStore) Valid(user, password, userAddr string) bool {
	logger.Debug("SOCKS5 authentication attempt", "username", user, "client", userAddr)

	// 提取基础用户名 (与 v1 相同)
	baseUsername := extractBaseUsername(user)

	// 验证凭证 (与 v1 相同)
	isValid := baseUsername == g.ConfigUsername && password == g.ConfigPassword

	if isValid {
		logger.Debug("SOCKS5 authentication successful", "username", user, "base_username", baseUsername, "client", userAddr)
	} else {
		logger.Warn("SOCKS5 authentication failed", "username", user, "base_username", baseUsername, "client", userAddr)
	}

	return isValid
}
