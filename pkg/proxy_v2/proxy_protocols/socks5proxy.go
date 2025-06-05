package proxy_protocols

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"time"

	"github.com/things-go/go-socks5"

	"github.com/buhuipao/anyproxy/pkg/config"
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
	slog.Info("Creating SOCKS5 proxy",
		"listen_addr", config.ListenAddr,
		"auth_enabled", config.AuthUsername != "")

	proxy := &SOCKS5Proxy{
		config:         config,
		dialFunc:       dialFn,
		groupExtractor: groupExtractor,
	}

	// 配置认证方法 (与 v1 相同)
	socks5Auths := []socks5.Authenticator{}

	if config.AuthUsername != "" && config.AuthPassword != "" {
		slog.Debug("Configuring SOCKS5 authentication", "auth_username", config.AuthUsername)

		// 使用内置的 UserPassAuthenticator 和自定义凭证存储 (与 v1 相同)
		credStore := &GroupBasedCredentialStore{
			ConfigUsername: config.AuthUsername,
			ConfigPassword: config.AuthPassword,
		}
		socks5Auths = append(socks5Auths, socks5.UserPassAuthenticator{
			Credentials: credStore,
		})
		slog.Debug("SOCKS5 user/password authentication configured", "auth_username", config.AuthUsername)
	} else {
		slog.Debug("No authentication configured for SOCKS5 proxy")
	}

	// 创建包装的拨号函数，支持组信息提取 (与 v1 相同)
	wrappedDialFunc := func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
		requestID := fmt.Sprintf("%d", time.Now().UnixNano())
		dialStart := time.Now()

		slog.Debug("SOCKS5 dial request received",
			"request_id", requestID,
			"network", network,
			"address", addr,
			"client_addr", func() string {
				if request != nil {
					return request.RemoteAddr.String()
				}
				return "unknown"
			}())

		var userCtx *common.UserContext

		// 从请求的 AuthContext 中提取用户信息 (与 v1 相同)
		if request.AuthContext != nil && request.AuthContext.Payload != nil {
			if username, exists := request.AuthContext.Payload["username"]; exists {
				groupID := ""
				if groupExtractor != nil {
					groupID = groupExtractor(username)
					slog.Debug("Extracted group ID from SOCKS5 username",
						"request_id", requestID,
						"username", username,
						"group_id", groupID)
				}
				userCtx = &common.UserContext{
					Username: username,
					GroupID:  groupID,
				}
				slog.Info("SOCKS5 user context extracted from authentication",
					"request_id", requestID,
					"username", username,
					"group_id", groupID,
					"target_addr", addr)
			} else {
				slog.Debug("No username found in SOCKS5 authentication context", "request_id", requestID)
			}
		}

		// 如果没有提取到用户上下文，创建默认的 (与 v1 相同)
		if userCtx == nil {
			userCtx = &common.UserContext{
				Username: "socks5-user", // SOCKS5 的默认用户名
				GroupID:  "",            // 默认组
			}
			slog.Debug("Using default user context for SOCKS5 request",
				"request_id", requestID,
				"default_username", userCtx.Username,
				"target_addr", addr)
		}

		// 将用户上下文添加到 context (与 v1 相同)
		ctx = context.WithValue(ctx, "user", userCtx)

		slog.Debug("Calling dial function for SOCKS5 request",
			"request_id", requestID,
			"network", network,
			"address", addr,
			"username", userCtx.Username,
			"group_id", userCtx.GroupID)

		conn, err := dialFn(ctx, network, addr)
		dialDuration := time.Since(dialStart)

		if err != nil {
			slog.Error("SOCKS5 dial failed",
				"request_id", requestID,
				"network", network,
				"address", addr,
				"username", userCtx.Username,
				"group_id", userCtx.GroupID,
				"dial_duration", dialDuration,
				"error", err)
			return nil, err
		}

		slog.Info("SOCKS5 dial successful",
			"request_id", requestID,
			"network", network,
			"address", addr,
			"username", userCtx.Username,
			"group_id", userCtx.GroupID,
			"dial_duration", dialDuration)

		// 🆕 使用 ConnWrapper 包装连接以提供正确的地址信息
		wrappedConn := common.NewConnWrapper(conn, network, addr)
		return wrappedConn, nil
	}

	slog.Debug("Configuring SOCKS5 server",
		"listen_addr", config.ListenAddr,
		"auth_methods_count", len(socks5Auths))

	// 创建 SOCKS5 服务器 (与 v1 相同)
	server := socks5.NewServer(
		socks5.WithAuthMethods(socks5Auths),
		socks5.WithDialAndRequest(wrappedDialFunc),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)

	proxy.server = server
	slog.Info("SOCKS5 proxy created successfully", "listen_addr", config.ListenAddr)
	return proxy, nil
}

// Start starts the SOCKS5 proxy server (与 v1 相同)
func (p *SOCKS5Proxy) Start() error {
	slog.Info("Starting SOCKS5 proxy server", "listen_addr", p.config.ListenAddr)
	startTime := time.Now()

	// 创建监听器 (与 v1 相同)
	slog.Debug("Creating TCP listener for SOCKS5", "address", p.config.ListenAddr)
	listener, err := net.Listen("tcp", p.config.ListenAddr)
	if err != nil {
		slog.Error("Failed to create TCP listener for SOCKS5 proxy",
			"listen_addr", p.config.ListenAddr,
			"error", err)
		return fmt.Errorf("failed to listen on %s: %v", p.config.ListenAddr, err)
	}
	p.listener = listener
	slog.Debug("TCP listener created successfully for SOCKS5", "listen_addr", p.config.ListenAddr)

	// 在单独的 goroutine 中启动 SOCKS5 服务器 (与 v1 相同)
	go func() {
		elapsed := time.Since(startTime)
		slog.Info("SOCKS5 server starting to serve requests",
			"listen_addr", p.config.ListenAddr,
			"startup_duration", elapsed)
		if err := p.server.Serve(listener); err != nil {
			slog.Error("SOCKS5 server terminated unexpectedly",
				"listen_addr", p.config.ListenAddr,
				"error", err)
		} else {
			slog.Info("SOCKS5 server stopped", "listen_addr", p.config.ListenAddr)
		}
	}()

	slog.Info("SOCKS5 proxy server started successfully",
		"listen_addr", p.config.ListenAddr,
		"startup_duration", time.Since(startTime))

	return nil
}

// Stop stops the SOCKS5 proxy server (与 v1 相同)
func (p *SOCKS5Proxy) Stop() error {
	slog.Info("Initiating SOCKS5 proxy server shutdown", "listen_addr", p.config.ListenAddr)
	stopTime := time.Now()

	if p.listener != nil {
		slog.Debug("Closing SOCKS5 listener", "listen_addr", p.config.ListenAddr)
		err := p.listener.Close()

		elapsed := time.Since(stopTime)
		if err != nil {
			slog.Error("Error closing SOCKS5 listener",
				"listen_addr", p.config.ListenAddr,
				"shutdown_duration", elapsed,
				"error", err)
			return err
		}

		slog.Info("SOCKS5 proxy server shutdown completed",
			"listen_addr", p.config.ListenAddr,
			"shutdown_duration", elapsed)
		return nil
	}

	slog.Debug("SOCKS5 listener was nil, nothing to close", "listen_addr", p.config.ListenAddr)
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
	slog.Debug("SOCKS5 authentication attempt",
		"username", user,
		"client_addr", userAddr)

	// 提取基础用户名 (与 v1 相同)
	baseUsername := extractBaseUsername(user)

	// 验证凭证 (与 v1 相同)
	isValid := baseUsername == g.ConfigUsername && password == g.ConfigPassword

	if isValid {
		slog.Debug("SOCKS5 authentication successful",
			"username", user,
			"base_username", baseUsername,
			"client_addr", userAddr)
	} else {
		slog.Warn("SOCKS5 authentication failed",
			"username", user,
			"base_username", baseUsername,
			"client_addr", userAddr)
	}

	return isValid
}

// SOCKS5Logger 自定义 SOCKS5 日志器 (与 v1 相同)
type SOCKS5Logger struct{}

func (l *SOCKS5Logger) Errorf(format string, args ...interface{}) {
	slog.Error(fmt.Sprintf("SOCKS5: "+format, args...))
}

func (l *SOCKS5Logger) Printf(format string, args ...interface{}) {
	slog.Debug(fmt.Sprintf("SOCKS5: "+format, args...))
}
