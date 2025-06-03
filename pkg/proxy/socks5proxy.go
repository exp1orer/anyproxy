package proxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"
	"time"

	"github.com/things-go/go-socks5"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// GroupBasedCredentialStore implements CredentialStore interface with support for group-based usernames
type GroupBasedCredentialStore struct {
	ConfigUsername string
	ConfigPassword string
}

// Valid implements the CredentialStore interface
// Supports usernames in format "username.group_id" by extracting the base username for authentication
func (g *GroupBasedCredentialStore) Valid(user, password, userAddr string) bool {
	slog.Debug("SOCKS5 authentication attempt",
		"username", user,
		"client_addr", userAddr,
		"config_username", g.ConfigUsername)

	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(user)

	slog.Debug("Extracted base username for SOCKS5 authentication",
		"original_username", user,
		"base_username", baseUsername,
		"client_addr", userAddr)

	// Authenticate using the base username and provided password
	authenticated := baseUsername == g.ConfigUsername && password == g.ConfigPassword

	if authenticated {
		slog.Info("SOCKS5 authentication successful",
			"username", user,
			"base_username", baseUsername,
			"client_addr", userAddr)
	} else {
		slog.Warn("SOCKS5 authentication failed",
			"username", user,
			"base_username", baseUsername,
			"client_addr", userAddr,
			"reason", func() string {
				if baseUsername != g.ConfigUsername {
					return "invalid_username"
				}
				return "invalid_password"
			}())
	}

	return authenticated
}

// socks5Proxy implements the GatewayProxy interface for SOCKS5 protocol
type socks5Proxy struct {
	config         *config.SOCKS5Config
	server         *socks5.Server
	dialFunc       Dialer
	groupExtractor GroupExtractor
	listenAddr     string
	listener       net.Listener
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy
func NewSOCKS5Proxy(cfg *config.SOCKS5Config, dialFunc Dialer) (GatewayProxy, error) {
	return NewSOCKS5ProxyWithAuth(cfg, dialFunc, nil)
}

// NewSOCKS5ProxyWithAuth creates a new SOCKS5 proxy with authentication support
func NewSOCKS5ProxyWithAuth(cfg *config.SOCKS5Config, dialFunc Dialer, groupExtractor GroupExtractor) (GatewayProxy, error) {
	slog.Info("Creating new SOCKS5 proxy",
		"listen_addr", cfg.ListenAddr,
		"auth_enabled", cfg.AuthUsername != "",
		"group_extraction_enabled", groupExtractor != nil)

	if cfg == nil {
		slog.Error("SOCKS5 proxy creation failed: config cannot be nil")
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dialFunc == nil {
		slog.Error("SOCKS5 proxy creation failed: dialFunc cannot be nil")
		return nil, fmt.Errorf("dialFunc cannot be nil")
	}

	socks5Auths := []socks5.Authenticator{}

	if cfg.AuthUsername != "" && cfg.AuthPassword != "" {
		slog.Debug("Configuring SOCKS5 authentication",
			"auth_username", cfg.AuthUsername)

		// Use the built-in UserPassAuthenticator with our custom credential store
		credStore := &GroupBasedCredentialStore{
			ConfigUsername: cfg.AuthUsername,
			ConfigPassword: cfg.AuthPassword,
		}
		socks5Auths = append(socks5Auths, socks5.UserPassAuthenticator{
			Credentials: credStore,
		})
		slog.Debug("SOCKS5 user/password authentication configured",
			"auth_username", cfg.AuthUsername)
	} else {
		slog.Debug("No authentication configured for SOCKS5 proxy")
	}

	// Create a wrapper dial function that can extract group information from the request
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

		var userCtx *UserContext

		// Extract user information from the request's AuthContext
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
				userCtx = &UserContext{
					Username: username,
					GroupID:  groupID,
				}
				slog.Info("SOCKS5 user context extracted from authentication",
					"request_id", requestID,
					"username", username,
					"group_id", groupID,
					"target_addr", addr)
			} else {
				slog.Debug("No username found in SOCKS5 authentication context",
					"request_id", requestID)
			}
		}

		// If no user context was extracted, create a default one
		if userCtx == nil {
			userCtx = &UserContext{
				Username: "socks5-user", // Default username for SOCKS5
				GroupID:  "",            // Default group
			}
			slog.Debug("Using default user context for SOCKS5 request",
				"request_id", requestID,
				"default_username", userCtx.Username,
				"target_addr", addr)
		}

		// Add user context to the context
		ctx = context.WithValue(ctx, "user", userCtx)

		slog.Debug("Calling dial function for SOCKS5 request",
			"request_id", requestID,
			"network", network,
			"address", addr,
			"username", userCtx.Username,
			"group_id", userCtx.GroupID)

		conn, err := dialFunc(ctx, network, addr)
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

		return conn, nil
	}

	slog.Debug("Configuring SOCKS5 server",
		"listen_addr", cfg.ListenAddr,
		"auth_methods_count", len(socks5Auths))

	// Create SOCKS5 server with the enhanced dial function
	server := socks5.NewServer(
		socks5.WithAuthMethods(socks5Auths),
		socks5.WithDialAndRequest(wrappedDialFunc),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)

	proxy := &socks5Proxy{
		config:         cfg,
		server:         server,
		dialFunc:       dialFunc,
		groupExtractor: groupExtractor,
		listenAddr:     cfg.ListenAddr,
	}

	slog.Info("SOCKS5 proxy created successfully",
		"listen_addr", cfg.ListenAddr,
		"auth_enabled", cfg.AuthUsername != "",
		"auth_username", cfg.AuthUsername)

	return proxy, nil
}

// Start starts the SOCKS5 server
func (s *socks5Proxy) Start() error {
	slog.Info("Starting SOCKS5 proxy server", "listen_addr", s.listenAddr)
	startTime := time.Now()

	// Create listener
	slog.Debug("Creating TCP listener for SOCKS5", "address", s.listenAddr)
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		slog.Error("Failed to create TCP listener for SOCKS5 proxy",
			"listen_addr", s.listenAddr,
			"error", err)
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = listener
	slog.Debug("TCP listener created successfully for SOCKS5", "listen_addr", s.listenAddr)

	// Start SOCKS5 server in a separate goroutine
	go func() {
		elapsed := time.Since(startTime)
		slog.Info("SOCKS5 server starting to serve requests",
			"listen_addr", s.listenAddr,
			"startup_duration", elapsed)
		if err := s.server.Serve(listener); err != nil {
			slog.Error("SOCKS5 server terminated unexpectedly",
				"listen_addr", s.listenAddr,
				"error", err)
		} else {
			slog.Info("SOCKS5 server stopped", "listen_addr", s.listenAddr)
		}
	}()

	slog.Info("SOCKS5 proxy server started successfully",
		"listen_addr", s.listenAddr,
		"startup_duration", time.Since(startTime))

	return nil
}

// Stop stops the SOCKS5 server
func (s *socks5Proxy) Stop() error {
	slog.Info("Initiating SOCKS5 proxy server shutdown", "listen_addr", s.listenAddr)
	stopTime := time.Now()

	if s.listener != nil {
		slog.Debug("Closing SOCKS5 listener", "listen_addr", s.listenAddr)
		err := s.listener.Close()

		elapsed := time.Since(stopTime)
		if err != nil {
			slog.Error("Error closing SOCKS5 listener",
				"listen_addr", s.listenAddr,
				"shutdown_duration", elapsed,
				"error", err)
			return err
		}

		slog.Info("SOCKS5 proxy server shutdown completed",
			"listen_addr", s.listenAddr,
			"shutdown_duration", elapsed)
		return nil
	}

	slog.Debug("SOCKS5 listener was nil, nothing to close", "listen_addr", s.listenAddr)
	return nil
}

// DialConn implements the GatewayProxy interface by using the dialFunc
func (s *socks5Proxy) DialConn(network, addr string) (net.Conn, error) {
	slog.Debug("SOCKS5 direct dial request",
		"network", network,
		"address", addr,
		"listen_addr", s.listenAddr)

	dialStart := time.Now()
	conn, err := s.dialFunc(context.Background(), network, addr)
	dialDuration := time.Since(dialStart)

	if err != nil {
		slog.Error("SOCKS5 direct dial failed",
			"network", network,
			"address", addr,
			"dial_duration", dialDuration,
			"error", err)
		return nil, err
	}

	slog.Debug("SOCKS5 direct dial successful",
		"network", network,
		"address", addr,
		"dial_duration", dialDuration)

	return conn, nil
}

// SetListenAddr sets the address on which the SOCKS5 server will listen
func (s *socks5Proxy) SetListenAddr(addr string) {
	slog.Debug("Setting SOCKS5 listen address",
		"old_addr", s.listenAddr,
		"new_addr", addr)
	s.listenAddr = addr
}
