package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/things-go/go-socks5"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
)

// GroupBasedCredentialStore implements CredentialStore interface with support for group-based usernames
type GroupBasedCredentialStore struct {
	ConfigUsername string
	ConfigPassword string
}

// Valid implements the CredentialStore interface
// Supports usernames in format "username.group_id" by extracting the base username for authentication
func (g *GroupBasedCredentialStore) Valid(user, password, userAddr string) bool {
	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(user)

	// Authenticate using the base username and provided password
	authenticated := baseUsername == g.ConfigUsername && password == g.ConfigPassword

	if authenticated {
		logger.Info("SOCKS5 auth success", "user", user, "base", baseUsername, "from", userAddr)
	} else {
		logger.Warn("SOCKS5 auth failed", "user", user, "base", baseUsername, "from", userAddr)
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
	if cfg == nil {
		logger.Error("SOCKS5 proxy creation failed: config cannot be nil")
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dialFunc == nil {
		logger.Error("SOCKS5 proxy creation failed: dialFunc cannot be nil")
		return nil, fmt.Errorf("dialFunc cannot be nil")
	}

	logger.Info("Creating SOCKS5 proxy", "addr", cfg.ListenAddr, "auth", cfg.AuthUsername != "")

	socks5Auths := []socks5.Authenticator{}

	if cfg.AuthUsername != "" && cfg.AuthPassword != "" {
		// Use the built-in UserPassAuthenticator with our custom credential store
		credStore := &GroupBasedCredentialStore{
			ConfigUsername: cfg.AuthUsername,
			ConfigPassword: cfg.AuthPassword,
		}
		socks5Auths = append(socks5Auths, socks5.UserPassAuthenticator{
			Credentials: credStore,
		})
	}

	// Create a wrapper dial function that can extract group information from the request
	wrappedDialFunc := func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
		var userCtx *UserContext

		// Extract user information from the request's AuthContext
		if request.AuthContext != nil && request.AuthContext.Payload != nil {
			if username, exists := request.AuthContext.Payload["username"]; exists {
				groupID := ""
				if groupExtractor != nil {
					groupID = groupExtractor(username)
				}
				userCtx = &UserContext{
					Username: username,
					GroupID:  groupID,
				}
				logger.Info("SOCKS5 user context", "user", username, "group", groupID, "target", addr)
			}
		}

		// If no user context was extracted, create a default one
		if userCtx == nil {
			userCtx = &UserContext{
				Username: "socks5-user", // Default username for SOCKS5
				GroupID:  "",            // Default group
			}
		}

		// Add user context to the context
		type userContextKey string
		const userKey userContextKey = "user"
		ctx = context.WithValue(ctx, userKey, userCtx)

		conn, err := dialFunc(ctx, network, addr)
		if err != nil {
			logger.Error("SOCKS5 dial failed", "network", network, "addr", addr, "user", userCtx.Username, "group", userCtx.GroupID, "err", err)
			return nil, err
		}

		logger.Info("SOCKS5 dial success", "network", network, "addr", addr, "user", userCtx.Username, "group", userCtx.GroupID)
		return conn, nil
	}

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

	logger.Info("SOCKS5 proxy created", "addr", cfg.ListenAddr)
	return proxy, nil
}

// Start starts the SOCKS5 server
func (s *socks5Proxy) Start() error {
	logger.Info("Starting SOCKS5 proxy", "addr", s.listenAddr)

	// Create listener
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		logger.Error("Failed to create listener", "addr", s.listenAddr, "err", err)
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = listener

	// Start SOCKS5 server in a separate goroutine
	go func() {
		if err := s.server.Serve(listener); err != nil {
			logger.Error("SOCKS5 server error", "addr", s.listenAddr, "err", err)
		}
	}()

	logger.Info("SOCKS5 proxy started", "addr", s.listenAddr)
	return nil
}

// Stop stops the SOCKS5 server
func (s *socks5Proxy) Stop() error {
	logger.Info("Stopping SOCKS5 proxy", "addr", s.listenAddr)

	if s.listener != nil {
		err := s.listener.Close()
		if err != nil {
			logger.Error("Error closing listener", "addr", s.listenAddr, "err", err)
			return err
		}
		logger.Info("SOCKS5 proxy stopped", "addr", s.listenAddr)
		return nil
	}

	return nil
}

// DialConn implements the GatewayProxy interface by using the dialFunc
func (s *socks5Proxy) DialConn(network, addr string) (net.Conn, error) {
	conn, err := s.dialFunc(context.Background(), network, addr)
	if err != nil {
		logger.Error("SOCKS5 direct dial failed", "network", network, "addr", addr, "err", err)
		return nil, err
	}
	return conn, nil
}

// SetListenAddr sets the address on which the SOCKS5 server will listen
func (s *socks5Proxy) SetListenAddr(addr string) {
	s.listenAddr = addr
}
