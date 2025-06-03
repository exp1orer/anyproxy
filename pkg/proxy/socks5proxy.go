package proxy

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net"

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
	// Extract the base username (without group_id) for authentication
	baseUsername := extractBaseUsername(user)

	// Authenticate using the base username and provided password
	return baseUsername == g.ConfigUsername && password == g.ConfigPassword
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
				slog.Info("SOCKS5 extracted user info", "username", username, "group_id", groupID)
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
		ctx = context.WithValue(ctx, "user", userCtx)
		return dialFunc(ctx, network, addr)
	}

	// Create SOCKS5 server with the enhanced dial function
	server := socks5.NewServer(
		socks5.WithAuthMethods(socks5Auths),
		socks5.WithDialAndRequest(wrappedDialFunc),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
	)

	return &socks5Proxy{
		config:         cfg,
		server:         server,
		dialFunc:       dialFunc,
		groupExtractor: groupExtractor,
		listenAddr:     cfg.ListenAddr,
	}, nil
}

// Start starts the SOCKS5 server
func (s *socks5Proxy) Start() error {
	// Create listener
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", s.listenAddr, err)
	}
	s.listener = listener

	// Start SOCKS5 server in a separate goroutine
	go func() {
		slog.Info("Starting SOCKS5 server", "listen_addr", s.listenAddr)
		if err := s.server.Serve(listener); err != nil {
			slog.Error("SOCKS5 server error", "error", err)
		}
	}()

	return nil
}

// Stop stops the SOCKS5 server
func (s *socks5Proxy) Stop() error {
	if s.listener != nil {
		slog.Info("Stopping SOCKS5 server", "listen_addr", s.listenAddr)
		return s.listener.Close()
	}
	return nil
}

// DialConn implements the GatewayProxy interface by using the dialFunc
func (s *socks5Proxy) DialConn(network, addr string) (net.Conn, error) {
	if s.dialFunc == nil {
		return nil, fmt.Errorf("no dial function provided")
	}
	return s.dialFunc(context.Background(), network, addr)
}

// SetListenAddr sets the address on which the SOCKS5 server will listen
func (s *socks5Proxy) SetListenAddr(addr string) {
	s.listenAddr = addr
}
