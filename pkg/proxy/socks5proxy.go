package proxy

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/things-go/go-socks5"
)

// socks5Proxy implements the GatewayProxy interface for SOCKS5 protocol
type socks5Proxy struct {
	config     *config.SOCKS5Config
	server     *socks5.Server
	dialFunc   ProxyDialer
	listenAddr string
	listener   net.Listener
}

// NewSOCKS5Proxy creates a new SOCKS5 proxy
func NewSOCKS5Proxy(cfg *config.SOCKS5Config, dialFunc ProxyDialer) (GatewayProxy, error) {
	socks5Auths := []socks5.Authenticator{}
	if cfg.AuthUsername != "" && cfg.AuthPassword != "" {
		// Create authentication store with username/password from config
		socks5Auths = append(socks5Auths, &socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{
			cfg.AuthUsername: cfg.AuthPassword,
		}})
	}

	// Create SOCKS5 server
	server := socks5.NewServer(
		socks5.WithAuthMethods(socks5Auths),
		socks5.WithDial(dialFunc),
		socks5.WithLogger(socks5.NewLogger(log.Default())),
		// socks5.WithResolver(&ForwardDNSResolver{}),
	)

	return &socks5Proxy{
		config:     cfg,
		server:     server,
		dialFunc:   dialFunc,
		listenAddr: cfg.ListenAddr,
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
		log.Printf("Starting SOCKS5 server on %s", s.listenAddr)
		if err := s.server.Serve(listener); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	return nil
}

// Stop stops the SOCKS5 server
func (s *socks5Proxy) Stop() error {
	if s.listener != nil {
		log.Printf("Stopping SOCKS5 server on %s", s.listenAddr)
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

/*
type ForwardDNSResolver struct {
	resolver *net.Resolver
}

func (r *ForwardDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	ips, err := r.resolver.LookupIP(ctx, "ip", name)
	if err != nil {
		return ctx, nil, err
	}

	return ctx, ips[0], nil
}
*/
