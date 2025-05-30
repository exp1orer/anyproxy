package proxy

import (
	"context"
	"net"
)

// UserContext contains user authentication information for proxy requests
type UserContext struct {
	Username string
	GroupID  string
}

// GroupExtractor is a function type for extracting group ID from username
type GroupExtractor func(username string) string

// GatewayProxy defines the interface for different proxy implementations
type GatewayProxy interface {
	// Start starts the proxy server
	Start() error

	// Stop stops the proxy server
	Stop() error

	// DialConn creates a connection through an available client
	DialConn(network, addr string) (net.Conn, error)
}

// Dialer is a function type for creating network connections
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

var _ GatewayProxy = &socks5Proxy{}
var _ GatewayProxy = &httpProxy{}
