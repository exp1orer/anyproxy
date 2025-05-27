package proxy

import (
	"context"
	"net"
)

// GatewayProxy defines the interface for different proxy implementations
type GatewayProxy interface {
	// Start starts the proxy server
	Start() error

	// Stop stops the proxy server
	Stop() error

	// DialConn creates a connection through an available client
	DialConn(network, addr string) (net.Conn, error)
}

// ProxyDialer is a function type for creating network connections
type ProxyDialer func(ctx context.Context, network, addr string) (net.Conn, error)

var _ GatewayProxy = &socks5Proxy{}
var _ GatewayProxy = &httpProxy{}
