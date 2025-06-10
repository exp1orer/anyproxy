// Package transport provides transport layer abstractions for AnyProxy v2.
package transport

import (
	"crypto/tls"
	"net"
)

// AuthConfig authentication configuration
type AuthConfig struct {
	Username string
	Password string
}

// Transport interface - minimalist design to support multiple transport protocols
type Transport interface {
	// Server side: listen and handle connections (🆕 supports TLS configuration)
	ListenAndServe(addr string, handler func(Connection)) error
	ListenAndServeWithTLS(addr string, handler func(Connection), tlsConfig *tls.Config) error
	// Client side: connect to server (supports configuration)
	DialWithConfig(addr string, config *ClientConfig) (Connection, error)
	// Close transport layer
	Close() error
}

// Connection interface - simplified connection abstraction
type Connection interface {
	// Write message (binary data)
	WriteMessage(data []byte) error
	// Read message
	ReadMessage() ([]byte, error)
	// Connection management
	Close() error
	RemoteAddr() net.Addr
	LocalAddr() net.Addr
	// Client information - must be implemented by all transport layers
	GetClientID() string
	GetGroupID() string
}

// ClientConfig client configuration - copy necessary configuration from v1
type ClientConfig struct {
	ClientID   string
	GroupID    string
	Username   string
	Password   string
	TLSCert    string
	TLSConfig  *tls.Config
	SkipVerify bool
}

// ConnectionHandler connection handler function type
type ConnectionHandler func(Connection)
