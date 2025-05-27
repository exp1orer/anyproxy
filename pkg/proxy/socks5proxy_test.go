package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSOCKS5Proxy(t *testing.T) {
	tests := []struct {
		name    string
		config  *config.SOCKS5Config
		dialFn  ProxyDialer
		wantErr bool
	}{
		{
			name: "valid config with auth",
			config: &config.SOCKS5Config{
				AuthUsername: "testuser",
				AuthPassword: "testpass",
			},
			dialFn:  mockDialer,
			wantErr: false,
		},
		{
			name: "valid config without auth",
			config: &config.SOCKS5Config{
				AuthUsername: "",
				AuthPassword: "",
			},
			dialFn:  mockDialer,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewSOCKS5Proxy(tt.config, tt.dialFn)
			assert.NoError(t, err)
			assert.NotNil(t, proxy)
		})
	}
}

func TestSOCKS5Proxy_DialConn(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.SOCKS5Config
		dialFn   ProxyDialer
		network  string
		addr     string
		wantErr  bool
		expected net.Conn
	}{
		{
			name: "successful dial",
			config: &config.SOCKS5Config{
				AuthUsername: "testuser",
				AuthPassword: "testpass",
			},
			dialFn:   mockDialer,
			network:  "tcp",
			addr:     "example.com:80",
			wantErr:  false,
			expected: &mockConn{},
		},
		{
			name: "dial failure",
			config: &config.SOCKS5Config{
				AuthUsername: "testuser",
				AuthPassword: "testpass",
			},
			dialFn:  failingDialer,
			network: "tcp",
			addr:    "example.com:80",
			wantErr: true,
		},
		{
			name: "UDP network",
			config: &config.SOCKS5Config{
				AuthUsername: "testuser",
				AuthPassword: "testpass",
			},
			dialFn:  mockDialer,
			network: "udp",
			addr:    "example.com:53",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, err := NewSOCKS5Proxy(tt.config, tt.dialFn)
			require.NoError(t, err)

			conn, err := proxy.DialConn(tt.network, tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, conn)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, conn)
			}
		})
	}
}

func TestSOCKS5Proxy_StartStop(t *testing.T) {
	config := &config.SOCKS5Config{
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	proxy, err := NewSOCKS5Proxy(config, mockDialer)
	require.NoError(t, err)

	// Test Start
	err = proxy.Start()
	assert.NoError(t, err)

	// Give the server a moment to start
	time.Sleep(10 * time.Millisecond)

	// Test Stop
	err = proxy.Stop()
	// Stop may return an error due to closing the listener, which is expected
	// We just verify it doesn't panic

	// Test multiple stops (should be safe)
	err = proxy.Stop()
	// Multiple stops should be safe and not panic
}

func TestSOCKS5Proxy_InterfaceCompliance(t *testing.T) {
	config := &config.SOCKS5Config{
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	proxy, err := NewSOCKS5Proxy(config, mockDialer)
	require.NoError(t, err)

	// Verify that socks5Proxy implements GatewayProxy interface
	var _ GatewayProxy = proxy
}

// Helper functions for testing

func mockDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return &mockConn{}, nil
}

func failingDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return nil, errors.New("dial failed")
}

// Legacy test for backward compatibility
func TestDialConn(t *testing.T) {
	cfg := &config.SOCKS5Config{
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Create test connections
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Create a mock dial function that returns our test connection
	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return client, nil
	}

	proxy, err := NewSOCKS5Proxy(cfg, dialFn)
	if err != nil {
		t.Fatalf("Failed to create SOCKS5 proxy: %v", err)
	}

	// Test DialConn
	conn, err := proxy.DialConn("tcp", "example.com:80")
	if err != nil {
		t.Fatalf("DialConn failed: %v", err)
	}

	if conn != client {
		t.Fatal("DialConn didn't return the expected connection")
	}
}
