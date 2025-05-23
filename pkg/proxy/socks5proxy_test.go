package proxy

import (
	"context"
	"net"
	"testing"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// TODO: add more tests for socks5proxy
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
