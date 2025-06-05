package proxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestHTTPProxyConnect(t *testing.T) {
	// Create a mock target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer func() {
		if err := targetListener.Close(); err != nil {
			t.Logf("Error closing target listener: %v", err)
		}
	}()

	targetAddr := targetListener.Addr().String()

	// Start mock target server
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("Error closing connection: %v", err)
					}
				}()
				// Echo server
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, writeErr := c.Write(buf[:n]); writeErr != nil {
					t.Logf("Error writing to connection: %v", writeErr)
				}
			}(conn)
		}
	}()

	// Mock dial function
	dialFunc := func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, targetAddr)
	}

	// Create HTTP proxy
	cfg := &config.HTTPConfig{
		ListenAddr: "127.0.0.1:0",
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	// Start proxy
	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer func() {
		if err := proxy.Stop(); err != nil {
			t.Logf("Error stopping proxy: %v", err)
		}
	}()

	// Get proxy address
	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()

	// Test connection
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Error closing connection: %v", err)
		}
	}()

	// Send HTTP CONNECT request
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("Failed to send CONNECT request: %v", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Check for successful connection
	if !strings.Contains(response, "200 Connection Established") {
		t.Errorf("Expected '200 Connection Established', got: %s", response)
	}
}

func TestHTTPProxyConnectWithAuth(t *testing.T) {
	// Create a mock target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer func() {
		if err := targetListener.Close(); err != nil {
			t.Logf("Error closing target listener: %v", err)
		}
	}()

	targetAddr := targetListener.Addr().String()

	// Start mock target server
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() {
					if err := c.Close(); err != nil {
						t.Logf("Error closing connection: %v", err)
					}
				}()
				// Echo server
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if _, writeErr := c.Write(buf[:n]); writeErr != nil {
					t.Logf("Error writing to connection: %v", writeErr)
				}
			}(conn)
		}
	}()

	// Mock dial function
	dialFunc := func(_ context.Context, network, _ string) (net.Conn, error) {
		return net.Dial(network, targetAddr)
	}

	// Create HTTP proxy with authentication
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	// Start proxy
	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer func() {
		if err := proxy.Stop(); err != nil {
			t.Logf("Error stopping proxy: %v", err)
		}
	}()

	// Get proxy address
	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Test CONNECT with authentication
	t.Run("CONNECT with auth", func(t *testing.T) {
		// Connect to proxy
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}()

		// Send CONNECT request with authentication
		auth := "Basic dGVzdHVzZXI6dGVzdHBhc3M=" // base64(testuser:testpass)
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
			targetAddr, targetAddr, auth)
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			t.Fatalf("Failed to send CONNECT request: %v", err)
		}

		// Read CONNECT response
		reader := bufio.NewReader(conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CONNECT response: %v", err)
		}

		// Check for 200 Connection Established
		if !strings.Contains(response, "200 Connection Established") {
			t.Errorf("Expected '200 Connection Established', got: %s", response)
		}
	})

	// Test CONNECT without authentication (should fail)
	t.Run("CONNECT without auth", func(t *testing.T) {
		// Connect to proxy
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}()

		// Send CONNECT request without authentication
		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			t.Fatalf("Failed to send CONNECT request: %v", err)
		}

		// Read CONNECT response
		reader := bufio.NewReader(conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CONNECT response: %v", err)
		}

		// Check for 407 Proxy Authentication Required
		if !strings.Contains(response, "407 Proxy Authentication Required") {
			t.Errorf("Expected '407 Proxy Authentication Required', got: %s", response)
		}
	})
}
