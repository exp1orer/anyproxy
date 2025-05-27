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
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	// Start mock target server
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Echo server
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	// Mock dial function that connects to our target server
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	defer proxy.Stop()

	// Get proxy address
	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	// Test CONNECT method
	t.Run("CONNECT method", func(t *testing.T) {
		// Connect to proxy
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send CONNECT request
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

		// Check for 200 Connection Established
		if !strings.Contains(response, "200 Connection Established") {
			t.Errorf("Expected '200 Connection Established', got: %s", response)
		}

		// Read the rest of the headers (empty line)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read response headers: %v", err)
			}
			if line == "\r\n" {
				break
			}
		}

		// Now we should have a tunnel - test data transfer
		testData := "Hello, World!"
		_, err = conn.Write([]byte(testData))
		if err != nil {
			t.Fatalf("Failed to send test data: %v", err)
		}

		// Read echo response
		buf := make([]byte, len(testData))
		_, err = conn.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read echo response: %v", err)
		}

		if string(buf) != testData {
			t.Errorf("Expected echo '%s', got '%s'", testData, string(buf))
		}
	})
}

func TestHTTPProxyConnectWithAuth(t *testing.T) {
	// Create a mock target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().String()

	// Start mock target server
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Echo server
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				c.Write(buf[:n])
			}(conn)
		}
	}()

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	defer proxy.Stop()

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
		defer conn.Close()

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
		defer conn.Close()

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
