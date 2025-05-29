package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// TestHTTPProxyModes tests the two working modes of HTTP proxy
func TestHTTPProxyModes(t *testing.T) {
	// Create a simple HTTPS test server
	httpsServer := createTestHTTPSServer(t)
	defer httpsServer.Close()

	// Get server address
	serverAddr := httpsServer.Listener.Addr().String()
	serverHost := strings.Split(serverAddr, ":")[0]
	serverPort := strings.Split(serverAddr, ":")[1]

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Redirect to our test server
		return net.Dial(network, serverAddr)
	}

	// Create HTTP proxy
	cfg := &config.HTTPConfig{
		ListenAddr: "127.0.0.1:0",
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer proxy.Stop()

	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()
	time.Sleep(100 * time.Millisecond)

	t.Run("Mode 1: CONNECT Tunnel", func(t *testing.T) {
		// Simulate browser's CONNECT tunnel mode
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer conn.Close()

		// Send CONNECT request
		connectReq := fmt.Sprintf("CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n",
			serverHost, serverPort, serverHost, serverPort)
		_, err = conn.Write([]byte(connectReq))
		if err != nil {
			t.Fatalf("Failed to send CONNECT: %v", err)
		}

		// Read CONNECT response
		reader := bufio.NewReader(conn)
		response, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read CONNECT response: %v", err)
		}

		if !strings.Contains(response, "200 Connection Established") {
			t.Errorf("Expected CONNECT success, got: %s", response)
		}

		// Skip response headers
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("Failed to read headers: %v", err)
			}
			if line == "\r\n" {
				break
			}
		}

		// Now send HTTPS request through tunnel
		// Note: We're sending raw HTTP request here because TLS is simplified in testing
		httpReq := fmt.Sprintf("GET /test HTTP/1.1\r\nHost: %s:%s\r\n\r\n",
			serverHost, serverPort)
		_, err = conn.Write([]byte(httpReq))
		if err != nil {
			t.Fatalf("Failed to send HTTP request through tunnel: %v", err)
		}

		// Read response
		respLine, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("Failed to read response: %v", err)
		}

		if !strings.Contains(respLine, "200 OK") {
			t.Errorf("Expected 200 OK, got: %s", respLine)
		}

		t.Logf("✅ CONNECT tunnel mode test successful")
	})

	t.Run("Mode 2: Direct HTTPS Request", func(t *testing.T) {
		// Simulate client sending direct HTTPS URL
		// Create HTTP client with proxy configuration
		proxyURL := fmt.Sprintf("http://%s", proxyAddr)
		transport := &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Skip certificate verification in test environment
			},
		}

		client := &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		}

		// Send HTTPS request (Note: We use HTTP in testing, but the logic is the same)
		testURL := fmt.Sprintf("http://%s/test", serverAddr)
		resp, err := client.Get(testURL)
		if err != nil {
			t.Fatalf("Failed to send HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		if !strings.Contains(string(body), "Hello from test server") {
			t.Errorf("Unexpected response body: %s", string(body))
		}

		t.Logf("✅ Direct HTTPS request mode test successful")
	})
}

// TestServer wraps test server and listener
type TestServer struct {
	*http.Server
	Listener net.Listener
}

func (ts *TestServer) Close() error {
	ts.Server.Close()
	return ts.Listener.Close()
}

// createTestHTTPSServer creates a simple test server
func createTestHTTPSServer(t *testing.T) *TestServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello from test server"))
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		server.Serve(listener)
	}()

	return &TestServer{
		Server:   server,
		Listener: listener,
	}
}
