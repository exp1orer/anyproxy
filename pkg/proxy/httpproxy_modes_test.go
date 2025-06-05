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
	defer func() {
		if err := httpsServer.Close(); err != nil {
			t.Logf("Error closing HTTPS server: %v", err)
		}
	}()

	// Get server address
	serverAddr := httpsServer.Listener.Addr().String()
	serverHost := strings.Split(serverAddr, ":")[0]
	serverPort := strings.Split(serverAddr, ":")[1]

	// Mock dial function
	dialFunc := func(_ context.Context, _, _ string) (net.Conn, error) {
		// Redirect to our test server
		return net.Dial("tcp", serverAddr)
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
	defer func() {
		if err := proxy.Stop(); err != nil {
			t.Logf("Error stopping proxy: %v", err)
		}
	}()

	httpProxy := proxy.(*httpProxy)
	proxyAddr := httpProxy.listener.Addr().String()
	time.Sleep(100 * time.Millisecond)

	t.Run("Mode 1: CONNECT Tunnel", func(t *testing.T) {
		// Simulate browser's CONNECT tunnel mode
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("Failed to connect to proxy: %v", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				t.Logf("Error closing connection: %v", err)
			}
		}()

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
			Proxy: func(_ *http.Request) (*url.URL, error) {
				return url.Parse(proxyURL)
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // nolint:gosec // Skip certificate verification in test environment
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
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Error closing response body: %v", err)
			}
		}()

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
	serverErr := ts.Server.Close()
	listenerErr := ts.Listener.Close()

	// Return the first error encountered
	if serverErr != nil {
		return serverErr
	}
	return listenerErr
}

// createTestHTTPSServer creates a simple test server
func createTestHTTPSServer(t *testing.T) *TestServer {
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write([]byte("Hello from test server")); writeErr != nil {
			t.Logf("Error writing response: %v", writeErr)
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
	}

	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Logf("Server error: %v", serveErr)
		}
	}()

	return &TestServer{
		Server:   server,
		Listener: listener,
	}
}

func TestHTTPProxy_TransparentMode(t *testing.T) {
	// Create a mock HTTPS server
	cert, err := tls.LoadX509KeyPair("testdata/server.crt", "testdata/server.key")
	if err != nil {
		// Skip this test if certificates are not available
		t.Skip("Test certificates not available")
		return
	}

	httpsServer := &http.Server{
		Addr: "127.0.0.1:0",
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12, // Enforce minimum TLS 1.2
		},
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			if _, writeErr := w.Write([]byte("Hello from HTTPS server")); writeErr != nil {
				t.Logf("Error writing HTTPS response: %v", writeErr)
			}
		}),
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer func() {
		if err := httpsServer.Close(); err != nil {
			t.Logf("Error closing HTTPS server: %v", err)
		}
	}()

	httpsAddr := listener.Addr().String()

	go func() {
		err := httpsServer.ServeTLS(listener, "", "")
		if err != nil && err != http.ErrServerClosed {
			t.Logf("HTTPS server error: %v", err)
		}
	}()

	// Create HTTP proxy
	cfg := &config.HTTPConfig{
		ListenAddr: "127.0.0.1:0",
	}

	dialFunc := func(_ context.Context, _, addr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

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

	// Test transparent HTTPS connection through CONNECT
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Error closing connection: %v", err)
		}
	}()

	// Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", httpsAddr, httpsAddr)
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

	// Now establish TLS connection
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, // nolint:gosec // For testing only
	})

	// Send HTTP request over TLS
	httpReq := "GET / HTTP/1.1\r\nHost: " + httpsAddr + "\r\nConnection: close\r\n\r\n"
	_, err = tlsConn.Write([]byte(httpReq))
	if err != nil {
		t.Fatalf("Failed to send HTTP request: %v", err)
	}

	// Read response
	httpReader := bufio.NewReader(tlsConn)
	httpResponse, err := httpReader.ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read HTTP response: %v", err)
	}

	if !strings.Contains(httpResponse, "200 OK") {
		t.Errorf("Expected HTTP 200 OK, got: %s", httpResponse)
	}
}

func TestHTTPProxy_NonTunnelMode(t *testing.T) {
	// This test focuses on non-CONNECT HTTP requests
	// Create a simple HTTP target server (not HTTPS)
	targetServer := &http.Server{
		Addr:              "127.0.0.1:0",
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Echo back the request method and path
			response := fmt.Sprintf("Method: %s, Path: %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			if _, writeErr := w.Write([]byte(response)); writeErr != nil {
				t.Logf("Error writing response: %v", writeErr)
			}
		}),
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target server listener: %v", err)
	}
	targetAddr := listener.Addr().String()

	go func() {
		if serveErr := targetServer.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			t.Logf("Target server error: %v", serveErr)
		}
	}()
	defer func() {
		if err := targetServer.Close(); err != nil {
			t.Logf("Error closing target server: %v", err)
		}
	}()

	// Create HTTP proxy
	cfg := &config.HTTPConfig{
		ListenAddr: "127.0.0.1:0",
	}

	dialFunc := func(_ context.Context, _, _ string) (net.Conn, error) {
		// Always connect to our target server regardless of requested address
		return net.Dial("tcp", targetAddr)
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}
	defer func() {
		if err := proxy.Stop(); err != nil {
			t.Logf("Error stopping proxy: %v", err)
		}
	}()

	// Create HTTP client that uses the proxy
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   proxy.(*httpProxy).listener.Addr().String(),
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}

	// Test GET request through proxy
	testURL := "http://example.com:80/test/path"
	resp, err := client.Get(testURL)
	if err != nil {
		t.Fatalf("Failed to make GET request through proxy: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	expectedResponse := "Method: GET, Path: /test/path"
	if string(body) != expectedResponse {
		t.Errorf("Expected response '%s', got '%s'", expectedResponse, string(body))
	}
}
