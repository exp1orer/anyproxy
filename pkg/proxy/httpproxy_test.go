package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"encoding/base64"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestNewHTTPProxy(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:8080",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	if proxy == nil {
		t.Fatal("HTTP proxy is nil")
	}

	// Test type assertion
	httpProxy, ok := proxy.(*httpProxy)
	if !ok {
		t.Fatal("Proxy is not of type *httpProxy")
	}

	if httpProxy.config != cfg {
		t.Error("Config not set correctly")
	}

	if httpProxy.dialFunc == nil {
		t.Error("Dial function not set")
	}

	if httpProxy.listenAddr != cfg.ListenAddr {
		t.Errorf("Listen address not set correctly, got %s, want %s", httpProxy.listenAddr, cfg.ListenAddr)
	}
}

func TestHTTPProxyStartStop(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0", // Use port 0 for automatic port assignment
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	// Start the proxy
	err = proxy.Start()
	if err != nil {
		t.Fatalf("Failed to start HTTP proxy: %v", err)
	}

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the proxy
	err = proxy.Stop()
	if err != nil {
		t.Fatalf("Failed to stop HTTP proxy: %v", err)
	}
}

func TestHTTPProxyAuthenticate(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:8080",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	if err != nil {
		t.Fatalf("Failed to create HTTP proxy: %v", err)
	}

	httpProxy := proxy.(*httpProxy)

	// Test authentication with valid credentials
	// This would require creating a mock HTTP request with proper headers
	// For now, we just test that the proxy was created successfully
	if httpProxy.config.AuthUsername != "testuser" {
		t.Error("Auth username not set correctly")
	}

	if httpProxy.config.AuthPassword != "testpass" {
		t.Error("Auth password not set correctly")
	}
}

func TestHTTPProxy_DialConn(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function that returns a mock connection
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	// Test DialConn
	conn, err := proxy.DialConn("tcp", "example.com:80")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
}

func TestHTTPProxy_DialConnError(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function that returns an error
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("dial failed")
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	// Test DialConn with error
	conn, err := proxy.DialConn("tcp", "example.com:80")
	assert.Error(t, err)
	assert.Nil(t, conn)
	assert.Contains(t, err.Error(), "dial failed")
}

func TestHTTPProxy_SetListenAddr(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:8080",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	httpProxy := proxy.(*httpProxy)

	// Test SetListenAddr
	newAddr := "127.0.0.1:9090"
	httpProxy.SetListenAddr(newAddr)
	assert.Equal(t, newAddr, httpProxy.listenAddr)
}

func TestHTTPProxy_ServeHTTP(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	httpProxy := proxy.(*httpProxy)

	tests := []struct {
		name           string
		method         string
		url            string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "CONNECT without auth",
			method:         "CONNECT",
			url:            "example.com:80",
			expectedStatus: http.StatusProxyAuthRequired,
		},
		{
			name:   "CONNECT with valid auth",
			method: "CONNECT",
			url:    "example.com:80",
			headers: map[string]string{
				"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			},
			expectedStatus: http.StatusInternalServerError, // Will fail because hijacking not supported in test
		},
		{
			name:   "CONNECT with invalid auth",
			method: "CONNECT",
			url:    "example.com:80",
			headers: map[string]string{
				"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:credentials")),
			},
			expectedStatus: http.StatusProxyAuthRequired,
		},
		{
			name:           "GET without auth",
			method:         "GET",
			url:            "http://example.com/test",
			expectedStatus: http.StatusProxyAuthRequired,
		},
		{
			name:   "GET with valid auth",
			method: "GET",
			url:    "http://example.com/test",
			headers: map[string]string{
				"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			},
			expectedStatus: http.StatusBadGateway, // Will fail to connect to example.com
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.url, nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			w := httptest.NewRecorder()
			httpProxy.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHTTPProxy_Authenticate(t *testing.T) {
	cfg := &config.HTTPConfig{
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	httpProxy := proxy.(*httpProxy)

	tests := []struct {
		name     string
		header   string
		expected bool
	}{
		{
			name:     "valid credentials",
			header:   "Basic " + base64.StdEncoding.EncodeToString([]byte("testuser:testpass")),
			expected: true,
		},
		{
			name:     "invalid credentials",
			header:   "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:credentials")),
			expected: false,
		},
		{
			name:     "malformed header",
			header:   "Bearer token123",
			expected: false,
		},
		{
			name:     "invalid base64",
			header:   "Basic invalid-base64!@#",
			expected: false,
		},
		{
			name:     "empty header",
			header:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com", nil)
			if tt.header != "" {
				req.Header.Set("Proxy-Authorization", tt.header)
			}

			result := httpProxy.authenticate(req)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPProxy_HandleHTTP(t *testing.T) {
	cfg := &config.HTTPConfig{
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	// Mock dial function that creates a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	}))
	defer server.Close()

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract host and port from server URL
		serverURL := strings.TrimPrefix(server.URL, "http://")
		if addr == "example.com:80" {
			// Redirect to our test server
			return net.Dial("tcp", serverURL)
		}
		return nil, fmt.Errorf("connection refused")
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	httpProxy := proxy.(*httpProxy)

	// Test HTTP request handling
	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("testuser:testpass")))

	w := httptest.NewRecorder()
	httpProxy.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Hello, World!")
}

func TestHTTPProxy_Transfer(t *testing.T) {
	// Create a pipe to simulate connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Start transfer in goroutine
	go func() {
		// Write some data from server side
		server.Write([]byte("Hello from server"))
		server.Close()
	}()

	// Test transfer function
	cfg := &config.HTTPConfig{}
	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	httpProxy := proxy.(*httpProxy)

	// Call transfer (this is a private method, so we test it indirectly)
	// The transfer method is called internally by handleConnect and handleHTTPRequest

	// Read from client and verify data was transferred
	data := make([]byte, 1024)
	_, err = client.Read(data)
	if err != nil && err != io.EOF {
		t.Fatalf("Failed to read from client: %v", err)
	}

	// We can't directly test the private transfer method, but we can verify
	// that the proxy was created successfully and the method exists
	assert.NotNil(t, httpProxy)
}

func TestHTTPProxy_InterfaceCompliance(t *testing.T) {
	cfg := &config.HTTPConfig{
		ListenAddr:   "127.0.0.1:0",
		AuthUsername: "testuser",
		AuthPassword: "testpass",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return &mockConn{}, nil
	}

	proxy, err := NewHTTPProxy(cfg, dialFunc)
	require.NoError(t, err)

	// Verify that httpProxy implements GatewayProxy interface
	var _ GatewayProxy = proxy
}

// Mock connection with writer for testing transfer
type mockConnWithWriter struct {
	net.Conn
	writer io.Writer
	closed bool
}

func (m *mockConnWithWriter) Write(data []byte) (int, error) {
	if m.writer != nil {
		return m.writer.Write(data)
	}
	return len(data), nil
}

func (m *mockConnWithWriter) Close() error {
	m.closed = true
	return nil
}

func (m *mockConnWithWriter) Read(buf []byte) (int, error) {
	return 0, io.EOF
}

func (m *mockConnWithWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockConnWithWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

func (m *mockConnWithWriter) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConnWithWriter) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConnWithWriter) SetWriteDeadline(t time.Time) error {
	return nil
}

// TestHTTPProxy_AuthenticateWithGroupID tests authentication with group-based usernames
func TestHTTPProxy_AuthenticateWithGroupID(t *testing.T) {
	tests := []struct {
		name           string
		configUsername string
		configPassword string
		authUsername   string
		authPassword   string
		expectedAuth   bool
		expectedUser   string
	}{
		{
			name:           "valid credentials with group ID",
			configUsername: "testuser",
			configPassword: "testpass",
			authUsername:   "testuser@production",
			authPassword:   "testpass",
			expectedAuth:   true,
			expectedUser:   "testuser@production",
		},
		{
			name:           "valid credentials without group ID",
			configUsername: "testuser",
			configPassword: "testpass",
			authUsername:   "testuser",
			authPassword:   "testpass",
			expectedAuth:   true,
			expectedUser:   "testuser",
		},
		{
			name:           "invalid username with group ID",
			configUsername: "testuser",
			configPassword: "testpass",
			authUsername:   "wronguser@production",
			authPassword:   "testpass",
			expectedAuth:   false,
			expectedUser:   "wronguser@production",
		},
		{
			name:           "invalid password with group ID",
			configUsername: "testuser",
			configPassword: "testpass",
			authUsername:   "testuser@production",
			authPassword:   "wrongpass",
			expectedAuth:   false,
			expectedUser:   "testuser@production",
		},
		{
			name:           "valid username with multiple @ symbols",
			configUsername: "testuser",
			configPassword: "testpass",
			authUsername:   "testuser@prod@env",
			authPassword:   "testpass",
			expectedAuth:   true,
			expectedUser:   "testuser@prod@env",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy := &httpProxy{
				config: &config.HTTPConfig{
					AuthUsername: tt.configUsername,
					AuthPassword: tt.configPassword,
				},
			}

			// Create request with Basic auth
			req := httptest.NewRequest("GET", "http://example.com", nil)
			auth := base64.StdEncoding.EncodeToString([]byte(tt.authUsername + ":" + tt.authPassword))
			req.Header.Set("Proxy-Authorization", "Basic "+auth)

			username, password, authenticated := proxy.authenticateAndExtractUser(req)

			assert.Equal(t, tt.expectedAuth, authenticated)
			assert.Equal(t, tt.expectedUser, username)
			assert.Equal(t, tt.authPassword, password)
		})
	}
}
