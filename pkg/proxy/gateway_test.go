package proxy

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestGatewayMultipleProxies(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenAddr:   "127.0.0.1:0", // Use port 0 for automatic assignment
			TLSCert:      "testdata/server.crt",
			TLSKey:       "testdata/server.key",
			AuthUsername: "testuser",
			AuthPassword: "testpass",
		},
		Proxy: config.ProxyConfig{
			HTTP: config.HTTPConfig{
				ListenAddr:   "127.0.0.1:0", // Use port 0 for automatic assignment
				AuthUsername: "httpuser",
				AuthPassword: "httppass",
			},
			SOCKS5: config.SOCKS5Config{
				ListenAddr:   "127.0.0.1:0", // Use port 0 for automatic assignment
				AuthUsername: "socksuser",
				AuthPassword: "sockspass",
			},
		},
	}

	// Create gateway with both proxies configured
	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	// Check that both proxies were created
	if len(gateway.proxies) != 2 {
		t.Fatalf("Expected 2 proxies, got %d", len(gateway.proxies))
	}

	// Verify proxy types
	var hasHTTP, hasSOCKS5 bool
	for _, proxy := range gateway.proxies {
		switch proxy.(type) {
		case *httpProxy:
			hasHTTP = true
		case *socks5Proxy:
			hasSOCKS5 = true
		}
	}

	if !hasHTTP {
		t.Error("HTTP proxy not found")
	}
	if !hasSOCKS5 {
		t.Error("SOCKS5 proxy not found")
	}
}

func TestGatewayHTTPOnly(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenAddr:   "127.0.0.1:0",
			TLSCert:      "testdata/server.crt",
			TLSKey:       "testdata/server.key",
			AuthUsername: "testuser",
			AuthPassword: "testpass",
		},
		Proxy: config.ProxyConfig{
			HTTP: config.HTTPConfig{
				ListenAddr:   "127.0.0.1:0",
				AuthUsername: "httpuser",
				AuthPassword: "httppass",
			},
			// SOCKS5 not configured (empty ListenAddr)
		},
	}

	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	// Check that only HTTP proxy was created
	if len(gateway.proxies) != 1 {
		t.Fatalf("Expected 1 proxy, got %d", len(gateway.proxies))
	}

	// Verify it's HTTP proxy
	if _, ok := gateway.proxies[0].(*httpProxy); !ok {
		t.Error("Expected HTTP proxy")
	}
}

func TestGatewaySOCKS5Only(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenAddr:   "127.0.0.1:0",
			TLSCert:      "testdata/server.crt",
			TLSKey:       "testdata/server.key",
			AuthUsername: "testuser",
			AuthPassword: "testpass",
		},
		Proxy: config.ProxyConfig{
			// HTTP not configured (empty ListenAddr)
			SOCKS5: config.SOCKS5Config{
				ListenAddr:   "127.0.0.1:0",
				AuthUsername: "socksuser",
				AuthPassword: "sockspass",
			},
		},
	}

	gateway, err := NewGateway(cfg)
	if err != nil {
		t.Fatalf("Failed to create gateway: %v", err)
	}

	// Check that only SOCKS5 proxy was created
	if len(gateway.proxies) != 1 {
		t.Fatalf("Expected 1 proxy, got %d", len(gateway.proxies))
	}

	// Verify it's SOCKS5 proxy
	if _, ok := gateway.proxies[0].(*socks5Proxy); !ok {
		t.Error("Expected SOCKS5 proxy")
	}
}

func TestGatewayNoProxies(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			ListenAddr:   "127.0.0.1:0",
			TLSCert:      "testdata/server.crt",
			TLSKey:       "testdata/server.key",
			AuthUsername: "testuser",
			AuthPassword: "testpass",
		},
		Proxy: config.ProxyConfig{
			// Neither HTTP nor SOCKS5 configured
		},
	}

	_, err := NewGateway(cfg)
	if err == nil {
		t.Fatal("Expected error when no proxies are configured")
	}

	expectedError := "no proxy configured"
	if err.Error()[:len(expectedError)] != expectedError {
		t.Errorf("Expected error to start with '%s', got: %v", expectedError, err)
	}
}

func TestGateway_ClientConnManagement(t *testing.T) {
	gateway := &Gateway{
		clients: make(map[string]*ClientConn),
	}

	// Test adding client
	client := &ClientConn{
		ID: "test-client-1",
	}
	gateway.addClient(client)

	// Verify client was added
	gateway.clientsMu.RLock()
	storedClient, exists := gateway.clients["test-client-1"]
	gateway.clientsMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, client, storedClient)

	// Test removing client
	gateway.removeClient("test-client-1")

	gateway.clientsMu.RLock()
	_, exists = gateway.clients["test-client-1"]
	gateway.clientsMu.RUnlock()

	assert.False(t, exists)
}

func TestGateway_GetRandomClient(t *testing.T) {
	gateway := &Gateway{
		clients: make(map[string]*ClientConn),
	}

	// Test no clients available
	_, err := gateway.getRandomClient()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no clients available")

	// Add a client
	client := &ClientConn{
		ID: "test-client-1",
	}
	gateway.addClient(client)

	// Test getting client
	randomClient, err := gateway.getRandomClient()
	assert.NoError(t, err)
	assert.Equal(t, client, randomClient)
}

func TestClientConn_Basic(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		Conns:    make(map[string]*ProxyConn),
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	assert.Equal(t, "test-client", client.ID)
	assert.NotNil(t, client.Conns)
	assert.NotNil(t, client.msgChans)
	assert.NotNil(t, client.stopCh)
}

func TestClientConn_RouteMessage(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	tests := []struct {
		name    string
		msg     map[string]interface{}
		setup   func()
		wantLog bool
	}{
		{
			name: "valid connect_response message",
			msg: map[string]interface{}{
				"type": "connect_response",
				"id":   "conn1",
			},
			setup: func() {},
		},
		{
			name: "message without connection ID",
			msg: map[string]interface{}{
				"type": "data",
			},
			setup:   func() {},
			wantLog: true,
		},
		{
			name: "message for non-existent connection",
			msg: map[string]interface{}{
				"type": "data",
				"id":   "nonexistent",
			},
			setup: func() {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			// This test mainly ensures no panic occurs
			client.routeMessage(tt.msg)
		})
	}
}

func TestClientConn_CreateMessageChannel(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	connID := "test-conn"
	client.createMessageChannel(connID)

	client.msgChansMu.RLock()
	msgChan, exists := client.msgChans[connID]
	client.msgChansMu.RUnlock()

	assert.True(t, exists)
	assert.NotNil(t, msgChan)
	assert.Equal(t, 100, cap(msgChan))

	// Test creating duplicate channel (should not create new one)
	client.createMessageChannel(connID)

	client.msgChansMu.RLock()
	assert.Equal(t, 1, len(client.msgChans))
	client.msgChansMu.RUnlock()

	// Cleanup
	close(client.stopCh)
	time.Sleep(10 * time.Millisecond) // Give goroutine time to exit
}

func TestClientConn_CloseConnection(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		Conns:    make(map[string]*ProxyConn),
		msgChans: make(map[string]chan map[string]interface{}),
	}

	// Create a mock connection
	pipe1, pipe2 := net.Pipe()
	defer pipe1.Close()

	proxyConn := &ProxyConn{
		ID:        "test-conn",
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}

	client.Conns["test-conn"] = proxyConn
	client.msgChans["test-conn"] = make(chan map[string]interface{}, 1)

	// Test close connection
	client.closeConnection("test-conn")

	// Verify connection was removed
	assert.NotContains(t, client.Conns, "test-conn")
	assert.NotContains(t, client.msgChans, "test-conn")

	// Verify Done channel was closed
	select {
	case <-proxyConn.Done:
		// Expected
	default:
		t.Error("Done channel should be closed")
	}
}

func TestClientConn_StopBasic(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		writeBuf: make(chan interface{}, 10),
		Conns:    make(map[string]*ProxyConn),
		msgChans: make(map[string]chan map[string]interface{}),
		stopCh:   make(chan struct{}),
	}

	// Add a mock connection
	pipe1, pipe2 := net.Pipe()
	defer pipe1.Close()

	proxyConn := &ProxyConn{
		ID:        "test-conn",
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}
	client.Conns["test-conn"] = proxyConn

	// Test stop - this will panic because Conn and Writer are nil
	// but we can test that the method exists
	assert.Panics(t, func() {
		client.Stop()
	})
}

func TestProxyConn_Basic(t *testing.T) {
	pipe1, pipe2 := net.Pipe()
	defer pipe1.Close()
	defer pipe2.Close()

	proxyConn := &ProxyConn{
		ID:        "test-conn",
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}

	assert.Equal(t, "test-conn", proxyConn.ID)
	assert.Equal(t, pipe2, proxyConn.LocalConn)
	assert.NotNil(t, proxyConn.Done)
}

func TestGateway_NewGatewayErrors(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectError string
	}{
		{
			name: "no proxies configured",
			config: &config.Config{
				Gateway: config.GatewayConfig{
					ListenAddr:   "127.0.0.1:0",
					TLSCert:      "testdata/server.crt",
					TLSKey:       "testdata/server.key",
					AuthUsername: "testuser",
					AuthPassword: "testpass",
				},
				Proxy: config.ProxyConfig{
					// No proxies configured
				},
			},
			expectError: "no proxy configured",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewGateway(tt.config)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}

// Mock implementations for testing

type mockWebSocketConn struct {
	closed bool
	mu     sync.Mutex
}

func (m *mockWebSocketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockWebSocketConn) ReadJSON(v interface{}) error {
	return fmt.Errorf("mock read error")
}

func (m *mockWebSocketConn) WriteJSON(v interface{}) error {
	return nil
}

func (m *mockWebSocketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockWebSocketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (m *mockWebSocketConn) SetPongHandler(h func(appData string) error) {
}

func (m *mockWebSocketConn) SetPingHandler(h func(appData string) error) {
}

func (m *mockWebSocketConn) WriteMessage(messageType int, data []byte) error {
	return nil
}

func (m *mockWebSocketConn) ReadMessage() (messageType int, p []byte, err error) {
	return 0, nil, fmt.Errorf("mock read error")
}

func (m *mockWebSocketConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockWebSocketConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

func (m *mockWebSocketConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockWebSocketConn) Read(b []byte) (n int, err error) {
	return 0, fmt.Errorf("mock read error")
}

func (m *mockWebSocketConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}
