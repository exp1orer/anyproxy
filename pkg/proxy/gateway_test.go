package proxy

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/buhuipao/anyproxy/pkg/config"
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
		clients:        make(map[string]*ClientConn),
		groups:         make(map[string]map[string]struct{}),
		portForwardMgr: NewPortForwardManager(),
	}
	// Initialize the default group
	gateway.groups[""] = make(map[string]struct{})

	// Test adding client
	client := &ClientConn{
		ID:      "test-client-1",
		GroupID: "", // Default group
	}
	gateway.addClient(client)

	// Verify client was added
	gateway.clientsMu.RLock()
	storedClient, exists := gateway.clients["test-client-1"]
	gateway.clientsMu.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, client, storedClient)

	// Verify client was added to group
	gateway.clientsMu.RLock()
	_, groupExists := gateway.groups[""]["test-client-1"]
	gateway.clientsMu.RUnlock()
	assert.True(t, groupExists)

	// Test removing client
	gateway.removeClient("test-client-1")

	gateway.clientsMu.RLock()
	_, exists = gateway.clients["test-client-1"]
	_, groupExists = gateway.groups[""]["test-client-1"]
	gateway.clientsMu.RUnlock()

	assert.False(t, exists)
	assert.False(t, groupExists)
}

func TestGateway_GetRandomClient(t *testing.T) {
	gateway := &Gateway{
		clients:        make(map[string]*ClientConn),
		groups:         make(map[string]map[string]struct{}),
		portForwardMgr: NewPortForwardManager(),
	}
	// Initialize the default group
	gateway.groups[""] = make(map[string]struct{})

	// Test no clients available
	_, err := gateway.getClientByGroup("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no clients available")

	// Add a client
	client := &ClientConn{
		ID:      "test-client-1",
		GroupID: "", // Default group
	}
	gateway.addClient(client)

	// Test getting client
	randomClient, err := gateway.getClientByGroup("")
	assert.NoError(t, err)
	assert.Equal(t, client, randomClient)
}

func TestClientConn_Basic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &ClientConn{
		ID:       "test-client",
		Conns:    make(map[string]*Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	assert.Equal(t, "test-client", client.ID)
	assert.NotNil(t, client.Conns)
	assert.NotNil(t, client.msgChans)
	assert.NotNil(t, client.ctx)
}

func TestClientConn_RouteMessage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &ClientConn{
		ID:       "test-client",
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
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
		t.Run(tt.name, func(_ *testing.T) {
			tt.setup()
			// This test mainly ensures no panic occurs
			client.routeMessage(tt.msg)
		})
	}
}

func TestClientConn_CreateMessageChannel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &ClientConn{
		ID:       "test-client",
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
	}

	connID := TestConnID
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
	cancel()
	time.Sleep(10 * time.Millisecond) // Give goroutine time to exit
}

func TestClientConn_CloseConnection(t *testing.T) {
	client := &ClientConn{
		ID:       "test-client",
		Conns:    make(map[string]*Conn),
		msgChans: make(map[string]chan map[string]interface{}),
	}

	// Create a mock connection
	pipe1, pipe2 := net.Pipe()
	defer func() {
		if err := pipe1.Close(); err != nil {
			t.Logf("Error closing pipe1: %v", err)
		}
	}()

	proxyConn := &Conn{
		ID:        TestConnID,
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}

	client.Conns[TestConnID] = proxyConn
	client.msgChans[TestConnID] = make(chan map[string]interface{}, 1)

	// Test close connection
	client.closeConnection(TestConnID)

	// Verify connection was removed
	assert.NotContains(t, client.Conns, TestConnID)
	assert.NotContains(t, client.msgChans, TestConnID)

	// Verify Done channel was closed
	select {
	case <-proxyConn.Done:
		// Expected
	default:
		t.Error("Done channel should be closed")
	}
}

func TestClientConn_StopBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &ClientConn{
		ID:       "test-client",
		writeBuf: make(chan interface{}, 10),
		Conns:    make(map[string]*Conn),
		msgChans: make(map[string]chan map[string]interface{}),
		ctx:      ctx,
		cancel:   cancel,
		stopOnce: sync.Once{}, // Initialize stopOnce
	}

	// Add a mock connection
	pipe1, pipe2 := net.Pipe()
	defer func() {
		if err := pipe1.Close(); err != nil {
			t.Logf("Error closing pipe1: %v", err)
		}
	}()

	proxyConn := &Conn{
		ID:        TestConnID,
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}
	client.Conns[TestConnID] = proxyConn

	// Test stop - this should no longer panic with our improved error handling
	// The new implementation safely handles nil Conn and Writer
	assert.NotPanics(t, func() {
		client.Stop()
	})

	// Verify that connections were properly cleaned up
	assert.Empty(t, client.Conns, "All connections should be cleaned up")
	assert.Empty(t, client.msgChans, "All message channels should be cleaned up")
}

func TestProxyConn_Basic(t *testing.T) {
	pipe1, pipe2 := net.Pipe()
	defer func() {
		if err := pipe1.Close(); err != nil {
			t.Logf("Error closing pipe1: %v", err)
		}
	}()
	defer func() {
		if err := pipe2.Close(); err != nil {
			t.Logf("Error closing pipe2: %v", err)
		}
	}()

	proxyConn := &Conn{
		ID:        TestConnID,
		LocalConn: pipe2,
		Done:      make(chan struct{}),
	}

	assert.Equal(t, TestConnID, proxyConn.ID)
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
