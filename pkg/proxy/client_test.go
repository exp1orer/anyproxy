package proxy

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name   string
		config *config.ClientConfig
	}{
		{
			name: "valid config",
			config: &config.ClientConfig{
				ClientID:       "test-client",
				GatewayAddr:    "localhost:8080",
				AuthUsername:   "user",
				AuthPassword:   "pass",
				ForbiddenHosts: []string{"forbidden.com"},
				GatewayTLSCert: "",
			},
		},
		{
			name: "config with TLS cert",
			config: &config.ClientConfig{
				ClientID:       "test-client-tls",
				GatewayAddr:    "localhost:8443",
				AuthUsername:   "user",
				AuthPassword:   "pass",
				ForbiddenHosts: []string{},
				GatewayTLSCert: "/path/to/cert.pem",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			require.NoError(t, err)
			require.NotNil(t, client)

			assert.Equal(t, tt.config, client.config)
			assert.NotNil(t, client.conns)
			assert.NotNil(t, client.msgChans)
			assert.NotNil(t, client.ctx)
			assert.NotNil(t, client.writeBuf)
			assert.Equal(t, writeBufSize, cap(client.writeBuf))
		})
	}
}

func TestProxyClient_GenerateClientID(t *testing.T) {
	config := &config.ClientConfig{
		ClientID: "test-client",
	}
	client, err := NewClient(config)
	require.NoError(t, err)

	id1 := client.generateClientID()
	id2 := client.generateClientID()

	assert.True(t, strings.HasPrefix(id1, "test-client-"))
	assert.True(t, strings.HasPrefix(id2, "test-client-"))
	assert.NotEqual(t, id1, id2) // Should be unique
}

func TestProxyClient_IsConnectionAllowed(t *testing.T) {
	config := &config.ClientConfig{
		ForbiddenHosts: []string{"forbidden.com", "blocked.net"},
	}
	client, err := NewClient(config)
	require.NoError(t, err)

	tests := []struct {
		name     string
		address  string
		expected bool
	}{
		{
			name:     "allowed host",
			address:  "google.com:80",
			expected: true,
		},
		{
			name:     "forbidden host",
			address:  "forbidden.com:80",
			expected: false,
		},
		{
			name:     "blocked host",
			address:  "blocked.net:443",
			expected: false,
		},
		{
			name:     "subdomain of forbidden host",
			address:  "sub.forbidden.com:80",
			expected: false, // This ends with "forbidden.com" so should be blocked
		},
		{
			name:     "host without port",
			address:  "allowed.com",
			expected: true,
		},
		{
			name:     "forbidden host without port",
			address:  "forbidden.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.isConnectionAllowed(tt.address)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestProxyClient_CreateTLSConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.ClientConfig
		expectError bool
	}{
		{
			name: "no TLS cert",
			config: &config.ClientConfig{
				GatewayAddr: "example.com:8080",
			},
			expectError: false,
		},
		{
			name: "invalid TLS cert path",
			config: &config.ClientConfig{
				GatewayAddr:    "example.com:8080",
				GatewayTLSCert: "/nonexistent/cert.pem",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			require.NoError(t, err)

			tlsConfig, err := client.createTLSConfig()
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, tlsConfig)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tlsConfig)
				assert.Equal(t, "example.com", tlsConfig.ServerName)
			}
		})
	}
}

func TestProxyClient_CloseAllConnections(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	// Create mock connections
	mockConn1 := &mockConn{closed: false}
	mockConn2 := &mockConn{closed: false}

	client.conns["conn1"] = mockConn1
	client.conns["conn2"] = mockConn2

	client.closeAllConnections()

	assert.True(t, mockConn1.closed)
	assert.True(t, mockConn2.closed)
	assert.Empty(t, client.conns)
}

func TestProxyClient_CleanupConnection(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	// Setup connection and message channel
	mockConn := &mockConn{closed: false}
	client.conns[TestConnID] = mockConn
	client.msgChans[TestConnID] = make(chan map[string]interface{}, 1)

	client.cleanupConnection(TestConnID)

	// Verify connection was removed
	assert.NotContains(t, client.conns, TestConnID)
	assert.NotContains(t, client.msgChans, TestConnID)
}

func TestProxyClient_RouteMessage(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	tests := []struct {
		name    string
		msg     map[string]interface{}
		setup   func()
		wantLog bool
	}{
		{
			name: "valid connect message",
			msg: map[string]interface{}{
				"type": "connect",
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

func TestProxyClient_HandleDataMessage(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	// Setup mock connection
	mockConn := &mockConn{writeData: make([]byte, 0)}
	client.conns[TestConnID] = mockConn

	tests := []struct {
		name    string
		msg     map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid data message",
			msg: map[string]interface{}{
				"id":   TestConnID,
				"data": base64.StdEncoding.EncodeToString([]byte("hello world")),
			},
			wantErr: false,
		},
		{
			name: "invalid connection ID",
			msg: map[string]interface{}{
				"data": base64.StdEncoding.EncodeToString([]byte("hello")),
			},
			wantErr: true,
		},
		{
			name: "invalid data format",
			msg: map[string]interface{}{
				"id":   TestConnID,
				"data": 123, // not a string
			},
			wantErr: true,
		},
		{
			name: "invalid base64 data",
			msg: map[string]interface{}{
				"id":   TestConnID,
				"data": "invalid-base64!@#",
			},
			wantErr: true,
		},
		{
			name: "unknown connection",
			msg: map[string]interface{}{
				"id":   "unknown-conn",
				"data": base64.StdEncoding.EncodeToString([]byte("hello")),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.handleDataMessage(tt.msg)

			if !tt.wantErr && tt.msg["id"] == TestConnID {
				expectedData, _ := base64.StdEncoding.DecodeString(tt.msg["data"].(string))
				assert.Equal(t, expectedData, mockConn.writeData)
			}
		})
	}
}

func TestProxyClient_HandleCloseMessage(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	// Setup mock connection
	mockConn := &mockConn{closed: false}
	client.conns[TestConnID] = mockConn
	client.msgChans[TestConnID] = make(chan map[string]interface{}, 1)

	tests := []struct {
		name string
		msg  map[string]interface{}
	}{
		{
			name: "valid close message",
			msg: map[string]interface{}{
				"id": TestConnID,
			},
		},
		{
			name: "invalid connection ID",
			msg:  map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.handleCloseMessage(tt.msg)

			if tt.msg["id"] == TestConnID {
				assert.True(t, mockConn.closed)
				assert.NotContains(t, client.conns, TestConnID)
			}
		})
	}
}

// TestProxyClient_SendConnectResponse tests the sendConnectResponse method
// Note: This test is simplified due to the complexity of mocking WebSocketWriter
func TestProxyClient_SendConnectResponse(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	// Test that sendConnectResponse panics when writer is nil (expected behavior)
	assert.Panics(t, func() {
		_ = client.sendConnectResponse(TestConnID, true, "")
	})
}

// Mock implementations for testing

// WebSocketWriterInterface defines the interface for WebSocket writers
type WebSocketWriterInterface interface {
	WriteJSON(v interface{}) error
	Start()
	Stop()
}

type mockConn struct {
	net.Conn
	closed    bool
	writeData []byte
	readData  []byte
	readPos   int
	writeErr  error
	readErr   error
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) Write(data []byte) (int, error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, data...)
	return len(data), nil
}

func (m *mockConn) Read(buf []byte) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.readData) {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(buf, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}
}

func (m *mockConn) SetDeadline(_ time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// Integration test with mock WebSocket server
func TestProxyClient_Integration(t *testing.T) {
	// Create a mock WebSocket server
	upgrader := websocket.Upgrader{
		CheckOrigin: func(_ *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Failed to upgrade connection: %v", err)
			return
		}
		defer func() {
			if closeErr := conn.Close(); closeErr != nil {
				t.Logf("Error closing connection: %v", closeErr)
			}
		}()

		// Echo messages back
		for {
			var msg map[string]interface{}
			err := conn.ReadJSON(&msg)
			if err != nil {
				break
			}
			if writeErr := conn.WriteJSON(msg); writeErr != nil {
				t.Logf("Error writing JSON: %v", writeErr)
				break
			}
		}
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	config := &config.ClientConfig{
		ClientID:     "test-client",
		GatewayAddr:  strings.TrimPrefix(wsURL, "ws://"),
		AuthUsername: "user",
		AuthPassword: "pass",
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Test that client can be created and stopped without starting
	err = client.Stop()
	assert.NoError(t, err)
}

func TestProxyClient_StartStop(t *testing.T) {
	config := &config.ClientConfig{
		ClientID:     "test-client",
		GatewayAddr:  "nonexistent:8080", // Will fail to connect
		AuthUsername: "user",
		AuthPassword: "pass",
	}

	client, err := NewClient(config)
	require.NoError(t, err)

	// Start the client (will fail to connect but shouldn't error)
	err = client.Start()
	assert.NoError(t, err)

	// Give it a moment to attempt connection
	time.Sleep(100 * time.Millisecond)

	// Stop the client
	err = client.Stop()
	assert.NoError(t, err)
}

func TestProxyClient_CreateMessageChannel(t *testing.T) {
	client, err := NewClient(&config.ClientConfig{})
	require.NoError(t, err)

	connID := TestConnID
	client.createMessageChannel(connID)

	client.msgChansMu.RLock()
	msgChan, exists := client.msgChans[connID]
	client.msgChansMu.RUnlock()

	assert.True(t, exists)
	assert.NotNil(t, msgChan)
	assert.Equal(t, 100, cap(msgChan))

	// Cleanup
	client.cancel()
	time.Sleep(10 * time.Millisecond) // Give goroutine time to exit
}
