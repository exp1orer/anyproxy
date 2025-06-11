package client

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/common/connection"
	"github.com/buhuipao/anyproxy/pkg/common/message"
	"github.com/buhuipao/anyproxy/pkg/common/protocol"
	"github.com/buhuipao/anyproxy/pkg/config"
)

// mockMessageConnection implements transport.Connection for message testing
type mockMessageConnection struct {
	messages      []map[string]interface{}
	messageIndex  int
	writeMessages []map[string]interface{}
	readErr       error
	writeErr      error
	closed        bool
}

func (m *mockMessageConnection) ReadMessage() ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}
	return []byte("test"), nil
}

func (m *mockMessageConnection) WriteMessage(data []byte) error {
	return m.writeErr
}

func (m *mockMessageConnection) Close() error {
	m.closed = true
	return nil
}

func (m *mockMessageConnection) RemoteAddr() net.Addr {
	return mockAddr{network: "tcp", address: "mock:1234"}
}

func (m *mockMessageConnection) LocalAddr() net.Addr {
	return mockAddr{network: "tcp", address: "mock:5678"}
}

func (m *mockMessageConnection) GetClientID() string {
	return "test-client"
}

func (m *mockMessageConnection) GetGroupID() string {
	return "test-group"
}

func TestRouteMessage(t *testing.T) {
	tests := []struct {
		name                 string
		msg                  map[string]interface{}
		existingChannels     map[string]chan map[string]interface{}
		expectChannelCreated bool
		expectMessageRouted  bool
		fillChannel          bool
	}{
		{
			name: "route connect message",
			msg: map[string]interface{}{
				"type": protocol.MsgTypeConnect,
				"id":   "conn-1",
			},
			expectChannelCreated: true,
			expectMessageRouted:  true,
		},
		{
			name: "route data message to existing channel",
			msg: map[string]interface{}{
				"type": protocol.MsgTypeData,
				"id":   "conn-1",
				"data": []byte("test"),
			},
			existingChannels: map[string]chan map[string]interface{}{
				"conn-1": make(chan map[string]interface{}, 1),
			},
			expectMessageRouted: true,
		},
		{
			name: "route message without connection ID",
			msg: map[string]interface{}{
				"type": protocol.MsgTypeData,
			},
			expectMessageRouted: false,
		},
		{
			name: "route message to non-existent connection",
			msg: map[string]interface{}{
				"type": protocol.MsgTypeData,
				"id":   "unknown-conn",
				"data": []byte("test"),
			},
			expectMessageRouted: false,
		},
		{
			name: "route message to full channel",
			msg: map[string]interface{}{
				"type": protocol.MsgTypeData,
				"id":   "conn-1",
				"data": []byte("test"),
			},
			existingChannels: map[string]chan map[string]interface{}{
				"conn-1": make(chan map[string]interface{}, 1),
			},
			fillChannel: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				config: &config.ClientConfig{
					ClientID: "test-client",
				},
				connMgr: connection.NewManager("test-client"),
				ctx:     context.Background(),
			}

			// Set up existing channels
			if tt.existingChannels != nil {
				for connID := range tt.existingChannels {
					// Create channel through normal flow
					client.connMgr.CreateMessageChannel(connID, protocol.DefaultMessageChannelSize)
				}
			}

			// Fill channel if needed
			if tt.fillChannel {
				if connID, ok := tt.msg["id"].(string); ok {
					ch, exists := client.connMgr.GetMessageChannel(connID)
					if exists {
						ch <- map[string]interface{}{"dummy": "message"}
					}
				}
			}

			// Route message
			client.routeMessage(tt.msg)

			// Verify channel creation
			if connID, ok := tt.msg["id"].(string); ok {
				msgChan, hasChannel := client.connMgr.GetMessageChannel(connID)
				if tt.expectChannelCreated && !hasChannel {
					t.Error("Expected channel to be created")
				}

				// Verify message was routed
				if tt.expectMessageRouted && hasChannel && !tt.fillChannel {
					select {
					case receivedMsg := <-msgChan:
						if receivedMsg["type"] != tt.msg["type"] {
							t.Errorf("Routed message type mismatch: got %v, want %v",
								receivedMsg["type"], tt.msg["type"])
						}
					default:
						t.Error("Expected message to be routed but channel is empty")
					}
				}
			}
		})
	}
}

func TestHandleDataMessage(t *testing.T) {
	tests := []struct {
		name        string
		msg         map[string]interface{}
		hasConn     bool
		writeErr    error
		expectWrite bool
	}{
		{
			name: "successful data write with bytes",
			msg: map[string]interface{}{
				"id":   "conn-1",
				"data": []byte("test data"),
			},
			hasConn:     true,
			expectWrite: true,
		},
		{
			name: "successful data write with base64",
			msg: map[string]interface{}{
				"id":   "conn-1",
				"data": base64.StdEncoding.EncodeToString([]byte("test data")),
			},
			hasConn:     true,
			expectWrite: true,
		},
		{
			name: "missing connection ID",
			msg: map[string]interface{}{
				"data": []byte("test data"),
			},
			expectWrite: false,
		},
		{
			name: "invalid data format",
			msg: map[string]interface{}{
				"id":   "conn-1",
				"data": 12345, // Invalid type
			},
			hasConn:     true,
			expectWrite: false,
		},
		{
			name: "connection not found",
			msg: map[string]interface{}{
				"id":   "unknown-conn",
				"data": []byte("test data"),
			},
			hasConn:     false,
			expectWrite: false,
		},
		{
			name: "write error",
			msg: map[string]interface{}{
				"id":   "conn-1",
				"data": []byte("test data"),
			},
			hasConn:     true,
			writeErr:    errors.New("write error"),
			expectWrite: true,
		},
		{
			name: "large data write",
			msg: map[string]interface{}{
				"id":   "conn-1",
				"data": make([]byte, 20000), // Large data
			},
			hasConn:     true,
			expectWrite: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				config: &config.ClientConfig{
					ClientID: "test-client",
				},
				connMgr: connection.NewManager("test-client"),
				ctx:     context.Background(),
			}

			// Create mock connection if needed
			var mockConn *mockNetConnWithWrite
			if tt.hasConn {
				mockConn = &mockNetConnWithWrite{
					writeErr: tt.writeErr,
				}
				if connID, ok := tt.msg["id"].(string); ok {
					client.connMgr.AddConnection(connID, mockConn)
				}
			}

			// Handle data message
			client.handleDataMessage(tt.msg)

			// Verify write
			if mockConn != nil {
				if mockConn.writeCalled != tt.expectWrite {
					t.Errorf("Write called = %v, want %v", mockConn.writeCalled, tt.expectWrite)
				}
			}
		})
	}
}

// mockNetConnWithWrite extends mockNetConn with write tracking
type mockNetConnWithWrite struct {
	mockNetConn
	writeCalled bool
	writeErr    error
	writtenData []byte
}

func (m *mockNetConnWithWrite) Write(b []byte) (n int, err error) {
	m.writeCalled = true
	m.writtenData = b
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return len(b), nil
}

func TestHandleCloseMessage(t *testing.T) {
	tests := []struct {
		name           string
		msg            map[string]interface{}
		expectedConnID string
		hasConnection  bool
	}{
		{
			name: "valid close message",
			msg: map[string]interface{}{
				"id": "conn-1",
			},
			expectedConnID: "conn-1",
			hasConnection:  true,
		},
		{
			name:          "missing connection ID",
			msg:           map[string]interface{}{},
			hasConnection: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			client := &Client{
				config: &config.ClientConfig{
					ClientID: "test-client",
				},
				connMgr: connection.NewManager("test-client"),
			}

			// Add connection if needed
			if tt.hasConnection && tt.expectedConnID != "" {
				client.connMgr.AddConnection(tt.expectedConnID, &mockNetConn{id: tt.expectedConnID})
			}

			// Handle close message
			client.handleCloseMessage(tt.msg)

			// Verify connection was cleaned up
			if tt.hasConnection && tt.expectedConnID != "" {
				_, exists := client.connMgr.GetConnection(tt.expectedConnID)
				if exists {
					t.Error("Expected connection to be cleaned up")
				}
			}
		})
	}
}

func TestCreateMessageChannel(t *testing.T) {
	// Create client
	client := &Client{
		config: &config.ClientConfig{
			ClientID: "test-client",
		},
		connMgr: connection.NewManager("test-client"),
		ctx:     context.Background(),
		wg:      sync.WaitGroup{},
	}

	// Test creating new channel
	connID := "conn-1"
	client.createMessageChannel(connID)

	// Verify channel created
	_, exists := client.connMgr.GetMessageChannel(connID)
	if !exists {
		t.Error("Message channel not created")
	}

	// Test creating duplicate channel
	client.createMessageChannel(connID)

	// Should still have only one channel
	newChannelCount := client.connMgr.GetMessageChannelCount()
	if newChannelCount != 1 {
		t.Errorf("Expected 1 channel, got %d", newChannelCount)
	}
}

func TestProcessConnectionMessages(t *testing.T) {
	tests := []struct {
		name            string
		messages        []map[string]interface{}
		closeChannel    bool
		cancelContext   bool
		expectProcessed int
	}{
		{
			name: "process multiple messages",
			messages: []map[string]interface{}{
				{"type": protocol.MsgTypeConnect, "id": "conn-1"},
				{"type": protocol.MsgTypeData, "id": "conn-1", "data": []byte("test")},
				{"type": protocol.MsgTypeClose, "id": "conn-1"},
			},
			expectProcessed: 3,
		},
		{
			name: "channel closed",
			messages: []map[string]interface{}{
				{"type": protocol.MsgTypeData, "id": "conn-1", "data": []byte("test")},
			},
			closeChannel:    true,
			expectProcessed: 1,
		},
		{
			name: "context cancelled",
			messages: []map[string]interface{}{
				{"type": protocol.MsgTypeData, "id": "conn-1", "data": []byte("test")},
			},
			cancelContext:   true,
			expectProcessed: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create client
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			client := &Client{
				config: &config.ClientConfig{
					ClientID: "test-client",
				},
				ctx:     ctx,
				connMgr: connection.NewManager("test-client"),
			}

			// Create message channel
			msgChan := make(chan map[string]interface{}, len(tt.messages))

			// Add messages to channel
			for _, msg := range tt.messages {
				msgChan <- msg
			}

			// Cancel context if needed
			if tt.cancelContext {
				cancel()
			}

			// Close channel if needed
			if tt.closeChannel {
				time.AfterFunc(50*time.Millisecond, func() {
					close(msgChan)
				})
			}

			// Process messages
			done := make(chan struct{})
			go func() {
				defer close(done)
				client.processConnectionMessages("conn-1", msgChan)
			}()

			// Wait for completion
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
			}

			// Note: In a real test, we'd verify the actual side effects
			// For now, this test structure is here for future enhancement
		})
	}
}

func TestSendConnectResponse(t *testing.T) {
	tests := []struct {
		name      string
		connID    string
		success   bool
		errorMsg  string
		writeErr  error
		expectErr bool
	}{
		{
			name:      "successful response",
			connID:    "conn-1",
			success:   true,
			errorMsg:  "",
			expectErr: false,
		},
		{
			name:      "error response",
			connID:    "conn-1",
			success:   false,
			errorMsg:  "connection failed",
			expectErr: false,
		},
		{
			name:      "write error",
			connID:    "conn-1",
			success:   true,
			writeErr:  errors.New("write failed"),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			mockConn := &mockMessageConnection{
				writeErr: tt.writeErr,
			}

			// Create client
			client := &Client{
				config: &config.ClientConfig{
					ClientID: "test-client",
				},
				conn: mockConn,
			}
			// Initialize msgHandler
			client.msgHandler = message.NewClientExtendedMessageHandler(mockConn)

			// Send connect response
			err := client.sendConnectResponse(tt.connID, tt.success, tt.errorMsg)

			// Verify error
			if (err != nil) != tt.expectErr {
				t.Errorf("sendConnectResponse() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
