package gateway

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/message"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/protocol"
)

// Mock transport connection for message handler tests
type mockTransportConn struct {
	readData  []byte
	readErr   error
	writeData [][]byte
	writeErr  error
}

func (m *mockTransportConn) ReadMessage() ([]byte, error) {
	return m.readData, m.readErr
}

func (m *mockTransportConn) WriteMessage(data []byte) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.writeData = append(m.writeData, data)
	return nil
}

func (m *mockTransportConn) Read(p []byte) (n int, err error) {
	return 0, m.readErr
}

func (m *mockTransportConn) Write(p []byte) (n int, err error) {
	return len(p), m.writeErr
}

func (m *mockTransportConn) Close() error {
	return nil
}

func (m *mockTransportConn) LocalAddr() net.Addr {
	return mockAddr{network: "tcp", address: "127.0.0.1:8080"}
}

func (m *mockTransportConn) RemoteAddr() net.Addr {
	return mockAddr{network: "tcp", address: "127.0.0.1:12345"}
}

func (m *mockTransportConn) GetClientID() string {
	return "test-client"
}

func (m *mockTransportConn) GetGroupID() string {
	return "test-group"
}

func (m *mockTransportConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockTransportConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockTransportConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestReadNextMessage(t *testing.T) {
	client := &ClientConn{
		ID:      "test-client",
		GroupID: "test-group",
	}

	tests := []struct {
		name        string
		readData    []byte
		readErr     error
		wantErr     bool
		checkResult func(msg map[string]interface{}, err error)
	}{
		{
			name:     "non-binary message",
			readData: []byte(`{"type":"connect","id":"conn1","address":"example.com:80"}`),
			readErr:  nil,
			wantErr:  true,
		},
		{
			name:     "valid binary data message",
			readData: createBinaryDataMessage("conn1", []byte("test data")),
			readErr:  nil,
			wantErr:  false,
			checkResult: func(msg map[string]interface{}, err error) {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if msg["type"] != protocol.MsgTypeData {
					t.Errorf("expected type '%s', got %v", protocol.MsgTypeData, msg["type"])
				}
				if msg["id"] != "conn1" {
					t.Errorf("expected id 'conn1', got %v", msg["id"])
				}
				data, ok := msg["data"].([]byte)
				if !ok || !bytes.Equal(data, []byte("test data")) {
					t.Error("data mismatch")
				}
			},
		},
		{
			name:     "invalid binary message",
			readData: []byte{0xFF, 0xFF, 0xFF}, // Invalid magic bytes
			readErr:  nil,
			wantErr:  true,
		},
		{
			name:     "read error",
			readData: nil,
			readErr:  io.EOF,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockTransportConn{
				readData: tt.readData,
				readErr:  tt.readErr,
			}
			client.Conn = mockConn
			// Initialize msgHandler
			client.msgHandler = message.NewGatewayExtendedMessageHandler(mockConn)

			msg, err := client.readNextMessage()
			if (err != nil) != tt.wantErr {
				t.Errorf("readNextMessage() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkResult != nil {
				tt.checkResult(msg, err)
			}
		})
	}
}

func TestParseBinaryMessage(t *testing.T) {
	client := &ClientConn{
		ID:      "test-client",
		GroupID: "test-group",
	}

	tests := []struct {
		name        string
		msgData     []byte
		wantErr     bool
		checkResult func(msg map[string]interface{}, err error)
	}{
		{
			name:    "data message",
			msgData: createBinaryDataMessage("conn1", []byte("test data")),
			wantErr: false,
			checkResult: func(msg map[string]interface{}, err error) {
				if msg["type"] != protocol.MsgTypeData {
					t.Errorf("expected type '%s', got %v", protocol.MsgTypeData, msg["type"])
				}
				if msg["id"] != "conn1" {
					t.Errorf("expected id 'conn1', got %v", msg["id"])
				}
			},
		},
		{
			name:    "connect response message",
			msgData: createBinaryConnectResponseMessage("conn1", true, ""),
			wantErr: false,
			checkResult: func(msg map[string]interface{}, err error) {
				if msg["type"] != protocol.MsgTypeConnectResponse {
					t.Errorf("expected type '%s', got %v", protocol.MsgTypeConnectResponse, msg["type"])
				}
				if msg["success"] != true {
					t.Error("expected success true")
				}
			},
		},
		{
			name:    "close message",
			msgData: createBinaryCloseMessage("conn1"),
			wantErr: false,
			checkResult: func(msg map[string]interface{}, err error) {
				if msg["type"] != protocol.MsgTypeClose {
					t.Errorf("expected type '%s', got %v", protocol.MsgTypeClose, msg["type"])
				}
				if msg["id"] != "conn1" {
					t.Errorf("expected id 'conn1', got %v", msg["id"])
				}
			},
		},
		{
			name:    "invalid binary header",
			msgData: []byte{0xFF, 0xFF, 0xFF}, // Invalid magic bytes
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := &mockTransportConn{}
			client.Conn = mockConn
			// Initialize msgHandler
			client.msgHandler = message.NewGatewayExtendedMessageHandler(mockConn)

			msg, err := client.parseBinaryMessage(tt.msgData)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseBinaryMessage() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.checkResult != nil && err == nil {
				tt.checkResult(msg, err)
			}
		})
	}
}

func TestWriteMessages(t *testing.T) {
	client := &ClientConn{
		ID:      "test-client",
		GroupID: "test-group",
	}

	t.Run("writeDataMessage", func(t *testing.T) {
		mockConn := &mockTransportConn{}
		client.Conn = mockConn
		// Initialize msgHandler
		client.msgHandler = message.NewGatewayExtendedMessageHandler(mockConn)

		err := client.writeDataMessage("conn1", []byte("test data"))
		if err != nil {
			t.Fatalf("writeDataMessage failed: %v", err)
		}

		if len(mockConn.writeData) != 1 {
			t.Fatalf("expected 1 message written, got %d", len(mockConn.writeData))
		}

		// Verify it's a binary message
		if !protocol.IsBinaryMessage(mockConn.writeData[0]) {
			t.Error("expected binary message format")
		}
	})

	t.Run("writeConnectMessage", func(t *testing.T) {
		mockConn := &mockTransportConn{}
		client.Conn = mockConn
		// Initialize msgHandler
		client.msgHandler = message.NewGatewayExtendedMessageHandler(mockConn)

		err := client.writeConnectMessage("conn1", "tcp", "example.com:80")
		if err != nil {
			t.Fatalf("writeConnectMessage failed: %v", err)
		}

		if len(mockConn.writeData) != 1 {
			t.Fatalf("expected 1 message written, got %d", len(mockConn.writeData))
		}
	})

	t.Run("writeCloseMessage", func(t *testing.T) {
		mockConn := &mockTransportConn{}
		client.Conn = mockConn
		// Initialize msgHandler
		client.msgHandler = message.NewGatewayExtendedMessageHandler(mockConn)

		err := client.writeCloseMessage("conn1")
		if err != nil {
			t.Fatalf("writeCloseMessage failed: %v", err)
		}

		if len(mockConn.writeData) != 1 {
			t.Fatalf("expected 1 message written, got %d", len(mockConn.writeData))
		}
	})
}

// Helper functions to create binary messages
func createBinaryDataMessage(connID string, data []byte) []byte {
	return protocol.PackDataMessage(connID, data)
}

func createBinaryConnectResponseMessage(connID string, success bool, errorMsg string) []byte {
	return protocol.PackConnectResponseMessage(connID, success, errorMsg)
}

func createBinaryCloseMessage(connID string) []byte {
	return protocol.PackCloseMessage(connID)
}
