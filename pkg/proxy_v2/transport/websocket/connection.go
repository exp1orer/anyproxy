package websocket

import (
	"net"

	"github.com/gorilla/websocket"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

const (
	writeBufSize = 1000 // Same buffer size as v1
)

// webSocketConnectionWithInfo WebSocket connection implementation with client information and high-performance writing (🆕 integrates v1 performance optimizations)
type webSocketConnectionWithInfo struct {
	conn     *websocket.Conn
	clientID string
	groupID  string
	writer   *Writer          // 🆕 Integrated high-performance writer
	writeBuf chan interface{} // 🆕 Async write queue
}

var _ transport.Connection = (*webSocketConnectionWithInfo)(nil)

// NewWebSocketConnectionWithInfo creates WebSocket connection wrapper with client information and high-performance writing (🆕 integrates v1 performance optimizations)
func NewWebSocketConnectionWithInfo(conn *websocket.Conn, clientID, groupID string) transport.Connection {
	// 🆕 Create write buffer (same as v1)
	writeBuf := make(chan interface{}, writeBufSize)

	// 🆕 Create high-performance writer, using clientID as identifier (transport layer level tracking)
	writer := NewWriterWithID(conn, writeBuf, clientID)
	writer.Start()

	return &webSocketConnectionWithInfo{
		conn:     conn,
		clientID: clientID,
		groupID:  groupID,
		writer:   writer,   // 🆕 High-performance writer
		writeBuf: writeBuf, // 🆕 Async queue
	}
}

// WriteMessage implements transport.Connection
func (c *webSocketConnectionWithInfo) WriteMessage(data []byte) error {
	return c.writer.WriteMessage(data)
}

// ReadMessage implements transport.Connection
func (c *webSocketConnectionWithInfo) ReadMessage() ([]byte, error) {
	_, data, err := c.conn.ReadMessage()
	return data, err
}

// Close gracefully closes connection (🆕 using high-performance writer's graceful stop)
func (c *webSocketConnectionWithInfo) Close() error {
	// 🆕 First stop writer, ensure all messages are sent
	if c.writer != nil {
		c.writer.Stop()
	}

	// 🆕 Close write buffer
	if c.writeBuf != nil {
		close(c.writeBuf)
	}

	// Then close underlying connection (writer.Stop() already closed it, but call again for safety)
	return c.conn.Close()
}

func (c *webSocketConnectionWithInfo) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *webSocketConnectionWithInfo) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// GetClientID gets client ID
func (c *webSocketConnectionWithInfo) GetClientID() string {
	return c.clientID
}

// GetGroupID gets group ID
func (c *webSocketConnectionWithInfo) GetGroupID() string {
	return c.groupID
}
