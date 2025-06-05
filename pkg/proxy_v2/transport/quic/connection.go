package quic

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/quic-go/quic-go"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// 🆕 写入请求类型
type writeRequest struct {
	data    []byte
	errChan chan error
}

// quicConnection implements transport.Connection for QUIC streams
type quicConnection struct {
	stream   quic.Stream
	conn     quic.Connection
	clientID string
	groupID  string
	// 🆕 移除 mutex，改用异步写入
	writeChan chan *writeRequest // 🆕 异步写入队列
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	readChan  chan []byte
	errorChan chan error
	closeOnce sync.Once
	isClient  bool // Whether this is a client connection
}

var _ transport.Connection = (*quicConnection)(nil)

// newQUICConnection creates a new QUIC connection wrapper
func newQUICConnection(stream quic.Stream, conn quic.Connection, clientID, groupID string) *quicConnection {
	ctx, cancel := context.WithCancel(context.Background())

	c := &quicConnection{
		stream:    stream,
		conn:      conn,
		clientID:  clientID,
		groupID:   groupID,
		writeChan: make(chan *writeRequest, 1000), // 🆕 异步写入队列
		ctx:       ctx,
		cancel:    cancel,
		readChan:  make(chan []byte, 100),
		errorChan: make(chan error, 1),
		isClient:  true, // Default to client
	}

	// 🆕 启动读写 goroutines
	go c.receiveLoop()
	go c.writeLoop()
	return c
}

// newQUICServerConnection creates a new server-side QUIC connection
func newQUICServerConnection(stream quic.Stream, conn quic.Connection, clientID, groupID string) *quicConnection {
	ctx, cancel := context.WithCancel(context.Background())

	c := &quicConnection{
		stream:    stream,
		conn:      conn,
		clientID:  clientID,
		groupID:   groupID,
		writeChan: make(chan *writeRequest, 1000), // 🆕 异步写入队列
		ctx:       ctx,
		cancel:    cancel,
		readChan:  make(chan []byte, 100),
		errorChan: make(chan error, 1),
		isClient:  false, // Server connection
	}

	// 🆕 启动读写 goroutines
	go c.receiveLoop()
	go c.writeLoop()
	return c
}

// 🆕 异步写入 goroutine，避免锁竞争
func (c *quicConnection) writeLoop() {
	defer func() {
		// 清空队列中的错误通道
		for req := range c.writeChan {
			if req.errChan != nil {
				req.errChan <- fmt.Errorf("connection closed")
				close(req.errChan)
			}
		}
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		case req := <-c.writeChan:
			if c.closed {
				if req.errChan != nil {
					req.errChan <- fmt.Errorf("connection closed")
					close(req.errChan)
				}
				continue
			}

			err := c.writeDataDirect(req.data)
			if err != nil && isQUICError(err) {
				c.closed = true
			}

			if req.errChan != nil {
				req.errChan <- err
				close(req.errChan)
			}
		}
	}
}

// WriteMessage implements transport.Connection
func (c *quicConnection) WriteMessage(data []byte) error {
	return c.writeDataAsync(data)
}

// WriteJSON implements transport.Connection
func (c *quicConnection) WriteJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal JSON: %v", err)
	}
	return c.writeDataAsync(data)
}

// 🆕 异步写入方法，无锁设计
func (c *quicConnection) writeDataAsync(data []byte) error {
	if c.closed {
		return fmt.Errorf("connection closed")
	}

	errChan := make(chan error, 1)
	req := &writeRequest{
		data:    data,
		errChan: errChan,
	}

	select {
	case c.writeChan <- req:
		// 等待写入结果
		select {
		case err := <-errChan:
			return err
		case <-c.ctx.Done():
			// 🆕 确保 errChan 不泄漏
			go func() {
				<-errChan // 消费可能的错误
			}()
			return c.ctx.Err()
		}
	case <-c.ctx.Done():
		// 🆕 确保 errChan 不泄漏
		close(errChan)
		return c.ctx.Err()
	}
}

// 🆕 直接写入数据的方法，仅在 writeLoop 中使用
func (c *quicConnection) writeDataDirect(data []byte) error {
	// Write length prefix (4 bytes)
	length := uint32(len(data))
	if err := binary.Write(c.stream, binary.BigEndian, length); err != nil {
		return fmt.Errorf("write length: %v", err)
	}

	// Write data
	if _, err := c.stream.Write(data); err != nil {
		return fmt.Errorf("write data: %v", err)
	}

	return nil
}

// 🆕 保留 writeData 方法供认证时直接使用 (同步写入)
func (c *quicConnection) writeData(data []byte) error {
	return c.writeDataDirect(data)
}

// ReadMessage implements transport.Connection
func (c *quicConnection) ReadMessage() ([]byte, error) {
	select {
	case data := <-c.readChan:
		return data, nil
	case err := <-c.errorChan:
		return nil, err
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// 🆕 ReadJSON 读取并解析 JSON 消息
func (c *quicConnection) ReadJSON(v interface{}) error {
	data, err := c.ReadMessage()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// Close implements transport.Connection
func (c *quicConnection) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed = true

		// Cancel context
		if c.cancel != nil {
			c.cancel()
		}

		// 🆕 关闭写入队列
		close(c.writeChan)

		// Close stream
		if c.stream != nil {
			c.stream.Close()
		}

		// Only client connections close the entire QUIC connection
		if c.isClient && c.conn != nil {
			err = c.conn.CloseWithError(0, "connection closed")
		}
	})
	return err
}

// RemoteAddr implements transport.Connection
func (c *quicConnection) RemoteAddr() net.Addr {
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return &simpleAddr{network: "quic", address: "quic-remote"}
}

// LocalAddr implements transport.Connection
func (c *quicConnection) LocalAddr() net.Addr {
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return &simpleAddr{network: "quic", address: "quic-local"}
}

// GetClientID gets client ID - for upper layer code to extract client information
func (c *quicConnection) GetClientID() string {
	return c.clientID
}

// GetGroupID gets group ID - for upper layer code to extract client information
func (c *quicConnection) GetGroupID() string {
	return c.groupID
}

// receiveLoop handles incoming messages
func (c *quicConnection) receiveLoop() {
	defer func() {
		close(c.readChan)
		close(c.errorChan)
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			data, err := c.readData()
			if err != nil {
				if err == io.EOF || isQUICError(err) {
					return
				}
				select {
				case c.errorChan <- err:
				case <-c.ctx.Done():
					return
				}
				continue
			}

			select {
			case c.readChan <- data:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// readData reads data from QUIC stream using simple length-prefix format
func (c *quicConnection) readData() ([]byte, error) {
	// Read length prefix (4 bytes)
	var length uint32
	if err := binary.Read(c.stream, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %v", err)
	}

	// Check length reasonableness (max 10MB)
	if length > 10*1024*1024 {
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(c.stream, data); err != nil {
		return nil, fmt.Errorf("read data: %v", err)
	}

	return data, nil
}

// isQUICError checks if the error indicates a QUIC connection issue
func isQUICError(err error) bool {
	if err == nil {
		return false
	}

	// Check common QUIC error types
	switch err.(type) {
	case *quic.ApplicationError, *quic.TransportError:
		return true
	}

	return err == io.EOF
}

// simpleAddr simple address implementation
type simpleAddr struct {
	network, address string
}

func (a *simpleAddr) Network() string { return a.network }
func (a *simpleAddr) String() string  { return a.address }
