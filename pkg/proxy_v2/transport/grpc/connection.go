package grpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

// 🆕 写入消息类型
type writeRequest struct {
	msgType StreamMessage_MessageType
	data    []byte
	errChan chan error
}

// grpcStream unified stream interface
type grpcStream interface {
	Send(*StreamMessage) error
	Recv() (*StreamMessage, error)
	Context() context.Context
}

// grpcConnection unified gRPC connection implementation
type grpcConnection struct {
	stream   grpcStream
	conn     *grpc.ClientConn // Only client connections have this
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
}

var _ transport.Connection = (*grpcConnection)(nil)

// newGRPCConnection creates a client gRPC connection
func newGRPCConnection(stream TransportService_BiStreamClient, conn *grpc.ClientConn, clientID, groupID string) *grpcConnection {
	ctx, cancel := context.WithCancel(context.Background())

	c := &grpcConnection{
		stream:    stream,
		conn:      conn,
		clientID:  clientID,
		groupID:   groupID,
		writeChan: make(chan *writeRequest, 1000), // 🆕 异步写入队列
		ctx:       ctx,
		cancel:    cancel,
		readChan:  make(chan []byte, 100),
		errorChan: make(chan error, 1),
	}

	// 🆕 启动读写 goroutines
	go c.receiveLoop()
	go c.writeLoop()
	return c
}

// newGRPCServerConnection creates a server gRPC connection
func newGRPCServerConnection(stream TransportService_BiStreamServer, clientID, groupID string) *grpcConnection {
	ctx, cancel := context.WithCancel(stream.Context())

	c := &grpcConnection{
		stream:    stream,
		conn:      nil, // Server connections don't have client connections
		clientID:  clientID,
		groupID:   groupID,
		writeChan: make(chan *writeRequest, 1000), // 🆕 异步写入队列
		ctx:       ctx,
		cancel:    cancel,
		readChan:  make(chan []byte, 100),
		errorChan: make(chan error, 1),
	}

	// 🆕 启动读写 goroutines
	go c.receiveLoop()
	go c.writeLoop()
	return c
}

// 🆕 异步写入 goroutine，避免锁竞争
func (c *grpcConnection) writeLoop() {
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

			msg := &StreamMessage{
				Type:     req.msgType,
				Data:     req.data,
				ClientId: c.clientID,
				GroupId:  c.groupID,
			}

			err := c.stream.Send(msg)
			if err != nil && isGRPCError(err) {
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
func (c *grpcConnection) WriteMessage(data []byte) error {
	return c.writeMessageAsync(StreamMessage_DATA, data)
}

// 🆕 异步写入方法，无锁设计
func (c *grpcConnection) writeMessageAsync(msgType StreamMessage_MessageType, data []byte) error {
	if c.closed {
		return fmt.Errorf("connection closed")
	}

	errChan := make(chan error, 1)
	req := &writeRequest{
		msgType: msgType,
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
				select {
				case <-errChan:
					// 成功消费错误
				case <-time.After(5 * time.Second):
					// 超时后退出，防止永久阻塞
					logger.Warn("Timeout waiting for write error channel", "client_id", c.clientID)
				}
			}()
			return c.ctx.Err()
		}
	case <-c.ctx.Done():
		// 🆕 确保 errChan 不泄漏
		close(errChan)
		return c.ctx.Err()
	}
}

// ReadMessage implements transport.Connection
func (c *grpcConnection) ReadMessage() ([]byte, error) {
	select {
	case data := <-c.readChan:
		return data, nil
	case err := <-c.errorChan:
		return nil, err
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// Close implements transport.Connection
func (c *grpcConnection) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.closed = true

		// Cancel context
		if c.cancel != nil {
			c.cancel()
		}

		// 🆕 关闭写入队列
		close(c.writeChan)

		// Only client connections close the gRPC connection
		if c.conn != nil {
			err = c.conn.Close()
		}
	})
	return err
}

// RemoteAddr implements transport.Connection
func (c *grpcConnection) RemoteAddr() net.Addr {
	if c.conn != nil {
		return &simpleAddr{network: "grpc", address: c.conn.Target()}
	}
	return &simpleAddr{network: "grpc", address: "grpc-client"}
}

// LocalAddr implements transport.Connection
func (c *grpcConnection) LocalAddr() net.Addr {
	return &simpleAddr{network: "grpc", address: "grpc-server"}
}

// GetClientID gets client ID - for upper layer code to extract client information
func (c *grpcConnection) GetClientID() string {
	return c.clientID
}

// GetGroupID gets group ID - for upper layer code to extract client information
func (c *grpcConnection) GetGroupID() string {
	return c.groupID
}

// receiveLoop handles receiving messages
func (c *grpcConnection) receiveLoop() {
	defer func() {
		close(c.readChan)
		close(c.errorChan)
	}()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			msg, err := c.stream.Recv()
			if err != nil {
				if err == io.EOF || isGRPCError(err) {
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
			case c.readChan <- msg.Data:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// isGRPCError checks if the error is a connection error
func isGRPCError(err error) bool {
	if err == nil {
		return false
	}

	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.Canceled, codes.DeadlineExceeded:
			return true
		}
	}
	return false
}

// simpleAddr simple address implementation
type simpleAddr struct {
	network, address string
}

func (a *simpleAddr) Network() string { return a.network }
func (a *simpleAddr) String() string  { return a.address }
