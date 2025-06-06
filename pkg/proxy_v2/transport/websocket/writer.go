package websocket

import (
	"context"
	"fmt"
	"sync"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/gorilla/websocket"
)

// Writer manages WebSocket write operations in a single goroutine (从 v1 完整迁移)
// The caller is responsible for closing writeCh to prevent resource leaks
type Writer struct {
	conn         *websocket.Conn
	writeCh      chan interface{}
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
	wg           sync.WaitGroup
	messageCount int64
	bytesWritten int64
	connectionID string
}

// NewWriterWithID creates a new WebSocket writer with specific connection ID
// connID is required for proper request tracking across the system
func NewWriterWithID(conn *websocket.Conn, writeCh chan interface{}, connID string) *Writer {
	// connID 应该由调用方提供，确保有意义的追踪
	logger.Debug("Creating new WebSocket writer", "connection_id", connID, "remote_addr", conn.RemoteAddr(), "local_addr", conn.LocalAddr(), "write_channel_cap", cap(writeCh))

	ctx, cancel := context.WithCancel(context.Background())
	writer := &Writer{
		conn:         conn,
		writeCh:      writeCh,
		ctx:          ctx,
		cancel:       cancel,
		connectionID: connID,
	}

	logger.Debug("WebSocket writer created successfully", "connection_id", connID)

	return writer
}

// Start starts the writer goroutine (从 v1 完整迁移)
func (w *Writer) Start() {
	logger.Info("Starting WebSocket writer", "connection_id", w.connectionID, "remote_addr", w.conn.RemoteAddr())

	w.wg.Add(1)
	go w.writeLoop()

	logger.Debug("WebSocket writer goroutine started", "connection_id", w.connectionID)
}

// Stop stops the writer and waits for completion (从 v1 完整迁移)
func (w *Writer) Stop() {
	logger.Info("Stopping WebSocket writer", "connection_id", w.connectionID, "messages_written", w.messageCount)

	w.once.Do(func() {
		logger.Debug("Cancelling WebSocket writer context", "connection_id", w.connectionID)
		w.cancel()

		// wait for writeLoop to finish, and all messages to be written to conn
		logger.Debug("Waiting for WebSocket writer goroutine to finish", "connection_id", w.connectionID)
		w.wg.Wait()

		// Close the WebSocket connection
		logger.Debug("Closing WebSocket connection", "connection_id", w.connectionID)
		if err := w.conn.Close(); err != nil {
			logger.Debug("Error closing WebSocket connection (expected during shutdown)", "connection_id", w.connectionID, "err", err)
		}

		logger.Info("WebSocket writer stopped", "connection_id", w.connectionID, "total_messages", w.messageCount, "total_bytes", w.bytesWritten)
	})
}

// WriteJSON queues a JSON message for writing (从 v1 完整迁移)
func (w *Writer) WriteJSON(v interface{}) error {
	// Check if context is cancelled
	select {
	case <-w.ctx.Done():
		logger.Debug("Write rejected - WebSocket writer stopped", "connection_id", w.connectionID)
		return websocket.ErrCloseSent
	default:
	}

	// Try to write or handle cancellation
	select {
	case w.writeCh <- v:
		logger.Debug("Message queued for WebSocket write", "connection_id", w.connectionID, "queue_length", len(w.writeCh), "queue_capacity", cap(w.writeCh))
		return nil
	case <-w.ctx.Done():
		logger.Debug("Write cancelled - WebSocket writer stopped during queue", "connection_id", w.connectionID)
		return websocket.ErrCloseSent
	default:
		// 修复：当通道满时返回错误，而不是静默丢弃消息
		logger.Error("WebSocket write channel full, rejecting message", "connection_id", w.connectionID, "queue_capacity", cap(w.writeCh), "total_messages", w.messageCount)
		return fmt.Errorf("write channel full: cannot queue message")
	}
}

// WriteMessage queues a binary message for writing (🆕 扩展功能)
func (w *Writer) WriteMessage(data []byte) error {
	// 包装为特殊的消息类型
	msg := &binaryMessage{data: data}
	return w.WriteJSON(msg)
}

// binaryMessage 表示二进制消息 (🆕 扩展功能)
type binaryMessage struct {
	data []byte
}

// writeLoop processes messages in a single goroutine to ensure order (从 v1 完整迁移，🆕 扩展二进制消息支持)
func (w *Writer) writeLoop() {
	logger.Debug("WebSocket write loop started", "connection_id", w.connectionID)

	defer func() {
		logger.Debug("WebSocket write loop finished", "connection_id", w.connectionID, "messages_processed", w.messageCount, "bytes_written", w.bytesWritten)
		w.wg.Done()
	}()

	for {
		select {
		case <-w.ctx.Done():
			logger.Debug("WebSocket write loop stopping due to context cancellation", "connection_id", w.connectionID, "messages_processed", w.messageCount)
			// Drain remaining messages to preserve order
			w.drainMessages()
			return

		case msg := <-w.writeCh:
			var err error

			// 🆕 支持二进制消息
			if binMsg, ok := msg.(*binaryMessage); ok {
				err = w.conn.WriteMessage(websocket.BinaryMessage, binMsg.data)
				w.bytesWritten += int64(len(binMsg.data))
			} else {
				err = w.conn.WriteJSON(msg)
			}

			if err != nil {
				logger.Error("WebSocket write error", "connection_id", w.connectionID, "err", err, "message_count", w.messageCount)
				// Don't call Stop() here to avoid potential deadlock
				// Just return and let the caller handle the error through normal error handling
				return
			}

			w.messageCount++
		}
	}
}

// drainMessages processes remaining messages before shutdown (从 v1 完整迁移，🆕 扩展二进制消息支持)
func (w *Writer) drainMessages() {
	logger.Debug("Draining remaining WebSocket messages", "connection_id", w.connectionID, "queue_length", len(w.writeCh))

	drainedCount := 0

	for {
		select {
		case msg, ok := <-w.writeCh:
			if !ok {
				logger.Debug("WebSocket write channel closed during drain", "connection_id", w.connectionID, "drained_messages", drainedCount)
				return
			}

			var err error

			// 🆕 支持二进制消息
			if binMsg, ok := msg.(*binaryMessage); ok {
				err = w.conn.WriteMessage(websocket.BinaryMessage, binMsg.data)
			} else {
				err = w.conn.WriteJSON(msg)
			}

			if err != nil {
				logger.Error("Error writing final message during drain", "connection_id", w.connectionID, "err", err, "drained_messages", drainedCount)
			} else {
				drainedCount++
				w.messageCount++
			}
		default:
			logger.Debug("WebSocket message drain completed", "connection_id", w.connectionID, "drained_messages", drainedCount)
			return
		}
	}
}
