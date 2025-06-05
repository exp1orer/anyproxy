package proxy

import (
	"context"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/gorilla/websocket"
)

// WebSocketWriter manages WebSocket write operations in a single goroutine
// The caller is responsible for closing writeCh to prevent resource leaks
type WebSocketWriter struct {
	conn         *websocket.Conn
	writeCh      chan interface{}
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
	wg           sync.WaitGroup
	messageCount int64
	connectionID string
}

// NewWebSocketWriter creates a new WebSocket writer
func NewWebSocketWriter(conn *websocket.Conn, writeCh chan interface{}) *WebSocketWriter {
	connectionID := generateConnectionID()

	ctx, cancel := context.WithCancel(context.Background())
	writer := &WebSocketWriter{
		conn:         conn,
		writeCh:      writeCh,
		ctx:          ctx,
		cancel:       cancel,
		connectionID: connectionID,
	}

	logger.Debug("WebSocket writer created", "id", connectionID)
	return writer
}

// Start starts the writer goroutine
func (w *WebSocketWriter) Start() {
	logger.Debug("Starting WebSocket writer", "id", w.connectionID)
	w.wg.Add(1)
	go w.writeLoop()
}

// Stop stops the writer and waits for completion
func (w *WebSocketWriter) Stop() {
	w.once.Do(func() {
		logger.Debug("Stopping WebSocket writer", "id", w.connectionID, "msgs", w.messageCount)
		w.cancel()
		w.wg.Wait()

		if err := w.conn.Close(); err != nil {
			logger.Debug("Error closing WebSocket", "id", w.connectionID, "err", err)
		}

		logger.Info("WebSocket writer stopped", "id", w.connectionID, "msgs", w.messageCount)
	})
}

// WriteJSON queues a JSON message for writing
func (w *WebSocketWriter) WriteJSON(v interface{}) error {
	select {
	case <-w.ctx.Done():
		return websocket.ErrCloseSent
	default:
	}

	select {
	case w.writeCh <- v:
		return nil
	case <-w.ctx.Done():
		return websocket.ErrCloseSent
	default:
		logger.Warn("WebSocket write buffer full", "id", w.connectionID)
		return nil
	}
}

// writeLoop processes messages in a single goroutine to ensure order
func (w *WebSocketWriter) writeLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.ctx.Done():
			w.drainMessages()
			return

		case msg := <-w.writeCh:
			if err := w.conn.WriteJSON(msg); err != nil {
				logger.Error("WebSocket write error", "id", w.connectionID, "err", err)
				return
			}
			w.messageCount++
		}
	}
}

// drainMessages processes remaining messages before shutdown
func (w *WebSocketWriter) drainMessages() {
	remaining := len(w.writeCh)
	if remaining == 0 {
		return
	}

	logger.Debug("Draining messages", "id", w.connectionID, "count", remaining)

	deadline := time.Now().Add(5 * time.Second)
	for remaining > 0 && time.Now().Before(deadline) {
		select {
		case msg, ok := <-w.writeCh:
			if !ok {
				return
			}
			w.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err := w.conn.WriteJSON(msg); err != nil {
				logger.Error("Error draining", "id", w.connectionID, "err", err)
				return
			}
			remaining--
		default:
			return
		}
	}
}

// generateConnectionID generates a unique connection ID for tracking
func generateConnectionID() string {
	return time.Now().Format("20060102-150405.000000")
}
