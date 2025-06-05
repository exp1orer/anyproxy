package websocket

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketWriter manages WebSocket write operations in a single goroutine (从 v1 完整迁移)
// The caller is responsible for closing writeCh to prevent resource leaks
type WebSocketWriter struct {
	conn         *websocket.Conn
	writeCh      chan interface{}
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
	wg           sync.WaitGroup
	messageCount int64
	bytesWritten int64
	startTime    time.Time
	connectionID string
}

// NewWebSocketWriter creates a new WebSocket writer (从 v1 完整迁移)
func NewWebSocketWriter(conn *websocket.Conn, writeCh chan interface{}) *WebSocketWriter {
	connectionID := generateConnectionID()

	slog.Debug("Creating new WebSocket writer",
		"connection_id", connectionID,
		"remote_addr", conn.RemoteAddr(),
		"local_addr", conn.LocalAddr(),
		"write_channel_cap", cap(writeCh))

	ctx, cancel := context.WithCancel(context.Background())
	writer := &WebSocketWriter{
		conn:         conn,
		writeCh:      writeCh,
		ctx:          ctx,
		cancel:       cancel,
		startTime:    time.Now(),
		connectionID: connectionID,
	}

	slog.Debug("WebSocket writer created successfully",
		"connection_id", connectionID)

	return writer
}

// Start starts the writer goroutine (从 v1 完整迁移)
func (w *WebSocketWriter) Start() {
	slog.Info("Starting WebSocket writer",
		"connection_id", w.connectionID,
		"remote_addr", w.conn.RemoteAddr())

	w.wg.Add(1)
	go w.writeLoop()

	slog.Debug("WebSocket writer goroutine started",
		"connection_id", w.connectionID)
}

// Stop stops the writer and waits for completion (从 v1 完整迁移)
func (w *WebSocketWriter) Stop() {
	slog.Info("Stopping WebSocket writer",
		"connection_id", w.connectionID,
		"messages_written", w.messageCount)

	stopStart := time.Now()

	w.once.Do(func() {
		slog.Debug("Cancelling WebSocket writer context",
			"connection_id", w.connectionID)
		w.cancel()

		// wait for writeLoop to finish, and all messages to be written to conn
		slog.Debug("Waiting for WebSocket writer goroutine to finish",
			"connection_id", w.connectionID)
		w.wg.Wait()

		// Close the WebSocket connection
		slog.Debug("Closing WebSocket connection",
			"connection_id", w.connectionID)
		if err := w.conn.Close(); err != nil {
			slog.Debug("Error closing WebSocket connection (expected during shutdown)",
				"connection_id", w.connectionID,
				"error", err)
		}

		elapsed := time.Since(stopStart)
		uptime := time.Since(w.startTime)

		slog.Info("WebSocket writer stopped",
			"connection_id", w.connectionID,
			"stop_duration", elapsed,
			"total_uptime", uptime,
			"total_messages", w.messageCount,
			"total_bytes", w.bytesWritten,
			"avg_msg_per_sec", func() float64 {
				if uptime.Seconds() > 0 {
					return float64(w.messageCount) / uptime.Seconds()
				}
				return 0
			}())
	})
}

// WriteJSON queues a JSON message for writing (从 v1 完整迁移)
func (w *WebSocketWriter) WriteJSON(v interface{}) error {
	// Check if context is cancelled
	select {
	case <-w.ctx.Done():
		slog.Debug("Write rejected - WebSocket writer stopped",
			"connection_id", w.connectionID)
		return websocket.ErrCloseSent
	default:
	}

	// Try to write or handle cancellation
	select {
	case w.writeCh <- v:
		slog.Debug("Message queued for WebSocket write",
			"connection_id", w.connectionID,
			"queue_length", len(w.writeCh),
			"queue_capacity", cap(w.writeCh))
		return nil
	case <-w.ctx.Done():
		slog.Debug("Write cancelled - WebSocket writer stopped during queue",
			"connection_id", w.connectionID)
		return websocket.ErrCloseSent
	default:
		// Channel is full, log and drop message
		slog.Error("WebSocket write channel full, dropping message",
			"connection_id", w.connectionID,
			"queue_capacity", cap(w.writeCh),
			"total_messages", w.messageCount)
		return nil
	}
}

// WriteMessage queues a binary message for writing (🆕 扩展功能)
func (w *WebSocketWriter) WriteMessage(data []byte) error {
	// 包装为特殊的消息类型
	msg := &binaryMessage{data: data}
	return w.WriteJSON(msg)
}

// binaryMessage 表示二进制消息 (🆕 扩展功能)
type binaryMessage struct {
	data []byte
}

// writeLoop processes messages in a single goroutine to ensure order (从 v1 完整迁移，🆕 扩展二进制消息支持)
func (w *WebSocketWriter) writeLoop() {
	slog.Debug("WebSocket write loop started",
		"connection_id", w.connectionID)

	defer func() {
		slog.Debug("WebSocket write loop finished",
			"connection_id", w.connectionID,
			"messages_processed", w.messageCount,
			"bytes_written", w.bytesWritten)
		w.wg.Done()
	}()

	// Performance tracking
	lastLogTime := time.Now()
	lastMessageCount := int64(0)

	for {
		select {
		case <-w.ctx.Done():
			slog.Debug("WebSocket write loop stopping due to context cancellation",
				"connection_id", w.connectionID,
				"messages_processed", w.messageCount)
			// Drain remaining messages to preserve order
			w.drainMessages()
			return

		case msg := <-w.writeCh:
			writeStart := time.Now()
			var err error

			// 🆕 支持二进制消息
			if binMsg, ok := msg.(*binaryMessage); ok {
				err = w.conn.WriteMessage(websocket.BinaryMessage, binMsg.data)
				w.bytesWritten += int64(len(binMsg.data))
			} else {
				err = w.conn.WriteJSON(msg)
			}

			if err != nil {
				slog.Error("WebSocket write error",
					"connection_id", w.connectionID,
					"error", err,
					"message_count", w.messageCount,
					"write_duration", time.Since(writeStart))
				// Don't call Stop() here to avoid potential deadlock
				// Just return and let the caller handle the error through normal error handling
				return
			}

			w.messageCount++
			writeDuration := time.Since(writeStart)

			// Log performance statistics periodically
			if w.messageCount%1000 == 0 || time.Since(lastLogTime) > 30*time.Second {
				messagesInPeriod := w.messageCount - lastMessageCount
				timePeriod := time.Since(lastLogTime)
				msgRate := float64(messagesInPeriod) / timePeriod.Seconds()

				slog.Debug("WebSocket writer performance statistics",
					"connection_id", w.connectionID,
					"total_messages", w.messageCount,
					"messages_in_period", messagesInPeriod,
					"time_period", timePeriod,
					"msg_rate_per_sec", msgRate,
					"queue_length", len(w.writeCh))

				lastLogTime = time.Now()
				lastMessageCount = w.messageCount
			}

			// Only log individual writes for debugging or slow writes
			if writeDuration > 100*time.Millisecond {
				slog.Debug("Slow WebSocket write detected",
					"connection_id", w.connectionID,
					"write_duration", writeDuration,
					"message_count", w.messageCount)
			}
		}
	}
}

// drainMessages processes remaining messages before shutdown (从 v1 完整迁移，🆕 扩展二进制消息支持)
func (w *WebSocketWriter) drainMessages() {
	slog.Debug("Draining remaining WebSocket messages",
		"connection_id", w.connectionID,
		"queue_length", len(w.writeCh))

	drainedCount := 0
	drainStart := time.Now()

	for {
		select {
		case msg, ok := <-w.writeCh:
			if !ok {
				slog.Debug("WebSocket write channel closed during drain",
					"connection_id", w.connectionID,
					"drained_messages", drainedCount)
				return
			}

			writeStart := time.Now()
			var err error

			// 🆕 支持二进制消息
			if binMsg, ok := msg.(*binaryMessage); ok {
				err = w.conn.WriteMessage(websocket.BinaryMessage, binMsg.data)
			} else {
				err = w.conn.WriteJSON(msg)
			}

			if err != nil {
				slog.Error("Error writing final message during drain",
					"connection_id", w.connectionID,
					"error", err,
					"drained_messages", drainedCount,
					"write_duration", time.Since(writeStart))
			} else {
				drainedCount++
				w.messageCount++
			}
		default:
			drainDuration := time.Since(drainStart)
			slog.Debug("WebSocket message drain completed",
				"connection_id", w.connectionID,
				"drained_messages", drainedCount,
				"drain_duration", drainDuration)
			return
		}
	}
}

// generateConnectionID generates a unique connection ID for tracking (从 v1 完整迁移)
func generateConnectionID() string {
	return time.Now().Format("20060102-150405.000000")
}
