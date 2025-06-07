package websocket

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = (pongWait * 9) / 10
)

var (
	// ErrStopped is returned when trying to write to a stopped writer
	ErrStopped = errors.New("writer stopped")

	// ErrQueueFull is returned when the write queue is full
	ErrQueueFull = errors.New("write queue full")

	// ErrWriteTimeout is returned when a write operation times out
	ErrWriteTimeout = errors.New("write timeout")
)

// writeMsg represents a message to be written
type writeMsg struct {
	msgType  int
	data     []byte
	callback chan error
}

// Writer manages WebSocket write operations in a single goroutine
type Writer struct {
	conn         *websocket.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	once         sync.Once
	wg           sync.WaitGroup
	messageCount int64
	bytesWritten int64
	connectionID string
	stopped      atomic.Bool
	stopCh       chan struct{}
	ch           chan *writeMsg
	backupCh     chan *writeMsg
	queueTimeout time.Duration
	writeTimeout time.Duration
}

// NewWriterWithID creates a new WebSocket writer with specific connection ID
func NewWriterWithID(conn *websocket.Conn, _ chan interface{}, connID string) *Writer {
	logger.Debug("Creating new WebSocket writer", "connection_id", connID, "remote_addr", conn.RemoteAddr(), "local_addr", conn.LocalAddr())

	ctx, cancel := context.WithCancel(context.Background())
	writer := &Writer{
		conn:         conn,
		ctx:          ctx,
		cancel:       cancel,
		connectionID: connID,
		stopCh:       make(chan struct{}),
		ch:           make(chan *writeMsg, 100),
		backupCh:     make(chan *writeMsg, 100),
		queueTimeout: 5 * time.Second,
		writeTimeout: 10 * time.Second,
	}

	logger.Debug("WebSocket writer created successfully", "connection_id", connID)

	return writer
}

// Start starts the writer goroutine
func (w *Writer) Start() {
	logger.Info("Starting WebSocket writer", "connection_id", w.connectionID, "remote_addr", w.conn.RemoteAddr())

	w.wg.Add(1)
	go w.run()

	logger.Debug("WebSocket writer goroutine started", "connection_id", w.connectionID)
}

// Stop stops the writer and waits for completion
func (w *Writer) Stop() {
	logger.Info("Stopping WebSocket writer", "connection_id", w.connectionID, "messages_written", w.messageCount)

	w.once.Do(func() {
		w.stopped.Store(true)
		close(w.stopCh)

		// wait for writer to finish
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

// WriteMessage queues a binary message for writing
func (w *Writer) WriteMessage(data []byte) error {
	if w.stopped.Load() {
		return ErrStopped
	}

	msg := &writeMsg{
		msgType:  websocket.BinaryMessage,
		data:     data,
		callback: make(chan error, 1),
	}

	select {
	case w.ch <- msg:
		// Successfully queued
	default:
		// Queue is full, use backup channel
		select {
		case w.backupCh <- msg:
		case <-time.After(w.queueTimeout):
			return ErrQueueFull
		}
	}

	// Wait for write completion with timeout
	select {
	case err := <-msg.callback:
		return err
	case <-time.After(w.writeTimeout):
		return ErrWriteTimeout
	}
}

// run is the main writer loop
func (w *Writer) run() {
	defer func() {
		logger.Debug("WebSocket writer stopped", "client_id", w.connectionID)
		w.wg.Done()
	}()

	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-w.stopCh:
			// Graceful shutdown
			w.handleShutdown()
			return

		case msg := <-w.ch:
			if err := w.handleWrite(msg); err != nil {
				logger.Debug("Write error", "err", err)
			}

		case msg := <-w.backupCh:
			if err := w.handleWrite(msg); err != nil {
				logger.Debug("Write error from backup queue", "err", err)
			}

		case <-ticker.C:
			// Send ping
			w.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck
			if err := w.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				logger.Debug("Ping error", "err", err)
				return
			}
		}
	}
}

// handleWrite writes a message and sends result to callback
func (w *Writer) handleWrite(msg *writeMsg) error {
	w.conn.SetWriteDeadline(time.Now().Add(writeWait)) //nolint:errcheck

	err := w.conn.WriteMessage(msg.msgType, msg.data)

	// Update statistics
	if err == nil {
		atomic.AddInt64(&w.messageCount, 1)
		atomic.AddInt64(&w.bytesWritten, int64(len(msg.data)))
	}

	// Send result to callback
	select {
	case msg.callback <- err:
	default:
		// Callback channel might be closed if timed out
	}

	return err
}

// handleShutdown drains remaining messages
func (w *Writer) handleShutdown() {
	logger.Debug("Draining remaining WebSocket messages", "connection_id", w.connectionID)

	drainedCount := 0

	// Drain main channel
	for {
		select {
		case msg := <-w.ch:
			if err := w.handleWrite(msg); err != nil {
				logger.Debug("Error writing message during drain", "err", err)
			} else {
				drainedCount++
			}
		default:
			goto drainBackup
		}
	}

drainBackup:
	// Drain backup channel
	for {
		select {
		case msg := <-w.backupCh:
			if err := w.handleWrite(msg); err != nil {
				logger.Debug("Error writing message during drain", "err", err)
			} else {
				drainedCount++
			}
		default:
			logger.Debug("WebSocket message drain completed", "connection_id", w.connectionID, "drained_messages", drainedCount)
			return
		}
	}
}
