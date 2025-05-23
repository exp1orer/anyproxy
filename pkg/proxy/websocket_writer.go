package proxy

import (
	"log/slog"
	"sync"

	"github.com/gorilla/websocket"
)

// WebSocketWriter manages WebSocket write operations in a single goroutine
// The caller is responsible for closing writeCh to prevent resource leaks
type WebSocketWriter struct {
	conn    *websocket.Conn
	writeCh chan interface{}
	stopCh  chan struct{}
	once    sync.Once
	wg      sync.WaitGroup
}

// NewWebSocketWriter creates a new WebSocket writer
func NewWebSocketWriter(conn *websocket.Conn, writeCh chan interface{}) *WebSocketWriter {
	return &WebSocketWriter{
		conn:    conn,
		writeCh: writeCh,
		stopCh:  make(chan struct{}),
	}
}

// Start starts the writer goroutine
func (w *WebSocketWriter) Start() {
	w.wg.Add(1)
	go w.writeLoop()
}

// Stop stops the writer and waits for completion
func (w *WebSocketWriter) Stop() {
	w.once.Do(func() {
		close(w.stopCh)
		// wait for writeLoop to finish, and all messages to be written to conn
		w.wg.Wait()
		w.conn.Close()
	})
}

// WriteJSON queues a JSON message for writing
func (w *WebSocketWriter) WriteJSON(v interface{}) error {
	// First check if already stopped
	select {
	case <-w.stopCh:
		return websocket.ErrCloseSent
	default:
	}

	// Then try to write or handle stop signal
	select {
	case w.writeCh <- v:
		return nil
	case <-w.stopCh:
		return websocket.ErrCloseSent
	default:
		slog.Error("WebSocket write channel full, dropping message")
		return nil
	}
}

// writeLoop processes messages in a single goroutine to ensure order
func (w *WebSocketWriter) writeLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.stopCh:
			// Drain remaining messages to preserve order
			w.drainMessages()
			return

		case msg := <-w.writeCh:
			if err := w.conn.WriteJSON(msg); err != nil {
				slog.Error("WebSocket write error", "error", err)
				go w.Stop() // Auto-stop on write errors
				return
			}
		}
	}
}

// drainMessages processes remaining messages before shutdown
func (w *WebSocketWriter) drainMessages() {
	for {
		select {
		case msg := <-w.writeCh:
			if err := w.conn.WriteJSON(msg); err != nil {
				slog.Error("Error writing final message", "error", err)
			}
		default:
			return
		}
	}
}
