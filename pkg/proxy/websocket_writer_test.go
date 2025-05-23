package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func TestWebSocketWriter_ClosedChannel(t *testing.T) {
	// Create a test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade: %v", err)
		}
		defer conn.Close()

		// Keep connection alive for test
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to test server
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create WebSocketWriter with buffered channel
	writeCh := make(chan interface{}, 1000)
	writer := NewWebSocketWriter(conn, writeCh)
	writer.Start()

	// Write a message before stopping
	err = writer.WriteJSON(map[string]string{"test": "message1"})
	if err != nil {
		t.Errorf("Expected no error before stopping, got: %v", err)
	}

	// Stop the writer
	writer.Stop()

	// Try to write after stopping - should not panic
	err = writer.WriteJSON(map[string]string{"test": "message2"})
	if err != websocket.ErrCloseSent {
		t.Errorf("Expected ErrCloseSent after stopping, got: %v", err)
	}

	// Try multiple writes - should not panic
	for i := 0; i < 10; i++ {
		err = writer.WriteJSON(map[string]string{"test": "message"})
		if err != websocket.ErrCloseSent {
			t.Errorf("Expected ErrCloseSent, got: %v", err)
		}
	}

	// Caller should close the channel
	close(writeCh)
}

func TestWebSocketWriter_ConcurrentWritesAfterClose(t *testing.T) {
	// Create a test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade: %v", err)
		}
		defer conn.Close()

		// Keep connection alive for test
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to test server
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create WebSocketWriter with buffered channel
	writeCh := make(chan interface{}, 1000)
	writer := NewWebSocketWriter(conn, writeCh)
	writer.Start()

	// Write some messages before stopping
	for i := 0; i < 5; i++ {
		err = writer.WriteJSON(map[string]string{"pre": "stop"})
		if err != nil {
			t.Errorf("Expected no error before stopping, got: %v", err)
		}
	}

	// Stop the writer
	writer.Stop()

	// Start multiple goroutines trying to write concurrently
	var wg sync.WaitGroup
	numGoroutines := 10
	numWritesPerGoroutine := 20

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numWritesPerGoroutine; j++ {
				err := writer.WriteJSON(map[string]interface{}{
					"goroutine": id,
					"message":   j,
				})
				// Should always return ErrCloseSent, never panic
				if err != websocket.ErrCloseSent {
					t.Errorf("Expected ErrCloseSent from goroutine %d, got: %v", id, err)
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	// Additional writes should still work safely
	err = writer.WriteJSON(map[string]string{"final": "test"})
	if err != websocket.ErrCloseSent {
		t.Errorf("Expected ErrCloseSent for final write, got: %v", err)
	}

	// Caller should close the channel
	close(writeCh)
}

func TestWebSocketWriter_MessageOrder(t *testing.T) {
	var receivedMessages []int
	var mu sync.Mutex

	// Create a test WebSocket server that collects messages
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade: %v", err)
		}
		defer conn.Close()

		// Read messages in order
		for {
			var msg map[string]int
			err := conn.ReadJSON(&msg)
			if err != nil {
				break
			}
			if id, ok := msg["id"]; ok {
				mu.Lock()
				receivedMessages = append(receivedMessages, id)
				mu.Unlock()
			}
		}
	}))
	defer server.Close()

	// Connect to test server
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create WebSocketWriter with buffered channel
	writeCh := make(chan interface{}, 1000)
	writer := NewWebSocketWriter(conn, writeCh)
	writer.Start()

	// Send messages in order
	numMessages := 100
	for i := 0; i < numMessages; i++ {
		err := writer.WriteJSON(map[string]int{"id": i})
		if err != nil {
			t.Errorf("Failed to send message %d: %v", i, err)
		}
	}

	// Allow time for all messages to be sent
	time.Sleep(100 * time.Millisecond)

	// Stop the writer to ensure all messages are flushed
	writer.Stop()

	// Verify message order
	mu.Lock()
	defer mu.Unlock()

	if len(receivedMessages) != numMessages {
		t.Errorf("Expected %d messages, got %d", numMessages, len(receivedMessages))
	}

	for i, msg := range receivedMessages {
		if msg != i {
			t.Errorf("Message out of order: expected %d, got %d at position %d", i, msg, i)
		}
	}

	// Caller should close the channel
	close(writeCh)
}

func TestWebSocketWriter_ResourceCleanup(t *testing.T) {
	// Create a test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Failed to upgrade: %v", err)
		}
		defer conn.Close()

		// Keep connection alive briefly
		time.Sleep(50 * time.Millisecond)
	}))
	defer server.Close()

	// Connect to test server
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Create WebSocketWriter with buffered channel
	writeCh := make(chan interface{}, 1000)
	writer := NewWebSocketWriter(conn, writeCh)
	writer.Start()

	// Send some messages
	for i := 0; i < 10; i++ {
		err := writer.WriteJSON(map[string]int{"id": i})
		if err != nil {
			t.Errorf("Failed to send message %d: %v", i, err)
		}
	}

	// Stop the writer
	writer.Stop()

	// Test that we can call WriteJSON many times after Stop without panic
	for i := 0; i < 100; i++ {
		writer.WriteJSON(map[string]int{"after_stop": i})
	}

	// Test concurrent writes after stop - should not panic
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			writer.WriteJSON(map[string]int{"concurrent": id})
		}(i)
	}
	wg.Wait()

	// Caller closes the channel
	close(writeCh)

	t.Log("All writes after stop completed without panic - resource cleanup test passed")
}
