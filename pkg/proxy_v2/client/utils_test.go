package client

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestGetClientID(t *testing.T) {
	tests := []struct {
		name       string
		actualID   string
		configID   string
		expectedID string
	}{
		{
			name:       "with actualID set",
			actualID:   "actual-client-id",
			configID:   "config-client-id",
			expectedID: "actual-client-id",
		},
		{
			name:       "without actualID",
			actualID:   "",
			configID:   "config-client-id",
			expectedID: "config-client-id",
		},
		{
			name:       "both empty",
			actualID:   "",
			configID:   "",
			expectedID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				actualID: tt.actualID,
				config: &config.ClientConfig{
					ClientID: tt.configID,
				},
			}

			id := client.getClientID()

			if id != tt.expectedID {
				t.Errorf("getClientID() = %s, want %s", id, tt.expectedID)
			}
		})
	}
}

func TestGenerateClientID(t *testing.T) {
	tests := []struct {
		name       string
		clientID   string
		replicaIdx int
	}{
		{
			name:       "basic generation",
			clientID:   "test-client",
			replicaIdx: 0,
		},
		{
			name:       "with replica index",
			clientID:   "test-client",
			replicaIdx: 5,
		},
		{
			name:       "empty client ID",
			clientID:   "",
			replicaIdx: 0,
		},
		{
			name:       "special characters in ID",
			clientID:   "test-client-@#$",
			replicaIdx: 1,
		},
		{
			name:       "large replica index",
			clientID:   "test-client",
			replicaIdx: 999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				config: &config.ClientConfig{
					ClientID: tt.clientID,
				},
				replicaIdx: tt.replicaIdx,
			}

			generatedID := client.generateClientID()

			// Check that the generated ID contains expected components
			expectedPrefix := fmt.Sprintf("%s-r%d-", tt.clientID, tt.replicaIdx)
			if !strings.HasPrefix(generatedID, expectedPrefix) {
				t.Errorf("Generated ID %s should start with %s", generatedID, expectedPrefix)
			}

			// Check that a unique suffix was added (xid format)
			suffix := strings.TrimPrefix(generatedID, expectedPrefix)
			if len(suffix) == 0 {
				t.Error("Generated ID should have a unique suffix")
			}

			// Verify format: clientID-rN-xid
			parts := strings.Split(generatedID, "-")
			if len(parts) < 3 {
				t.Errorf("Generated ID should have at least 3 parts separated by '-', got %d", len(parts))
			}

			// Generate another ID and ensure it's different
			anotherID := client.generateClientID()
			if generatedID == anotherID {
				t.Error("Two generated IDs should be different")
			}
		})
	}
}

func TestGetMessageFields(t *testing.T) {
	tests := []struct {
		name     string
		msg      map[string]interface{}
		expected []string
	}{
		{
			name:     "empty message",
			msg:      map[string]interface{}{},
			expected: []string{},
		},
		{
			name: "message with single field",
			msg: map[string]interface{}{
				"type": "connect",
			},
			expected: []string{"type"},
		},
		{
			name: "message with multiple fields",
			msg: map[string]interface{}{
				"type":    "data",
				"id":      "conn-1",
				"data":    []byte("test"),
				"network": "tcp",
			},
			expected: []string{"type", "id", "data", "network"},
		},
		{
			name: "message with various types",
			msg: map[string]interface{}{
				"string": "value",
				"number": 42,
				"float":  3.14,
				"bool":   true,
				"null":   nil,
				"array":  []int{1, 2, 3},
				"map":    map[string]string{"key": "value"},
			},
			expected: []string{"string", "number", "float", "bool", "null", "array", "map"},
		},
		{
			name: "message with special keys",
			msg: map[string]interface{}{
				"key-with-dash":       "value",
				"key_with_underscore": "value",
				"key.with.dot":        "value",
				"key@with@at":         "value",
				"":                    "empty key",
			},
			expected: []string{"key-with-dash", "key_with_underscore", "key.with.dot", "key@with@at", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := getMessageFields(tt.msg)

			// Sort both slices for comparison since map iteration order is random
			sort.Strings(fields)
			sort.Strings(tt.expected)

			if len(fields) != len(tt.expected) {
				t.Errorf("getMessageFields() returned %d fields, want %d", len(fields), len(tt.expected))
				return
			}

			for i, field := range fields {
				if field != tt.expected[i] {
					t.Errorf("Field[%d] = %s, want %s", i, field, tt.expected[i])
				}
			}
		})
	}
}

func TestGetMessageFieldsConcurrency(t *testing.T) {
	// Test that getMessageFields is safe for concurrent use
	msg := map[string]interface{}{
		"field1": "value1",
		"field2": "value2",
		"field3": "value3",
		"field4": "value4",
		"field5": "value5",
	}

	// Run multiple goroutines accessing the same message
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			fields := getMessageFields(msg)
			if len(fields) != 5 {
				t.Errorf("Expected 5 fields, got %d", len(fields))
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
