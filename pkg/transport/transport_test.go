package transport

import (
	"crypto/tls"
	"fmt"
	"sync"
	"testing"
)

// Mock transport for testing
type mockTransport struct {
	authConfig *AuthConfig
	closed     bool
}

func (m *mockTransport) ListenAndServe(addr string, handler func(Connection)) error {
	return nil
}

func (m *mockTransport) ListenAndServeWithTLS(addr string, handler func(Connection), tlsConfig *tls.Config) error {
	return nil
}

func (m *mockTransport) DialWithConfig(addr string, config *ClientConfig) (Connection, error) {
	return nil, nil
}

func (m *mockTransport) Close() error {
	m.closed = true
	return nil
}

func TestRegisterTransportCreator(t *testing.T) {
	// Clear existing creators
	transportMutex.Lock()
	transportCreatorMap = make(map[string]Creator)
	transportMutex.Unlock()

	// Test registration
	testCreator := func(authConfig *AuthConfig) Transport {
		return &mockTransport{authConfig: authConfig}
	}

	RegisterTransportCreator("test-transport", testCreator)

	// Verify registration
	transportMutex.RLock()
	creator, exists := transportCreatorMap["test-transport"]
	transportMutex.RUnlock()

	if !exists {
		t.Error("Transport creator was not registered")
	}

	if creator == nil {
		t.Error("Registered creator is nil")
	}
}

func TestCreateTransport(t *testing.T) {
	// Clear and setup
	transportMutex.Lock()
	transportCreatorMap = make(map[string]Creator)
	transportMutex.Unlock()

	authConfig := &AuthConfig{
		Username: "testuser",
		Password: "testpass",
	}

	// Register test transport
	RegisterTransportCreator("test-transport", func(config *AuthConfig) Transport {
		return &mockTransport{authConfig: config}
	})

	tests := []struct {
		name          string
		transportName string
		expectNil     bool
	}{
		{
			name:          "create registered transport",
			transportName: "test-transport",
			expectNil:     false,
		},
		{
			name:          "create unregistered transport",
			transportName: "unknown-transport",
			expectNil:     true,
		},
		{
			name:          "create with empty name uses default",
			transportName: "",
			expectNil:     true, // Default is not registered in test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := CreateTransport(tt.transportName, authConfig)

			if tt.expectNil && transport != nil {
				t.Error("Expected nil transport")
			}

			if !tt.expectNil && transport == nil {
				t.Error("Expected non-nil transport")
			}

			if transport != nil {
				mockT, ok := transport.(*mockTransport)
				if !ok {
					t.Error("Transport is not of expected type")
				}

				if mockT.authConfig != authConfig {
					t.Error("Auth config was not passed correctly")
				}
			}
		})
	}
}

func TestGetRegisteredTransports(t *testing.T) {
	// Clear and setup
	transportMutex.Lock()
	transportCreatorMap = make(map[string]Creator)
	transportMutex.Unlock()

	// Register multiple transports
	RegisterTransportCreator("transport1", func(config *AuthConfig) Transport {
		return &mockTransport{}
	})
	RegisterTransportCreator("transport2", func(config *AuthConfig) Transport {
		return &mockTransport{}
	})
	RegisterTransportCreator("transport3", func(config *AuthConfig) Transport {
		return &mockTransport{}
	})

	registered := getRegisteredTransports()

	if len(registered) != 3 {
		t.Errorf("Expected 3 registered transports, got %d", len(registered))
	}

	// Check all transports are present
	transportMap := make(map[string]bool)
	for _, name := range registered {
		transportMap[name] = true
	}

	expectedTransports := []string{"transport1", "transport2", "transport3"}
	for _, expected := range expectedTransports {
		if !transportMap[expected] {
			t.Errorf("Expected transport %s not found in registered list", expected)
		}
	}
}

func TestConcurrentTransportRegistration(t *testing.T) {
	// Clear existing
	transportMutex.Lock()
	transportCreatorMap = make(map[string]Creator)
	transportMutex.Unlock()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent registration
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			name := fmt.Sprintf("transport-%d", index)
			RegisterTransportCreator(name, func(config *AuthConfig) Transport {
				return &mockTransport{}
			})
		}(i)
	}

	wg.Wait()

	// Verify all registrations succeeded
	registered := getRegisteredTransports()
	if len(registered) != numGoroutines {
		t.Errorf("Expected %d registered transports, got %d", numGoroutines, len(registered))
	}
}

func TestConcurrentTransportCreation(t *testing.T) {
	// Clear and setup
	transportMutex.Lock()
	transportCreatorMap = make(map[string]Creator)
	transportMutex.Unlock()

	// Register a transport
	RegisterTransportCreator("concurrent-test", func(config *AuthConfig) Transport {
		return &mockTransport{authConfig: config}
	})

	var wg sync.WaitGroup
	numGoroutines := 10

	// Test concurrent creation
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			authConfig := &AuthConfig{
				Username: "user",
				Password: "pass",
			}

			transport := CreateTransport("concurrent-test", authConfig)
			if transport == nil {
				t.Error("Failed to create transport concurrently")
			}
		}()
	}

	wg.Wait()
}
