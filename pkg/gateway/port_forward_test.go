package gateway

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

// Mock client for port forwarding tests
type mockPortForwardClient struct {
	*ClientConn
	dialFunc func(ctx context.Context, network, address string) (net.Conn, error)
}

func (m *mockPortForwardClient) dialNetwork(ctx context.Context, network, address string) (net.Conn, error) {
	if m.dialFunc != nil {
		return m.dialFunc(ctx, network, address)
	}
	return &mockNetConn{}, nil
}

func TestNewPortForwardManager(t *testing.T) {
	mgr := NewPortForwardManager()

	if mgr == nil {
		t.Fatal("Expected non-nil PortForwardManager")
	}

	if mgr.portOwners == nil {
		t.Error("Expected portOwners map to be initialized")
	}

	if mgr.clientPorts == nil {
		t.Error("Expected clientPorts map to be initialized")
	}
}

func TestPortForwardManager_OpenPorts(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "test-client",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	tests := []struct {
		name      string
		ports     []config.OpenPort
		wantErr   bool
		setupFunc func()
	}{
		{
			name: "open TCP port successfully",
			ports: []config.OpenPort{
				{
					RemotePort: 18080,
					LocalPort:  8080,
					LocalHost:  "localhost",
					Protocol:   "tcp",
				},
			},
			wantErr: false,
		},
		{
			name: "open UDP port successfully",
			ports: []config.OpenPort{
				{
					RemotePort: 18081,
					LocalPort:  8081,
					LocalHost:  "localhost",
					Protocol:   "udp",
				},
			},
			wantErr: false,
		},
		{
			name: "port already in use by another client",
			ports: []config.OpenPort{
				{
					RemotePort: 18082,
					LocalPort:  8082,
					LocalHost:  "localhost",
					Protocol:   "tcp",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid protocol",
			ports: []config.OpenPort{
				{
					RemotePort: 18083,
					LocalPort:  8083,
					LocalHost:  "localhost",
					Protocol:   "invalid",
				},
			},
			wantErr: true,
		},
		{
			name:    "empty ports list",
			ports:   []config.OpenPort{},
			wantErr: false,
		},
	}

	// Pre-register port for conflict test
	mgr.portOwners[PortKey{Port: 18082, Protocol: "tcp"}] = "another-client"

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			err := mgr.OpenPorts(client.ClientConn, tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("OpenPorts() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Clean up opened ports
			if err == nil {
				mgr.CloseClientPorts(client.ID)
			}
		})
	}
}

func TestPortForwardManager_CloseClientPorts(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "test-client",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	// Open a port first
	ports := []config.OpenPort{
		{
			RemotePort: 18090,
			LocalPort:  8090,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
	}

	err := mgr.OpenPorts(client.ClientConn, ports)
	if err != nil {
		t.Fatalf("Failed to open ports: %v", err)
	}

	// Verify port is open
	portKey := PortKey{Port: 18090, Protocol: "tcp"}
	if _, exists := mgr.portOwners[portKey]; !exists {
		t.Error("Port should be registered")
	}

	// Close client ports
	mgr.CloseClientPorts(client.ID)

	// Verify port is closed
	if _, exists := mgr.portOwners[portKey]; exists {
		t.Error("Port should be removed after closing")
	}

	// Verify client entry is removed
	if _, exists := mgr.clientPorts[client.ID]; exists {
		t.Error("Client ports entry should be removed")
	}
}

func TestPortForwardManager_Stop(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client1 := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "client1",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	client2 := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "client2",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	// Open ports for multiple clients
	ports1 := []config.OpenPort{
		{
			RemotePort: 18091,
			LocalPort:  8091,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
	}

	ports2 := []config.OpenPort{
		{
			RemotePort: 18092,
			LocalPort:  8092,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
	}

	mgr.OpenPorts(client1.ClientConn, ports1)
	mgr.OpenPorts(client2.ClientConn, ports2)

	// Stop the manager
	mgr.Stop()

	// Verify all ports are closed
	if len(mgr.portOwners) != 0 {
		t.Errorf("Expected 0 ports after Stop, got %d", len(mgr.portOwners))
	}

	// Verify all client entries are removed
	if len(mgr.clientPorts) != 0 {
		t.Errorf("Expected 0 client entries after Stop, got %d", len(mgr.clientPorts))
	}
}

func TestPortForwardManager_GetClientPorts(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "test-client",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	// Initially no ports
	ports := mgr.GetClientPorts(client.ID)
	if len(ports) != 0 {
		t.Errorf("Expected 0 ports initially, got %d", len(ports))
	}

	// Open some ports
	openPorts := []config.OpenPort{
		{
			RemotePort: 18093,
			LocalPort:  8093,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
		{
			RemotePort: 18094,
			LocalPort:  8094,
			LocalHost:  "localhost",
			Protocol:   "udp",
		},
	}

	err := mgr.OpenPorts(client.ClientConn, openPorts)
	if err != nil {
		t.Fatalf("Failed to open ports: %v", err)
	}

	// Get client ports
	ports = mgr.GetClientPorts(client.ID)
	if len(ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(ports))
	}

	// Clean up
	mgr.CloseClientPorts(client.ID)
}

func TestPortForwardManager_ConcurrentOperations(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test concurrent port operations
	done := make(chan bool, 3)

	// Goroutine 1: Open ports
	go func() {
		client := &mockPortForwardClient{
			ClientConn: &ClientConn{
				ID:      "client1",
				GroupID: "test-group",
				ctx:     ctx,
				cancel:  cancel,
			},
		}

		ports := []config.OpenPort{
			{
				RemotePort: 18097,
				LocalPort:  8097,
				LocalHost:  "localhost",
				Protocol:   "tcp",
			},
		}

		mgr.OpenPorts(client.ClientConn, ports)
		done <- true
	}()

	// Goroutine 2: Get client ports
	go func() {
		time.Sleep(50 * time.Millisecond) // Give time for ports to open
		ports := mgr.GetClientPorts("client1")
		_ = ports // Just access it
		done <- true
	}()

	// Goroutine 3: Close ports
	go func() {
		time.Sleep(100 * time.Millisecond) // Give time for operations
		mgr.CloseClientPorts("client1")
		done <- true
	}()

	// Wait for all operations to complete
	for i := 0; i < 3; i++ {
		select {
		case <-done:
			// Success
		case <-time.After(2 * time.Second):
			t.Fatal("Concurrent operation timeout")
		}
	}
}

// TestPortForwardManager_SamePortDifferentProtocols tests that the same port number
// can be used for both TCP and UDP simultaneously
func TestPortForwardManager_SamePortDifferentProtocols(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "test-client",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	// Open both TCP and UDP on the same port number
	ports := []config.OpenPort{
		{
			RemotePort: 19000,
			LocalPort:  9000,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
		{
			RemotePort: 19000,
			LocalPort:  9001,
			LocalHost:  "localhost",
			Protocol:   "udp",
		},
	}

	err := mgr.OpenPorts(client.ClientConn, ports)
	if err != nil {
		t.Fatalf("Should be able to open same port for different protocols: %v", err)
	}

	// Verify both ports are registered
	tcpKey := PortKey{Port: 19000, Protocol: "tcp"}
	udpKey := PortKey{Port: 19000, Protocol: "udp"}

	if _, exists := mgr.portOwners[tcpKey]; !exists {
		t.Error("TCP port should be registered")
	}

	if _, exists := mgr.portOwners[udpKey]; !exists {
		t.Error("UDP port should be registered")
	}

	// Verify GetClientPorts returns both protocols
	clientPorts := mgr.GetClientPorts(client.ID)
	if len(clientPorts) != 2 {
		t.Errorf("Expected 2 port entries (TCP and UDP), got %d", len(clientPorts))
	}

	// Test that another client cannot use the same port+protocol combinations
	anotherClient := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "another-client",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	conflictPorts := []config.OpenPort{
		{
			RemotePort: 19000,
			LocalPort:  9002,
			LocalHost:  "localhost",
			Protocol:   "tcp", // Should conflict with existing TCP port
		},
	}

	err = mgr.OpenPorts(anotherClient.ClientConn, conflictPorts)
	if err == nil {
		t.Error("Should not be able to open already used port+protocol combination")
	}

	// But should be able to use a different protocol on the same port if not already taken
	// (In this case, both TCP and UDP are already taken by the first client)

	// Clean up
	mgr.CloseClientPorts(client.ID)

	// After cleanup, verify ports are removed
	if _, exists := mgr.portOwners[tcpKey]; exists {
		t.Error("TCP port should be removed after cleanup")
	}
	if _, exists := mgr.portOwners[udpKey]; exists {
		t.Error("UDP port should be removed after cleanup")
	}
}

// TestPortForwardManager_ProtocolSpecificOperations tests protocol-specific operations
func TestPortForwardManager_ProtocolSpecificOperations(t *testing.T) {
	mgr := NewPortForwardManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client1 := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "client1",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	client2 := &mockPortForwardClient{
		ClientConn: &ClientConn{
			ID:      "client2",
			GroupID: "test-group",
			ctx:     ctx,
			cancel:  cancel,
		},
	}

	// Client1 opens TCP on port 19001
	ports1 := []config.OpenPort{
		{
			RemotePort: 19001,
			LocalPort:  9003,
			LocalHost:  "localhost",
			Protocol:   "tcp",
		},
	}

	err := mgr.OpenPorts(client1.ClientConn, ports1)
	if err != nil {
		t.Fatalf("Failed to open TCP port for client1: %v", err)
	}

	// Client2 should be able to open UDP on the same port number
	ports2 := []config.OpenPort{
		{
			RemotePort: 19001,
			LocalPort:  9004,
			LocalHost:  "localhost",
			Protocol:   "udp",
		},
	}

	err = mgr.OpenPorts(client2.ClientConn, ports2)
	if err != nil {
		t.Fatalf("Should be able to open UDP port when TCP is already taken by another client: %v", err)
	}

	// Verify port ownership
	tcpKey := PortKey{Port: 19001, Protocol: "tcp"}
	udpKey := PortKey{Port: 19001, Protocol: "udp"}

	if owner := mgr.portOwners[tcpKey]; owner != client1.ID {
		t.Errorf("TCP port should be owned by client1, got %s", owner)
	}

	if owner := mgr.portOwners[udpKey]; owner != client2.ID {
		t.Errorf("UDP port should be owned by client2, got %s", owner)
	}

	// Clean up
	mgr.CloseClientPorts(client1.ID)
	mgr.CloseClientPorts(client2.ID)
}
