package proxy

import (
	"net"
	"testing"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestPortForwardManager(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()
	defer pm.Stop()

	// Test that the manager initializes correctly
	if pm == nil {
		t.Fatal("Failed to create port forwarding manager")
	}

	if pm.clientPorts == nil {
		t.Fatal("clientPorts map not initialized")
	}

	if pm.portOwners == nil {
		t.Fatal("portOwners map not initialized")
	}
}

func TestPortForwardManagerWithoutClient(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()
	defer pm.Stop()

	// Test opening ports without a real client (should fail gracefully)
	openPorts := []config.OpenPort{
		{
			RemotePort: 9999,
			LocalPort:  8080,
			LocalHost:  "127.0.0.1",
			Protocol:   "tcp",
		},
	}

	// This should fail because we don't have a real client
	err := pm.OpenPorts(nil, openPorts)
	if err == nil {
		t.Error("Expected error when opening ports with nil client")
	}
}

func TestPortConflictDetection(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()
	defer pm.Stop()

	// Create a mock client conn
	client1 := &ClientConn{
		ID:      "client1",
		GroupID: "group1",
	}

	client2 := &ClientConn{
		ID:      "client2",
		GroupID: "group2",
	}

	// Try to open the same port for different clients
	openPorts := []config.OpenPort{
		{
			RemotePort: 9998,
			LocalPort:  8080,
			LocalHost:  "127.0.0.1",
			Protocol:   "tcp",
		},
	}

	// First client opens port (this will fail because we don't have real connections, but we test conflict detection)
	pm.OpenPorts(client1, openPorts)

	// Manually add to port owners to simulate successful opening
	pm.portOwners[9998] = client1.ID

	// Second client tries to open same port (should detect conflict)
	err := pm.OpenPorts(client2, openPorts)
	if err == nil {
		t.Error("Expected error when trying to open conflicting port")
	}

	if !contains(err.Error(), "already in use") {
		t.Errorf("Expected 'already in use' error, got: %v", err)
	}
}

func TestClientPortCleanup(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()
	defer pm.Stop()

	clientID := "test-client"

	// Manually add some port ownership to test cleanup
	pm.clientPorts[clientID] = make(map[int]*PortListener)
	pm.portOwners[9997] = clientID

	// Create a proper TCP listener for testing
	listener, err := net.Listen("tcp", ":0") // Use available port
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	// Create a properly initialized PortListener
	pm.clientPorts[clientID][9997] = &PortListener{
		Port:     9997,
		ClientID: clientID,
		Protocol: "tcp",
		Listener: listener,
		StopCh:   make(chan struct{}),
	}

	// Test cleanup
	pm.CloseClientPorts(clientID)

	// Verify cleanup
	if _, exists := pm.clientPorts[clientID]; exists {
		t.Error("Client ports should be cleaned up")
	}

	if _, exists := pm.portOwners[9997]; exists {
		t.Error("Port ownership should be cleaned up")
	}
}

func TestGetClientPorts(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()
	defer pm.Stop()

	clientID := "test-client"

	// Test getting ports for non-existent client
	ports := pm.GetClientPorts(clientID)
	if ports != nil {
		t.Error("Expected nil for non-existent client")
	}

	// Add some ports manually with proper initialization
	pm.clientPorts[clientID] = make(map[int]*PortListener)

	// Create proper listeners for testing
	listener1, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener1: %v", err)
	}
	defer listener1.Close()

	packetConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test packet conn: %v", err)
	}
	defer packetConn.Close()

	pm.clientPorts[clientID][9001] = &PortListener{
		Port:     9001,
		ClientID: clientID,
		Protocol: "tcp",
		Listener: listener1,
		StopCh:   make(chan struct{}),
	}
	pm.clientPorts[clientID][9002] = &PortListener{
		Port:       9002,
		ClientID:   clientID,
		Protocol:   "udp",
		PacketConn: packetConn,
		StopCh:     make(chan struct{}),
	}

	// Test getting ports
	ports = pm.GetClientPorts(clientID)
	if len(ports) != 2 {
		t.Errorf("Expected 2 ports, got %d", len(ports))
	}

	// Verify ports are correct
	expectedPorts := map[int]bool{9001: true, 9002: true}
	for _, port := range ports {
		if !expectedPorts[port] {
			t.Errorf("Unexpected port: %d", port)
		}
	}
}

func TestPortForwardManagerStop(t *testing.T) {
	// Create a port forwarding manager
	pm := NewPortForwardManager()

	// Add some test data with proper initialization
	clientID := "test-client"
	pm.clientPorts[clientID] = make(map[int]*PortListener)

	// Create a proper listener for testing
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	pm.clientPorts[clientID][9000] = &PortListener{
		Port:     9000,
		ClientID: clientID,
		Protocol: "tcp",
		Listener: listener,
		StopCh:   make(chan struct{}),
	}
	pm.portOwners[9000] = clientID

	// Test stop
	pm.Stop()

	// Verify cleanup
	if len(pm.clientPorts) != 0 {
		t.Error("All client ports should be cleaned up on stop")
	}

	if len(pm.portOwners) != 0 {
		t.Error("All port owners should be cleaned up on stop")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsMiddle(s, substr))))
}

func containsMiddle(s, substr string) bool {
	for i := 1; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
