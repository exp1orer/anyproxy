package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
)

/*
Port Forwarding Implementation

This implementation uses direct listener closure for optimal performance and immediate shutdown response.

Implementation Details:
- TCP: listener.Close() immediately interrupts Accept() calls
- UDP: packetConn.Close() immediately interrupts ReadFrom() calls
- Error detection: Check for "use of closed network connection" string
- Thread safety: Use sync.Once to prevent double-closing channels
*/

// PortForwardManager manages port forwarding for clients
type PortForwardManager struct {
	// Map of client ID to their forwarded ports
	clientPorts map[string]map[int]*PortListener
	// Map of port to client ID (for conflict detection)
	portOwners map[int]string
	mutex      sync.RWMutex
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// PortListener represents a listening port for forwarding
type PortListener struct {
	Port       int
	Protocol   string
	ClientID   string
	LocalHost  string
	LocalPort  int
	Listener   net.Listener   // For TCP
	PacketConn net.PacketConn // For UDP
	StopCh     chan struct{}
	Client     *ClientConn
	stopOnce   sync.Once // Ensure channel is only closed once
}

// NewPortForwardManager creates a new port forwarding manager
func NewPortForwardManager() *PortForwardManager {
	return &PortForwardManager{
		clientPorts: make(map[string]map[int]*PortListener),
		portOwners:  make(map[int]string),
		stopCh:      make(chan struct{}),
	}
}

// OpenPorts opens the requested ports for a client
func (pm *PortForwardManager) OpenPorts(client *ClientConn, openPorts []config.OpenPort) error {
	if client == nil {
		return fmt.Errorf("client cannot be nil")
	}

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Initialize client ports map if it doesn't exist
	if pm.clientPorts[client.ID] == nil {
		pm.clientPorts[client.ID] = make(map[int]*PortListener)
	}

	var errors []error
	successfulPorts := []*PortListener{}

	for _, openPort := range openPorts {
		// Check if port is already in use
		if existingClientID, exists := pm.portOwners[openPort.RemotePort]; exists {
			if existingClientID != client.ID {
				errors = append(errors, fmt.Errorf("port %d already in use by client %s", openPort.RemotePort, existingClientID))
				continue
			}
			// Same client requesting same port - skip
			slog.Info("Port already opened by same client", "port", openPort.RemotePort, "client_id", client.ID)
			continue
		}

		// Create port listener
		portListener, err := pm.createPortListener(client, openPort)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to open port %d: %v", openPort.RemotePort, err))
			continue
		}

		// Register the port
		pm.clientPorts[client.ID][openPort.RemotePort] = portListener
		pm.portOwners[openPort.RemotePort] = client.ID
		successfulPorts = append(successfulPorts, portListener)

		slog.Info("Port forwarding opened",
			"client_id", client.ID,
			"remote_port", openPort.RemotePort,
			"local_host", openPort.LocalHost,
			"local_port", openPort.LocalPort,
			"protocol", openPort.Protocol)
	}

	// Start listening on successful ports
	for _, portListener := range successfulPorts {
		pm.wg.Add(1)
		go func(pl *PortListener) {
			defer pm.wg.Done()
			pm.handlePortListener(pl)
		}(portListener)
	}

	// If we have any errors, return them
	if len(errors) > 0 {
		return fmt.Errorf("failed to open some ports: %v", errors)
	}

	return nil
}

// createPortListener creates a new port listener
func (pm *PortForwardManager) createPortListener(client *ClientConn, openPort config.OpenPort) (*PortListener, error) {
	// Support both TCP and UDP
	if openPort.Protocol != "tcp" && openPort.Protocol != "udp" {
		return nil, fmt.Errorf("protocol %s not supported, only TCP and UDP are supported", openPort.Protocol)
	}

	addr := fmt.Sprintf(":%d", openPort.RemotePort)
	portListener := &PortListener{
		Port:      openPort.RemotePort,
		Protocol:  openPort.Protocol,
		ClientID:  client.ID,
		LocalHost: openPort.LocalHost,
		LocalPort: openPort.LocalPort,
		StopCh:    make(chan struct{}),
		Client:    client,
	}

	if openPort.Protocol == "tcp" {
		// Create TCP listener
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on TCP port %d: %v", openPort.RemotePort, err)
		}
		portListener.Listener = listener
	} else { // UDP
		// Create UDP listener
		packetConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on UDP port %d: %v", openPort.RemotePort, err)
		}
		portListener.PacketConn = packetConn
	}

	return portListener, nil
}

// handlePortListener handles incoming connections on a forwarded port
func (pm *PortForwardManager) handlePortListener(portListener *PortListener) {
	defer func() {
		// Close the appropriate connection based on protocol
		if portListener.Protocol == "tcp" {
			portListener.Listener.Close()
		} else {
			portListener.PacketConn.Close()
		}
		portListener.stopOnce.Do(func() {
			close(portListener.StopCh)
		})
		slog.Info("Port listener stopped", "port", portListener.Port, "client_id", portListener.ClientID)
	}()

	slog.Info("Started listening for port forwarding",
		"port", portListener.Port,
		"protocol", portListener.Protocol,
		"client_id", portListener.ClientID,
		"local_target", net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort)))

	if portListener.Protocol == "tcp" {
		pm.handleTCPPortListener(portListener)
	} else {
		pm.handleUDPPortListener(portListener)
	}
}

// handleTCPPortListener handles incoming connections on a forwarded TCP port
// Uses direct listener closure for optimal performance
func (pm *PortForwardManager) handleTCPPortListener(portListener *PortListener) {
	for {
		// Block on Accept() - this will be immediately interrupted when listener.Close() is called
		conn, err := portListener.Listener.Accept()
		if err != nil {
			// Check if we're stopping (listener was closed)
			select {
			case <-pm.stopCh:
				return
			case <-portListener.StopCh:
				return
			default:
			}

			// Check if the error is due to listener being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("Port listener closed", "port", portListener.Port)
				return
			}

			slog.Error("Error accepting connection on forwarded port", "port", portListener.Port, "error", err)
			continue
		}

		// Handle the connection asynchronously
		pm.wg.Add(1)
		go func(incomingConn net.Conn) {
			defer pm.wg.Done()
			pm.handleForwardedConnection(portListener, incomingConn)
		}(conn)
	}
}

// handleUDPPortListener handles incoming connections on a forwarded UDP port
// Uses direct connection closure for optimal performance
func (pm *PortForwardManager) handleUDPPortListener(portListener *PortListener) {
	buffer := make([]byte, 65536) // Maximum UDP packet size

	for {
		// Block on ReadFrom() - this will be immediately interrupted when packetConn.Close() is called
		n, addr, err := portListener.PacketConn.ReadFrom(buffer)
		if err != nil {
			// Check if we're stopping (connection was closed)
			select {
			case <-pm.stopCh:
				return
			case <-portListener.StopCh:
				return
			default:
			}

			// Check if the error is due to connection being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				slog.Debug("UDP port listener closed", "port", portListener.Port)
				return
			}

			slog.Error("Error reading UDP packet on forwarded port", "port", portListener.Port, "error", err)
			continue
		}

		// Handle the UDP packet asynchronously
		pm.wg.Add(1)
		go func(data []byte, clientAddr net.Addr) {
			defer pm.wg.Done()
			pm.handleUDPPacket(portListener, data, clientAddr)
		}(buffer[:n], addr)
	}
}

// handleUDPPacket handles a single UDP packet
func (pm *PortForwardManager) handleUDPPacket(portListener *PortListener, data []byte, clientAddr net.Addr) {
	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	slog.Debug("New UDP packet to forwarded port",
		"port", portListener.Port,
		"client_id", portListener.ClientID,
		"target", targetAddr,
		"client_addr", clientAddr,
		"data_size", len(data))

	// Create UDP connection to target
	targetConn, err := net.Dial("udp", targetAddr)
	if err != nil {
		slog.Error("Failed to create UDP connection to target",
			"port", portListener.Port,
			"client_id", portListener.ClientID,
			"target", targetAddr,
			"error", err)
		return
	}
	defer targetConn.Close()

	// Send data to target
	_, err = targetConn.Write(data)
	if err != nil {
		slog.Error("Failed to send UDP data to target",
			"port", portListener.Port,
			"error", err)
		return
	}

	// Read response from target (with timeout)
	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	responseBuffer := make([]byte, 65536)
	n, err := targetConn.Read(responseBuffer)
	if err != nil {
		// Timeout or other error - UDP is connectionless, so this might be expected
		slog.Debug("No response from UDP target", "port", portListener.Port, "error", err)
		return
	}

	// Send response back to client
	_, err = portListener.PacketConn.WriteTo(responseBuffer[:n], clientAddr)
	if err != nil {
		slog.Error("Failed to send UDP response to client",
			"port", portListener.Port,
			"error", err)
		return
	}

	slog.Debug("UDP packet forwarded successfully",
		"port", portListener.Port,
		"response_size", n)
}

// handleForwardedConnection handles a connection to a forwarded port
func (pm *PortForwardManager) handleForwardedConnection(portListener *PortListener, incomingConn net.Conn) {
	defer incomingConn.Close()

	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	slog.Info("New connection to forwarded port",
		"port", portListener.Port,
		"client_id", portListener.ClientID,
		"target", targetAddr,
		"remote_addr", incomingConn.RemoteAddr())

	// Use the client's dialNetwork method to create connection - this reuses existing logic
	clientConn, err := portListener.Client.dialNetwork("tcp", targetAddr)
	if err != nil {
		slog.Error("Failed to connect to target via client",
			"port", portListener.Port,
			"client_id", portListener.ClientID,
			"target", targetAddr,
			"error", err)
		return
	}
	defer clientConn.Close()

	// Create context for the connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start bidirectional data transfer
	var wg sync.WaitGroup

	// Copy from incoming connection to client connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyData(incomingConn, clientConn, "incoming->client", portListener.Port)
		cancel() // Signal other goroutine to stop
	}()

	// Copy from client connection to incoming connection
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyData(clientConn, incomingConn, "client->incoming", portListener.Port)
		cancel() // Signal other goroutine to stop
	}()

	// Wait for either direction to finish or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		slog.Debug("Port forwarding connection finished", "port", portListener.Port)
	case <-ctx.Done():
		slog.Debug("Port forwarding connection cancelled", "port", portListener.Port)
	case <-pm.stopCh:
		slog.Debug("Port forwarding manager stopping", "port", portListener.Port)
	}
}

// copyData copies data between connections with logging
func (pm *PortForwardManager) copyData(dst, src net.Conn, direction string, port int) {
	buffer := make([]byte, 32*1024) // 32KB buffer to match other components
	totalBytes := int64(0)

	for {
		// Set read timeout
		src.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := src.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)

			// Set write timeout
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

			_, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				slog.Error("Port forward write error",
					"direction", direction,
					"port", port,
					"error", writeErr,
					"transferred_bytes", totalBytes)
				return
			}
		}

		if err != nil {
			if err != net.ErrClosed {
				slog.Debug("Port forward connection closed",
					"direction", direction,
					"port", port,
					"error", err,
					"transferred_bytes", totalBytes)
			}
			return
		}
	}
}

// CloseClientPorts closes all ports for a specific client
// Uses direct closure for immediate shutdown
func (pm *PortForwardManager) CloseClientPorts(clientID string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		return
	}

	slog.Info("Closing all ports for client", "client_id", clientID, "port_count", len(clientPortMap))

	// Close all port listeners for this client
	for port, portListener := range clientPortMap {
		// Remove from port owners
		delete(pm.portOwners, port)

		// Direct closure - immediately interrupts Accept()/ReadFrom() calls
		portListener.stopOnce.Do(func() {
			close(portListener.StopCh)
		})

		// Close the appropriate connection based on protocol
		if portListener.Protocol == "tcp" {
			portListener.Listener.Close() // Immediate TCP listener closure
		} else {
			portListener.PacketConn.Close() // Immediate UDP connection closure
		}

		slog.Info("Closed port forwarding", "client_id", clientID, "port", port)
	}

	// Remove the client from clientPorts
	delete(pm.clientPorts, clientID)
}

// Stop stops the port forwarding manager
// Uses direct closure for immediate shutdown of all ports
func (pm *PortForwardManager) Stop() {
	slog.Info("Stopping port forwarding manager")

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Signal all goroutines to stop
	close(pm.stopCh)

	// Direct closure of all listeners and connections
	// This immediately interrupts all blocking Accept()/ReadFrom() calls
	for clientID := range pm.clientPorts {
		for port, portListener := range pm.clientPorts[clientID] {
			portListener.stopOnce.Do(func() {
				close(portListener.StopCh)
			})

			// Close the appropriate connection based on protocol
			if portListener.Protocol == "tcp" {
				portListener.Listener.Close() // Immediate TCP listener closure
			} else {
				portListener.PacketConn.Close() // Immediate UDP connection closure
			}
			slog.Info("Closed port forwarding during shutdown", "client_id", clientID, "port", port)
		}
	}

	// Clear all data structures
	pm.clientPorts = make(map[string]map[int]*PortListener)
	pm.portOwners = make(map[int]string)

	// Wait for all goroutines to finish
	pm.wg.Wait()

	slog.Info("Port forwarding manager stopped")
}

// GetClientPorts returns the ports currently opened by a client
func (pm *PortForwardManager) GetClientPorts(clientID string) []int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		return nil
	}

	ports := make([]int, 0, len(clientPortMap))
	for port := range clientPortMap {
		ports = append(ports, port)
	}
	return ports
}
