package proxy

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
)

/*
Port Forwarding Implementation

This implementation uses context-based cancellation for optimal performance and immediate shutdown response.

Implementation Details:
- TCP: listener.Close() immediately interrupts Accept() calls
- UDP: packetConn.Close() immediately interrupts ReadFrom() calls
- Error detection: Check for "use of closed network connection" string
- Context cancellation: Use context.Context for graceful shutdown coordination
*/

// PortForwardManager manages port forwarding for clients
type PortForwardManager struct {
	// Map of client ID to their forwarded ports
	clientPorts map[string]map[int]*PortListener
	// Map of port to client ID (for conflict detection)
	portOwners map[int]string
	mutex      sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
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
	Client     *ClientConn
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewPortForwardManager creates a new port forwarding manager
func NewPortForwardManager() *PortForwardManager {
	ctx, cancel := context.WithCancel(context.Background())
	manager := &PortForwardManager{
		clientPorts: make(map[string]map[int]*PortListener),
		portOwners:  make(map[int]string),
		ctx:         ctx,
		cancel:      cancel,
	}
	logger.Info("Port forwarding manager created")
	return manager
}

// OpenPorts opens the requested ports for a client
func (pm *PortForwardManager) OpenPorts(client *ClientConn, openPorts []config.OpenPort) error {
	if client == nil {
		logger.Error("Port opening failed: client cannot be nil")
		return fmt.Errorf("client cannot be nil")
	}

	logger.Info("Opening ports", "client", client.ID, "count", len(openPorts))

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if manager is shutting down
	select {
	case <-pm.ctx.Done():
		logger.Warn("Port opening rejected: manager shutting down", "client", client.ID)
		return fmt.Errorf("port forward manager is shutting down")
	default:
	}

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
				logger.Warn("Port conflict", "client", client.ID, "port", openPort.RemotePort, "owner", existingClientID)
				errors = append(errors, fmt.Errorf("port %d already in use by client %s", openPort.RemotePort, existingClientID))
				continue
			}
			// Same client requesting same port - skip
			logger.Debug("Port already opened", "port", openPort.RemotePort, "client", client.ID)
			continue
		}

		// Create port listener
		portListener, err := pm.createPortListener(client, openPort)
		if err != nil {
			logger.Error("Failed to create port listener", "client", client.ID, "port", openPort.RemotePort, "err", err)
			errors = append(errors, fmt.Errorf("failed to open port %d: %v", openPort.RemotePort, err))
			continue
		}

		// Register the port
		pm.clientPorts[client.ID][openPort.RemotePort] = portListener
		pm.portOwners[openPort.RemotePort] = client.ID
		successfulPorts = append(successfulPorts, portListener)

		logger.Info("Port forwarding created", "client", client.ID, "port", openPort.RemotePort, "target", fmt.Sprintf("%s:%d", openPort.LocalHost, openPort.LocalPort))
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
		logger.Error("Port opening failed", "client", client.ID, "errors", len(errors))
		return fmt.Errorf("failed to open some ports: %v", errors)
	}

	logger.Info("All ports opened", "client", client.ID, "count", len(successfulPorts))
	return nil
}

// createPortListener creates a new port listener
func (pm *PortForwardManager) createPortListener(client *ClientConn, openPort config.OpenPort) (*PortListener, error) {
	// Support both TCP and UDP
	if openPort.Protocol != ProtocolTCP && openPort.Protocol != ProtocolUDP {
		logger.Error("Unsupported protocol", "client", client.ID, "port", openPort.RemotePort, "protocol", openPort.Protocol)
		return nil, fmt.Errorf("protocol %s not supported, only TCP and UDP are supported", openPort.Protocol)
	}

	ctx, cancel := context.WithCancel(pm.ctx)
	addr := fmt.Sprintf(":%d", openPort.RemotePort)
	portListener := &PortListener{
		Port:      openPort.RemotePort,
		Protocol:  openPort.Protocol,
		ClientID:  client.ID,
		LocalHost: openPort.LocalHost,
		LocalPort: openPort.LocalPort,
		Client:    client,
		ctx:       ctx,
		cancel:    cancel,
	}

	if openPort.Protocol == ProtocolTCP {
		// Create TCP listener
		listener, err := net.Listen(ProtocolTCP, addr)
		if err != nil {
			logger.Error("Failed to create TCP listener", "client", client.ID, "port", openPort.RemotePort, "err", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on TCP port %d: %v", openPort.RemotePort, err)
		}
		portListener.Listener = listener
	} else { // UDP
		// Create UDP listener
		packetConn, err := net.ListenPacket("udp", addr)
		if err != nil {
			logger.Error("Failed to create UDP listener", "client", client.ID, "port", openPort.RemotePort, "err", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on UDP port %d: %v", openPort.RemotePort, err)
		}
		portListener.PacketConn = packetConn
	}

	return portListener, nil
}

// handlePortListener handles incoming connections on a forwarded port
func (pm *PortForwardManager) handlePortListener(portListener *PortListener) {
	defer func() {
		// Cancel the port listener context
		portListener.cancel()

		// Close the appropriate connection based on protocol
		if portListener.Protocol == ProtocolTCP && portListener.Listener != nil {
			if err := portListener.Listener.Close(); err != nil {
				logger.Warn("Error closing TCP listener", "port", portListener.Port, "err", err)
			}
		} else if portListener.PacketConn != nil {
			if err := portListener.PacketConn.Close(); err != nil {
				logger.Warn("Error closing UDP packet connection", "port", portListener.Port, "err", err)
			}
		}

		logger.Info("Port listener stopped", "port", portListener.Port, "client", portListener.ClientID)
	}()

	logger.Info("Port forwarding started", "port", portListener.Port, "protocol", portListener.Protocol, "client", portListener.ClientID, "target", net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort)))

	if portListener.Protocol == ProtocolTCP {
		pm.handleTCPPortListener(portListener)
	} else {
		pm.handleUDPPortListener(portListener)
	}
}

// handleTCPPortListener handles incoming connections on a forwarded TCP port
// Uses context for cancellation and direct listener closure for optimal performance
func (pm *PortForwardManager) handleTCPPortListener(portListener *PortListener) {
	// Create channels for async operations
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)

	// Start accepting connections in a separate goroutine
	go func() {
		defer close(connCh)
		defer close(errCh)

		for {
			conn, err := portListener.Listener.Accept()
			if err != nil {
				select {
				case errCh <- err:
				case <-portListener.ctx.Done():
				}
				return
			}

			select {
			case connCh <- conn:
			case <-portListener.ctx.Done():
				if err := conn.Close(); err != nil {
					logger.Debug("Error closing connection during shutdown (expected)", "err", err)
				}
				return
			}
		}
	}()

	for {
		select {
		case <-portListener.ctx.Done():
			return
		case conn, ok := <-connCh:
			if !ok {
				return
			}
			// Handle the connection asynchronously
			pm.wg.Add(1)
			go func(incomingConn net.Conn) {
				defer pm.wg.Done()
				pm.handleForwardedConnection(portListener, incomingConn)
			}(conn)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			// Check if the error is due to listener being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			logger.Error("Error accepting connection", "port", portListener.Port, "err", err)
			return
		}
	}
}

// handleUDPPortListener handles incoming connections on a forwarded UDP port
// Uses context for cancellation and direct connection closure for optimal performance
func (pm *PortForwardManager) handleUDPPortListener(portListener *PortListener) {
	buffer := make([]byte, 65536) // Maximum UDP packet size

	// Create channels for async operations
	type udpPacket struct {
		data []byte
		addr net.Addr
	}
	packetCh := make(chan udpPacket, 10)
	errCh := make(chan error, 1)

	// Start reading packets in a separate goroutine
	go func() {
		defer close(packetCh)
		defer close(errCh)

		for {
			n, addr, err := portListener.PacketConn.ReadFrom(buffer)
			if err != nil {
				select {
				case errCh <- err:
				case <-portListener.ctx.Done():
				}
				return
			}

			// Make a copy of the data
			data := make([]byte, n)
			copy(data, buffer[:n])

			select {
			case packetCh <- udpPacket{data: data, addr: addr}:
			case <-portListener.ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-portListener.ctx.Done():
			return
		case packet, ok := <-packetCh:
			if !ok {
				return
			}
			// Handle the UDP packet asynchronously
			pm.wg.Add(1)
			go func(data []byte, clientAddr net.Addr) {
				defer pm.wg.Done()
				pm.handleUDPPacket(portListener, data, clientAddr)
			}(packet.data, packet.addr)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			// Check if the error is due to connection being closed (normal shutdown)
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			logger.Error("Error reading UDP packet", "port", portListener.Port, "err", err)
			return
		}
	}
}

// handleUDPPacket handles a single UDP packet
func (pm *PortForwardManager) handleUDPPacket(portListener *PortListener, data []byte, clientAddr net.Addr) {
	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	logger.Debug("UDP packet", "port", portListener.Port, "client", portListener.ClientID, "target", targetAddr, "size", len(data))

	// Create UDP connection to target with context
	ctx, cancel := context.WithTimeout(portListener.ctx, 30*time.Second)
	defer cancel()

	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "udp", targetAddr)
	if err != nil {
		logger.Error("Failed to create UDP connection", "port", portListener.Port, "client", portListener.ClientID, "target", targetAddr, "err", err)
		return
	}
	defer func() {
		if err := targetConn.Close(); err != nil {
			logger.Warn("Error closing target connection", "err", err)
		}
	}()

	// Send data to target
	_, err = targetConn.Write(data)
	if err != nil {
		logger.Error("Failed to send UDP data", "port", portListener.Port, "err", err)
		return
	}

	// Read response from target with context deadline
	responseBuffer := make([]byte, 65536)
	n, err := targetConn.Read(responseBuffer)
	if err != nil {
		// Timeout or other error - UDP is connectionless, so this might be expected
		return
	}

	// Send response back to client
	_, err = portListener.PacketConn.WriteTo(responseBuffer[:n], clientAddr)
	if err != nil {
		logger.Error("Failed to send UDP response", "port", portListener.Port, "err", err)
		return
	}

	logger.Debug("UDP forwarded", "port", portListener.Port, "resp_size", n)
}

// handleForwardedConnection handles a connection to a forwarded port
func (pm *PortForwardManager) handleForwardedConnection(portListener *PortListener, incomingConn net.Conn) {
	defer func() {
		if err := incomingConn.Close(); err != nil {
			logger.Warn("Error closing incoming connection", "err", err)
		}
	}()

	// Create target address
	targetAddr := net.JoinHostPort(portListener.LocalHost, strconv.Itoa(portListener.LocalPort))

	logger.Info("New connection", "port", portListener.Port, "client", portListener.ClientID, "target", targetAddr, "from", incomingConn.RemoteAddr())

	// Use the client's dialNetwork method to create connection - this reuses existing logic
	clientConn, err := portListener.Client.dialNetwork(ProtocolTCP, targetAddr)
	if err != nil {
		logger.Error("Failed to connect", "port", portListener.Port, "client", portListener.ClientID, "target", targetAddr, "err", err)
		return
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			logger.Warn("Error closing client connection", "err", err)
		}
	}()

	// Create context for the connection with timeout
	ctx, cancel := context.WithTimeout(portListener.ctx, 30*time.Minute)
	defer cancel()

	// Start bidirectional data transfer
	pm.transferData(ctx, incomingConn, clientConn, portListener.Port)
}

// transferData handles bidirectional data transfer with context awareness
func (pm *PortForwardManager) transferData(ctx context.Context, conn1, conn2 net.Conn, port int) {
	var wg sync.WaitGroup

	// Copy from conn1 to conn2
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyDataWithContext(ctx, conn1, conn2, "incoming->client", port)
	}()

	// Copy from conn2 to conn1
	wg.Add(1)
	go func() {
		defer wg.Done()
		pm.copyDataWithContext(ctx, conn2, conn1, "client->incoming", port)
	}()

	// Wait for completion or context cancellation
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Normal completion
	case <-ctx.Done():
		// Context cancelled
	}
}

// copyDataWithContext copies data between connections with context awareness
func (pm *PortForwardManager) copyDataWithContext(ctx context.Context, dst, src net.Conn, direction string, port int) {
	buffer := make([]byte, 32*1024) // 32KB buffer to match other components
	totalBytes := int64(0)

	for {
		// Check context before each operation
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Set read timeout based on context
		if deadline, ok := ctx.Deadline(); ok {
			if err := src.SetReadDeadline(deadline); err != nil {
				logger.Warn("Failed to set read deadline", "err", err)
			}
		} else {
			if err := src.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				logger.Warn("Failed to set read deadline", "err", err)
			}
		}

		n, err := src.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)

			// Set write timeout based on context
			if deadline, ok := ctx.Deadline(); ok {
				if err := dst.SetWriteDeadline(deadline); err != nil {
					logger.Warn("Failed to set write deadline", "err", err)
				}
			} else {
				if err := dst.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
					logger.Warn("Failed to set write deadline", "err", err)
				}
			}

			_, writeErr := dst.Write(buffer[:n])
			if writeErr != nil {
				logger.Error("Port forward write error", "dir", direction, "port", port, "err", writeErr, "bytes", totalBytes)
				return
			}
		}

		if err != nil {
			if err != net.ErrClosed {
				logger.Debug("Port forward closed", "dir", direction, "port", port, "err", err, "bytes", totalBytes)
			}
			return
		}
	}
}

// CloseClientPorts closes all ports for a specific client
// Uses context cancellation for immediate shutdown
func (pm *PortForwardManager) CloseClientPorts(clientID string) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		return
	}

	logger.Info("Closing all ports for client", "client_id", clientID, "port_count", len(clientPortMap))

	// Close all port listeners for this client
	for port, portListener := range clientPortMap {
		// Remove from port owners
		delete(pm.portOwners, port)

		// Cancel the port listener context - this will gracefully stop all operations
		portListener.cancel()

		logger.Info("Closed port forwarding", "client_id", clientID, "port", port)
	}

	// Remove the client from clientPorts
	delete(pm.clientPorts, clientID)
}

// Stop stops the port forwarding manager
// Uses context cancellation for immediate shutdown of all ports
func (pm *PortForwardManager) Stop() {
	logger.Info("Stopping port forwarding manager")

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Cancel the main context - this will cascade to all port listeners
	pm.cancel()

	// Clear all data structures
	pm.clientPorts = make(map[string]map[int]*PortListener)
	pm.portOwners = make(map[int]string)

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		pm.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All port forwarding goroutines finished gracefully")
	case <-time.After(5 * time.Second):
		logger.Warn("Timeout waiting for port forwarding goroutines to finish")
	}

	logger.Info("Port forwarding manager stopped")
}

// GetClientPorts returns the ports currently opened by a client
func (pm *PortForwardManager) GetClientPorts(clientID string) []int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		logger.Debug("No ports found for client", "client_id", clientID)
		return nil
	}

	ports := make([]int, 0, len(clientPortMap))
	for port := range clientPortMap {
		ports = append(ports, port)
	}

	logger.Debug("Retrieved client ports", "client_id", clientID, "port_count", len(ports), "ports", ports)

	return ports
}
