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
	slog.Info("Creating new port forwarding manager")

	ctx, cancel := context.WithCancel(context.Background())
	manager := &PortForwardManager{
		clientPorts: make(map[string]map[int]*PortListener),
		portOwners:  make(map[int]string),
		ctx:         ctx,
		cancel:      cancel,
	}

	slog.Debug("Port forwarding manager initialized successfully",
		"client_ports_capacity", len(manager.clientPorts),
		"port_owners_capacity", len(manager.portOwners))

	return manager
}

// OpenPorts opens the requested ports for a client
func (pm *PortForwardManager) OpenPorts(client *ClientConn, openPorts []config.OpenPort) error {
	openStart := time.Now()

	if client == nil {
		slog.Error("Port opening failed: client cannot be nil")
		return fmt.Errorf("client cannot be nil")
	}

	slog.Info("Opening ports for client",
		"client_id", client.ID,
		"port_count", len(openPorts))

	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	// Check if manager is shutting down
	select {
	case <-pm.ctx.Done():
		slog.Warn("Port opening rejected: manager is shutting down",
			"client_id", client.ID)
		return fmt.Errorf("port forward manager is shutting down")
	default:
	}

	// Initialize client ports map if it doesn't exist
	if pm.clientPorts[client.ID] == nil {
		pm.clientPorts[client.ID] = make(map[int]*PortListener)
		slog.Debug("Initialized port map for new client", "client_id", client.ID)
	}

	var errors []error
	successfulPorts := []*PortListener{}
	conflictPorts := []int{}
	duplicatePorts := []int{}

	// Log details of each port request
	for i, openPort := range openPorts {
		slog.Debug("Processing port request",
			"client_id", client.ID,
			"port_index", i,
			"remote_port", openPort.RemotePort,
			"local_host", openPort.LocalHost,
			"local_port", openPort.LocalPort,
			"protocol", openPort.Protocol)
	}

	for _, openPort := range openPorts {
		// Check if port is already in use
		if existingClientID, exists := pm.portOwners[openPort.RemotePort]; exists {
			if existingClientID != client.ID {
				conflictPorts = append(conflictPorts, openPort.RemotePort)
				slog.Warn("Port conflict detected",
					"client_id", client.ID,
					"port", openPort.RemotePort,
					"existing_owner", existingClientID)
				errors = append(errors, fmt.Errorf("port %d already in use by client %s", openPort.RemotePort, existingClientID))
				continue
			}
			// Same client requesting same port - skip
			duplicatePorts = append(duplicatePorts, openPort.RemotePort)
			slog.Info("Port already opened by same client",
				"port", openPort.RemotePort,
				"client_id", client.ID)
			continue
		}

		// Create port listener
		slog.Debug("Creating port listener",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"protocol", openPort.Protocol)

		createStart := time.Now()
		portListener, err := pm.createPortListener(client, openPort)
		createDuration := time.Since(createStart)

		if err != nil {
			slog.Error("Failed to create port listener",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"protocol", openPort.Protocol,
				"create_duration", createDuration,
				"error", err)
			errors = append(errors, fmt.Errorf("failed to open port %d: %v", openPort.RemotePort, err))
			continue
		}

		// Register the port
		pm.clientPorts[client.ID][openPort.RemotePort] = portListener
		pm.portOwners[openPort.RemotePort] = client.ID
		successfulPorts = append(successfulPorts, portListener)

		slog.Info("Port forwarding created successfully",
			"client_id", client.ID,
			"remote_port", openPort.RemotePort,
			"local_host", openPort.LocalHost,
			"local_port", openPort.LocalPort,
			"protocol", openPort.Protocol,
			"create_duration", createDuration)
	}

	// Start listening on successful ports
	slog.Debug("Starting listeners for successful ports",
		"client_id", client.ID,
		"successful_count", len(successfulPorts))

	for i, portListener := range successfulPorts {
		slog.Debug("Starting port listener",
			"client_id", client.ID,
			"port", portListener.Port,
			"listener_index", i)

		pm.wg.Add(1)
		go func(pl *PortListener) {
			defer pm.wg.Done()
			pm.handlePortListener(pl)
		}(portListener)
	}

	elapsed := time.Since(openStart)

	// If we have any errors, return them
	if len(errors) > 0 {
		slog.Error("Port opening completed with errors",
			"client_id", client.ID,
			"requested_ports", len(openPorts),
			"successful_ports", len(successfulPorts),
			"error_count", len(errors),
			"conflict_ports", conflictPorts,
			"duplicate_ports", duplicatePorts,
			"duration", elapsed)
		return fmt.Errorf("failed to open some ports: %v", errors)
	}

	slog.Info("All ports opened successfully",
		"client_id", client.ID,
		"successful_ports", len(successfulPorts),
		"duplicate_ports", len(duplicatePorts),
		"total_requested", len(openPorts),
		"duration", elapsed)

	return nil
}

// createPortListener creates a new port listener
func (pm *PortForwardManager) createPortListener(client *ClientConn, openPort config.OpenPort) (*PortListener, error) {
	slog.Debug("Creating port listener",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"protocol", openPort.Protocol,
		"local_target", fmt.Sprintf("%s:%d", openPort.LocalHost, openPort.LocalPort))

	// Support both TCP and UDP
	if openPort.Protocol != "tcp" && openPort.Protocol != "udp" {
		slog.Error("Unsupported protocol for port forwarding",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"protocol", openPort.Protocol,
			"supported_protocols", []string{"tcp", "udp"})
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

	slog.Debug("Port listener structure created",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"bind_addr", addr)

	if openPort.Protocol == "tcp" {
		// Create TCP listener
		slog.Debug("Creating TCP listener",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"bind_addr", addr)

		listenStart := time.Now()
		listener, err := net.Listen("tcp", addr)
		listenDuration := time.Since(listenStart)

		if err != nil {
			slog.Error("Failed to create TCP listener",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"bind_addr", addr,
				"listen_duration", listenDuration,
				"error", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on TCP port %d: %v", openPort.RemotePort, err)
		}
		portListener.Listener = listener

		slog.Debug("TCP listener created successfully",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"listen_duration", listenDuration,
			"local_addr", listener.Addr())
	} else { // UDP
		// Create UDP listener
		slog.Debug("Creating UDP packet connection",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"bind_addr", addr)

		listenStart := time.Now()
		packetConn, err := net.ListenPacket("udp", addr)
		listenDuration := time.Since(listenStart)

		if err != nil {
			slog.Error("Failed to create UDP packet connection",
				"client_id", client.ID,
				"port", openPort.RemotePort,
				"bind_addr", addr,
				"listen_duration", listenDuration,
				"error", err)
			cancel()
			return nil, fmt.Errorf("failed to listen on UDP port %d: %v", openPort.RemotePort, err)
		}
		portListener.PacketConn = packetConn

		slog.Debug("UDP packet connection created successfully",
			"client_id", client.ID,
			"port", openPort.RemotePort,
			"listen_duration", listenDuration,
			"local_addr", packetConn.LocalAddr())
	}

	slog.Debug("Port listener created successfully",
		"client_id", client.ID,
		"port", openPort.RemotePort,
		"protocol", openPort.Protocol,
		"local_target", fmt.Sprintf("%s:%d", openPort.LocalHost, openPort.LocalPort))

	return portListener, nil
}

// handlePortListener handles incoming connections on a forwarded port
func (pm *PortForwardManager) handlePortListener(portListener *PortListener) {
	defer func() {
		// Cancel the port listener context
		portListener.cancel()

		// Close the appropriate connection based on protocol
		if portListener.Protocol == "tcp" && portListener.Listener != nil {
			portListener.Listener.Close()
		} else if portListener.PacketConn != nil {
			portListener.PacketConn.Close()
		}

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
				conn.Close()
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
				slog.Debug("Port listener closed", "port", portListener.Port)
				return
			}
			slog.Error("Error accepting connection on forwarded port", "port", portListener.Port, "error", err)
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
				slog.Debug("UDP port listener closed", "port", portListener.Port)
				return
			}
			slog.Error("Error reading UDP packet on forwarded port", "port", portListener.Port, "error", err)
			return
		}
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

	// Create UDP connection to target with context
	ctx, cancel := context.WithTimeout(portListener.ctx, 30*time.Second)
	defer cancel()

	var d net.Dialer
	targetConn, err := d.DialContext(ctx, "udp", targetAddr)
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

	// Read response from target with context deadline
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
		slog.Debug("Port forwarding connection finished", "port", port)
	case <-ctx.Done():
		slog.Debug("Port forwarding connection cancelled", "port", port)
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
			slog.Debug("Data copy cancelled by context", "direction", direction, "port", port, "transferred_bytes", totalBytes)
			return
		default:
		}

		// Set read timeout based on context
		if deadline, ok := ctx.Deadline(); ok {
			src.SetReadDeadline(deadline)
		} else {
			src.SetReadDeadline(time.Now().Add(30 * time.Second))
		}

		n, err := src.Read(buffer)
		if n > 0 {
			totalBytes += int64(n)

			// Set write timeout based on context
			if deadline, ok := ctx.Deadline(); ok {
				dst.SetWriteDeadline(deadline)
			} else {
				dst.SetWriteDeadline(time.Now().Add(30 * time.Second))
			}

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
// Uses context cancellation for immediate shutdown
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

		// Cancel the port listener context - this will gracefully stop all operations
		portListener.cancel()

		slog.Info("Closed port forwarding", "client_id", clientID, "port", port)
	}

	// Remove the client from clientPorts
	delete(pm.clientPorts, clientID)
}

// Stop stops the port forwarding manager
// Uses context cancellation for immediate shutdown of all ports
func (pm *PortForwardManager) Stop() {
	slog.Info("Stopping port forwarding manager")

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
		slog.Info("All port forwarding goroutines finished gracefully")
	case <-time.After(5 * time.Second):
		slog.Warn("Timeout waiting for port forwarding goroutines to finish")
	}

	slog.Info("Port forwarding manager stopped")
}

// GetClientPorts returns the ports currently opened by a client
func (pm *PortForwardManager) GetClientPorts(clientID string) []int {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	clientPortMap, exists := pm.clientPorts[clientID]
	if !exists {
		slog.Debug("No ports found for client", "client_id", clientID)
		return nil
	}

	ports := make([]int, 0, len(clientPortMap))
	for port := range clientPortMap {
		ports = append(ports, port)
	}

	slog.Debug("Retrieved client ports",
		"client_id", clientID,
		"port_count", len(ports),
		"ports", ports)

	return ports
}
