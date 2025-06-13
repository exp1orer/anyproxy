// Package protocols provides TUIC proxy implementation based on official TUIC specification
package protocols

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"crypto/sha256"

	"github.com/buhuipao/anyproxy/pkg/common/utils"
	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
)

// TUIC Protocol Constants based on official specification
const (
	// TUIC Protocol Version
	TUICVersion = 0x05

	// TUIC Command Types
	TUICCmdAuthenticate = 0x00 // for authenticating the multiplexed stream
	TUICCmdConnect      = 0x01 // for establishing a TCP relay
	TUICCmdPacket       = 0x02 // for relaying (fragmented part of) a UDP packet
	TUICCmdDissociate   = 0x03 // for terminating a UDP relaying session
	TUICCmdHeartbeat    = 0x04 // for keeping the QUIC connection alive

	// TUIC Address Types (as per official TUIC specification)
	TUICAddrNone   = 0xff // None (used in Packet commands that is not the first fragment)
	TUICAddrDomain = 0x00 // Fully-qualified domain name (first byte indicates length)
	TUICAddrIPv4   = 0x01 // IPv4 address
	TUICAddrIPv6   = 0x02 // IPv6 address

	// TUIC Authentication Constants
	TUICUUIDLength  = 16 // UUID length in bytes
	TUICTokenLength = 32 // Token length in bytes
)

// TUICProxy implements the TUIC proxy protocol
type TUICProxy struct {
	config         *config.TUICConfig
	listener       net.PacketConn
	dialFunc       func(ctx context.Context, network, addr string) (net.Conn, error)
	groupExtractor func(string) string
	running        bool
	mu             sync.Mutex
	stopCh         chan struct{}
	wg             sync.WaitGroup

	// Authentication
	authToken            []byte
	authenticatedClients map[string]*TUICClient
	clientsMu            sync.RWMutex

	// UDP sessions management
	udpSessions   map[string]map[uint16]*TUICUDPSession
	udpSessionsMu sync.RWMutex

	// Packet reassembly
	packetAssemblers map[string]map[uint16]*TUICPacketAssembler
	assemblersMu     sync.RWMutex
}

// TUICClient represents an authenticated TUIC client
type TUICClient struct {
	ID            string
	UUID          []byte
	Token         []byte
	RemoteAddr    net.Addr
	Authenticated bool
	LastSeen      time.Time
	mu            sync.Mutex
}

// TUICUDPSession represents a UDP relay session
type TUICUDPSession struct {
	AssocID    uint16
	Client     *TUICClient
	TargetConn net.PacketConn
	LastUsed   time.Time
	mu         sync.Mutex
}

// TUICPacketAssembler handles UDP packet fragmentation and reassembly
type TUICPacketAssembler struct {
	PacketID   uint16
	FragTotal  uint8
	Fragments  map[uint8][]byte
	TargetAddr *TUICAddress
	Size       uint16
	CreatedAt  time.Time
	mu         sync.Mutex
}

// TUICCommand represents a TUIC command structure
type TUICCommand struct {
	Version uint8
	Type    uint8
	Data    []byte
}

// TUICAddress represents a TUIC address structure
type TUICAddress struct {
	Type uint8
	Host string
	Port uint16
}

// TUICPacketData represents Packet command data
type TUICPacketData struct {
	AssocID   uint16
	PacketID  uint16
	FragTotal uint8
	FragID    uint8
	Size      uint16
	Address   *TUICAddress
	Payload   []byte
}

// NewTUICProxyWithAuth creates a new TUIC proxy with authentication
func NewTUICProxyWithAuth(cfg *config.TUICConfig, dialFn func(context.Context, string, string) (net.Conn, error), groupExtractor func(string) string) (utils.GatewayProxy, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("TUIC token is required")
	}
	if cfg.UUID == "" {
		return nil, fmt.Errorf("TUIC UUID is required")
	}
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("TUIC listen address is required")
	}

	// Hash the token for authentication
	tokenHash := sha256.Sum256([]byte(cfg.Token))

	proxy := &TUICProxy{
		config:               cfg,
		dialFunc:             dialFn,
		groupExtractor:       groupExtractor,
		authToken:            tokenHash[:],
		authenticatedClients: make(map[string]*TUICClient),
		udpSessions:          make(map[string]map[uint16]*TUICUDPSession),
		packetAssemblers:     make(map[string]map[uint16]*TUICPacketAssembler),
		stopCh:               make(chan struct{}),
	}

	return proxy, nil
}

// Start starts the TUIC proxy
func (p *TUICProxy) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("TUIC proxy is already running")
	}

	// Create UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", p.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	listener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}

	p.listener = listener
	p.running = true

	logger.Info("TUIC proxy started", "listen", p.config.ListenAddr, "version", TUICVersion)

	// Start packet handling
	p.wg.Add(1)
	go p.handlePackets()

	// Start cleanup routine
	p.wg.Add(1)
	go p.cleanupRoutine()

	return nil
}

// Stop stops the TUIC proxy
func (p *TUICProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.running = false
	close(p.stopCh)

	if p.listener != nil {
		p.listener.Close()
	}

	// Close all UDP sessions
	p.udpSessionsMu.Lock()
	for _, clientSessions := range p.udpSessions {
		for _, session := range clientSessions {
			if session.TargetConn != nil {
				session.TargetConn.Close()
			}
		}
	}
	p.udpSessionsMu.Unlock()

	p.wg.Wait()

	logger.Info("TUIC proxy stopped")
	return nil
}

// IsRunning returns whether the proxy is running
func (p *TUICProxy) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// handlePackets handles incoming UDP packets
func (p *TUICProxy) handlePackets() {
	defer p.wg.Done()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-p.stopCh:
			return
		default:
			n, clientAddr, err := p.listener.ReadFrom(buffer)
			if err != nil {
				if p.isRunning() {
					logger.Error("Failed to read UDP packet", "err", err)
				}
				return
			}

			if n > 0 {
				p.handleTUICPacket(clientAddr, buffer[:n])
			}
		}
	}
}

// isRunning safely checks if the proxy is running
func (p *TUICProxy) isRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// handleTUICPacket handles a TUIC packet from client
func (p *TUICProxy) handleTUICPacket(clientAddr net.Addr, data []byte) {
	// Parse TUIC command
	cmd, err := p.parseTUICCommand(data)
	if err != nil {
		logger.Error("Failed to parse TUIC command", "client", clientAddr, "err", err)
		return
	}

	clientID := clientAddr.String()

	// Handle different command types
	switch cmd.Type {
	case TUICCmdAuthenticate:
		p.handleAuthenticate(clientAddr, clientID, cmd)
	case TUICCmdConnect:
		p.handleConnect(clientAddr, clientID, cmd)
	case TUICCmdPacket:
		p.handlePacket(clientAddr, clientID, cmd)
	case TUICCmdDissociate:
		p.handleDissociate(clientAddr, clientID, cmd)
	case TUICCmdHeartbeat:
		p.handleHeartbeat(clientAddr, clientID, cmd)
	default:
		logger.Error("Unknown TUIC command type", "client", clientAddr, "type", cmd.Type)
	}
}

// parseTUICCommand parses a TUIC command from raw data
func (p *TUICProxy) parseTUICCommand(data []byte) (*TUICCommand, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("command too short")
	}

	cmd := &TUICCommand{
		Version: data[0],
		Type:    data[1],
		Data:    data[2:],
	}

	if cmd.Version != TUICVersion {
		return nil, fmt.Errorf("unsupported protocol version: 0x%02x", cmd.Version)
	}

	return cmd, nil
}

// handleAuthenticate handles Authenticate command
func (p *TUICProxy) handleAuthenticate(clientAddr net.Addr, clientID string, cmd *TUICCommand) {
	logger.Debug("Handling TUIC Authenticate", "client", clientAddr)

	// Parse authenticate data
	if len(cmd.Data) < TUICUUIDLength+TUICTokenLength {
		logger.Error("Authenticate data too short", "client", clientAddr, "expected", TUICUUIDLength+TUICTokenLength, "actual", len(cmd.Data))
		return
	}

	uuid := cmd.Data[:TUICUUIDLength]
	token := cmd.Data[TUICUUIDLength : TUICUUIDLength+TUICTokenLength]

	// Validate token
	if !p.validateToken(token) {
		logger.Error("Authentication failed: invalid token", "client", clientAddr, "uuid", fmt.Sprintf("%x", uuid[:8]))
		return
	}

	// Create/update client
	p.clientsMu.Lock()
	client := &TUICClient{
		ID:            clientID,
		UUID:          uuid,
		Token:         token,
		RemoteAddr:    clientAddr,
		Authenticated: true,
		LastSeen:      time.Now(),
	}
	p.authenticatedClients[clientID] = client
	p.clientsMu.Unlock()

	logger.Info("Client authenticated successfully", "client", clientAddr, "uuid", fmt.Sprintf("%x", uuid[:8]))
}

// validateToken validates the authentication token
func (p *TUICProxy) validateToken(token []byte) bool {
	if len(token) != len(p.authToken) {
		return false
	}
	for i, b := range token {
		if b != p.authToken[i] {
			return false
		}
	}
	return true
}

// handleConnect handles Connect command
func (p *TUICProxy) handleConnect(clientAddr net.Addr, clientID string, cmd *TUICCommand) {
	logger.Debug("Handling TUIC Connect", "client", clientAddr)

	// Check if client is authenticated
	client := p.getAuthenticatedClient(clientID)
	if client == nil {
		logger.Error("Connect command from unauthenticated client", "client", clientAddr)
		return
	}

	// Parse address
	addr, err := p.parseAddress(cmd.Data)
	if err != nil {
		logger.Error("Failed to parse connect address", "client", clientAddr, "err", err)
		return
	}

	target := p.formatAddress(addr)
	logger.Debug("Handling TUIC Connect", "client", clientAddr, "target", target)

	// Create TCP connection to target
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	targetConn, err := p.dialFunc(ctx, "tcp", target)
	if err != nil {
		logger.Error("Failed to connect to target", "client", clientAddr, "target", target, "err", err)
		return
	}

	logger.Info("TCP connection established", "client", clientAddr, "target", target)

	// Note: In a real QUIC implementation, this would establish a bidirectional stream
	// For UDP-based simulation, we log the successful connection
	// The actual TCP relay would happen through QUIC streams
	defer targetConn.Close()
}

// getAuthenticatedClient gets an authenticated client by ID
func (p *TUICProxy) getAuthenticatedClient(clientID string) *TUICClient {
	p.clientsMu.RLock()
	defer p.clientsMu.RUnlock()

	client, exists := p.authenticatedClients[clientID]
	if !exists || !client.Authenticated {
		return nil
	}
	return client
}

// parseAddress parses a TUIC address from data
func (p *TUICProxy) parseAddress(data []byte) (*TUICAddress, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("address data too short")
	}

	addrType := data[0]

	// Handle None address type first (only needs 1 byte)
	if addrType == TUICAddrNone {
		return &TUICAddress{Type: TUICAddrNone}, nil
	}

	// Other address types need at least 3 bytes (type + port)
	if len(data) < 3 {
		return nil, fmt.Errorf("address data too short")
	}

	var host string
	var port uint16

	switch addrType {
	case TUICAddrIPv4:
		if len(data) < 7 {
			return nil, fmt.Errorf("IPv4 address too short")
		}
		ip := net.IP(data[1:5])
		host = ip.String()
		port = binary.BigEndian.Uint16(data[5:7])
	case TUICAddrIPv6:
		if len(data) < 19 {
			return nil, fmt.Errorf("IPv6 address too short")
		}
		ip := net.IP(data[1:17])
		host = ip.String()
		port = binary.BigEndian.Uint16(data[17:19])
	case TUICAddrDomain:
		if len(data) < 4 {
			return nil, fmt.Errorf("domain address too short")
		}
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return nil, fmt.Errorf("domain address truncated")
		}
		host = string(data[2 : 2+domainLen])
		port = binary.BigEndian.Uint16(data[2+domainLen : 2+domainLen+2])
	default:
		return nil, fmt.Errorf("unknown address type: 0x%02x", addrType)
	}

	return &TUICAddress{
		Type: addrType,
		Host: host,
		Port: port,
	}, nil
}

// formatAddress formats a TUIC address to host:port string
func (p *TUICProxy) formatAddress(addr *TUICAddress) string {
	if addr.Type == TUICAddrNone {
		return ""
	}
	return fmt.Sprintf("%s:%d", addr.Host, addr.Port)
}

// handlePacket handles Packet command
func (p *TUICProxy) handlePacket(clientAddr net.Addr, clientID string, cmd *TUICCommand) {
	logger.Debug("Handling TUIC Packet", "client", clientAddr)

	// Check if client is authenticated
	client := p.getAuthenticatedClient(clientID)
	if client == nil {
		logger.Error("Packet command from unauthenticated client", "client", clientAddr)
		return
	}

	// Parse packet data
	packetData, err := p.parsePacketData(cmd.Data)
	if err != nil {
		logger.Error("Failed to parse packet data", "client", clientAddr, "err", err)
		return
	}

	logger.Debug("Handling TUIC Packet", "client", clientAddr, "assoc_id", packetData.AssocID,
		"pkt_id", packetData.PacketID, "frag", fmt.Sprintf("%d/%d", packetData.FragID+1, packetData.FragTotal))

	// Handle fragmentation
	completePacket := p.handlePacketFragmentation(clientID, packetData)
	if completePacket == nil {
		// Fragmentation not complete yet
		return
	}

	// Get or create UDP session
	session := p.getOrCreateUDPSession(clientID, packetData.AssocID, client)
	if session == nil {
		logger.Error("Failed to create UDP session", "client", clientAddr, "assoc_id", packetData.AssocID)
		return
	}

	// Forward UDP packet to target
	target := p.formatAddress(completePacket.Address)
	logger.Debug("Forwarding UDP packet", "client", clientAddr, "target", target, "size", len(completePacket.Payload))

	// For UDP relay, we need to resolve the target address
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		logger.Error("Failed to resolve target UDP address", "target", target, "err", err)
		return
	}

	_, err = session.TargetConn.WriteTo(completePacket.Payload, udpAddr)
	if err != nil {
		logger.Error("Failed to forward UDP packet", "client", clientAddr, "target", target, "err", err)
		return
	}

	session.mu.Lock()
	session.LastUsed = time.Now()
	session.mu.Unlock()

	logger.Debug("UDP packet forwarded successfully", "client", clientAddr, "target", target, "bytes", len(completePacket.Payload))
}

// parsePacketData parses Packet command data
func (p *TUICProxy) parsePacketData(data []byte) (*TUICPacketData, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("packet data too short")
	}

	assocID := binary.BigEndian.Uint16(data[0:2])
	packetID := binary.BigEndian.Uint16(data[2:4])
	fragTotal := data[4]
	fragID := data[5]
	size := binary.BigEndian.Uint16(data[6:8])

	// Parse address (if this is the first fragment)
	var addr *TUICAddress
	var payload []byte

	if fragID == 0 {
		// First fragment contains address
		var err error
		addr, err = p.parseAddress(data[8:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse address: %w", err)
		}

		addrLen := p.calculateAddressLength(data[8:])
		payload = data[8+addrLen:]
	} else {
		// Subsequent fragments have no address
		payload = data[8:]
	}

	return &TUICPacketData{
		AssocID:   assocID,
		PacketID:  packetID,
		FragTotal: fragTotal,
		FragID:    fragID,
		Size:      size,
		Address:   addr,
		Payload:   payload,
	}, nil
}

// calculateAddressLength calculates the length of address in data
func (p *TUICProxy) calculateAddressLength(data []byte) int {
	if len(data) < 1 {
		return 0
	}

	addrType := data[0]
	switch addrType {
	case TUICAddrIPv4:
		return 7 // Type(1) + IPv4(4) + Port(2)
	case TUICAddrIPv6:
		return 19 // Type(1) + IPv6(16) + Port(2)
	case TUICAddrDomain:
		if len(data) < 2 {
			return 0
		}
		domainLen := int(data[1])
		return 2 + domainLen + 2 // Type(1) + Len(1) + Domain + Port(2)
	case TUICAddrNone:
		return 1 // Type(1) only
	default:
		return 0
	}
}

// handlePacketFragmentation handles UDP packet fragmentation and reassembly
func (p *TUICProxy) handlePacketFragmentation(clientID string, packetData *TUICPacketData) *TUICPacketData {
	p.assemblersMu.Lock()
	defer p.assemblersMu.Unlock()

	// Initialize client assemblers map if needed
	if p.packetAssemblers[clientID] == nil {
		p.packetAssemblers[clientID] = make(map[uint16]*TUICPacketAssembler)
	}

	assembler, exists := p.packetAssemblers[clientID][packetData.PacketID]
	if !exists {
		assembler = &TUICPacketAssembler{
			PacketID:   packetData.PacketID,
			FragTotal:  packetData.FragTotal,
			Fragments:  make(map[uint8][]byte),
			TargetAddr: packetData.Address,
			Size:       packetData.Size,
			CreatedAt:  time.Now(),
		}
		p.packetAssemblers[clientID][packetData.PacketID] = assembler
	}

	assembler.mu.Lock()
	defer assembler.mu.Unlock()

	// Store fragment
	assembler.Fragments[packetData.FragID] = packetData.Payload

	// Check if all fragments received
	if len(assembler.Fragments) == int(assembler.FragTotal) {
		// Reassemble packet
		var completePayload []byte
		for i := uint8(0); i < assembler.FragTotal; i++ {
			if fragData, exists := assembler.Fragments[i]; exists {
				completePayload = append(completePayload, fragData...)
			} else {
				// Missing fragment
				return nil
			}
		}

		// Create complete packet
		completePacket := &TUICPacketData{
			AssocID:   packetData.AssocID,
			PacketID:  packetData.PacketID,
			FragTotal: 1,
			FragID:    0,
			Size:      uint16(len(completePayload)),
			Address:   assembler.TargetAddr,
			Payload:   completePayload,
		}

		// Remove assembler
		delete(p.packetAssemblers[clientID], packetData.PacketID)
		return completePacket
	}

	return nil // Fragmentation not yet complete
}

// getOrCreateUDPSession gets or creates a UDP session
func (p *TUICProxy) getOrCreateUDPSession(clientID string, assocID uint16, client *TUICClient) *TUICUDPSession {
	p.udpSessionsMu.Lock()
	defer p.udpSessionsMu.Unlock()

	// Initialize client sessions map if needed
	if p.udpSessions[clientID] == nil {
		p.udpSessions[clientID] = make(map[uint16]*TUICUDPSession)
	}

	session, exists := p.udpSessions[clientID][assocID]
	if !exists {
		// Create UDP connection for relay
		udpConn, err := net.ListenPacket("udp", ":0")
		if err != nil {
			logger.Error("Failed to create UDP connection", "client", client.RemoteAddr, "assoc_id", assocID, "err", err)
			return nil
		}

		session = &TUICUDPSession{
			AssocID:    assocID,
			Client:     client,
			TargetConn: udpConn,
			LastUsed:   time.Now(),
		}
		p.udpSessions[clientID][assocID] = session

		logger.Info("UDP session created", "client", client.RemoteAddr, "assoc_id", assocID)

		// Start relay back to client
		go p.relayUDPBack(clientID, session)
	}

	return session
}

// relayUDPBack relays UDP packets back to client
func (p *TUICProxy) relayUDPBack(clientID string, session *TUICUDPSession) {
	defer func() {
		// Cleanup session
		p.udpSessionsMu.Lock()
		if clientSessions, exists := p.udpSessions[clientID]; exists {
			delete(clientSessions, session.AssocID)
		}
		p.udpSessionsMu.Unlock()

		if session.TargetConn != nil {
			session.TargetConn.Close()
		}
	}()

	buffer := make([]byte, 4096)
	for {
		select {
		case <-p.stopCh:
			return
		default:
			session.TargetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, srcAddr, err := session.TargetConn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logger.Debug("UDP relay read error", "assoc_id", session.AssocID, "err", err)
				return
			}

			if n > 0 {
				// Send packet back to client
				p.sendUDPPacketToClient(session, srcAddr, buffer[:n])

				session.mu.Lock()
				session.LastUsed = time.Now()
				session.mu.Unlock()
			}
		}
	}
}

// sendUDPPacketToClient sends a UDP packet back to the client
func (p *TUICProxy) sendUDPPacketToClient(session *TUICUDPSession, srcAddr net.Addr, data []byte) {
	// Build address from source
	addr := p.buildAddressFromNetAddr(srcAddr)
	if addr == nil {
		logger.Error("Failed to build address from net.Addr", "addr", srcAddr)
		return
	}

	// Build packet data
	packetData := &TUICPacketData{
		AssocID:   session.AssocID,
		PacketID:  0, // Simple implementation, no fragmentation for responses
		FragTotal: 1,
		FragID:    0,
		Size:      uint16(len(data)),
		Address:   addr,
		Payload:   data,
	}

	// Build packet command
	cmdData := p.buildPacketCommandData(packetData)
	cmd := p.buildTUICCommand(TUICCmdPacket, cmdData)

	// Send to client
	_, err := p.listener.WriteTo(cmd, session.Client.RemoteAddr)
	if err != nil {
		logger.Error("Failed to send UDP packet to client", "client", session.Client.RemoteAddr,
			"assoc_id", session.AssocID, "err", err)
	}
}

// buildAddressFromNetAddr builds a TUIC address from net.Addr
func (p *TUICProxy) buildAddressFromNetAddr(addr net.Addr) *TUICAddress {
	switch a := addr.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			return &TUICAddress{
				Type: TUICAddrIPv4,
				Host: ip4.String(),
				Port: uint16(a.Port),
			}
		} else {
			return &TUICAddress{
				Type: TUICAddrIPv6,
				Host: a.IP.String(),
				Port: uint16(a.Port),
			}
		}
	default:
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		if portNum, err := net.LookupPort("udp", port); err == nil {
			return &TUICAddress{
				Type: TUICAddrDomain,
				Host: host,
				Port: uint16(portNum),
			}
		}
		return nil
	}
}

// buildPacketCommandData builds packet command data
func (p *TUICProxy) buildPacketCommandData(packetData *TUICPacketData) []byte {
	// Calculate address data size
	addrData := p.encodeAddress(packetData.Address)

	// Build command data
	data := make([]byte, 8+len(addrData)+len(packetData.Payload))

	binary.BigEndian.PutUint16(data[0:2], packetData.AssocID)
	binary.BigEndian.PutUint16(data[2:4], packetData.PacketID)
	data[4] = packetData.FragTotal
	data[5] = packetData.FragID
	binary.BigEndian.PutUint16(data[6:8], packetData.Size)

	offset := 8
	copy(data[offset:], addrData)
	offset += len(addrData)
	copy(data[offset:], packetData.Payload)

	return data
}

// encodeAddress encodes a TUIC address to bytes
func (p *TUICProxy) encodeAddress(addr *TUICAddress) []byte {
	if addr.Type == TUICAddrNone {
		return []byte{TUICAddrNone}
	}

	var data []byte
	data = append(data, addr.Type)

	switch addr.Type {
	case TUICAddrIPv4:
		ip := net.ParseIP(addr.Host).To4()
		if ip == nil {
			return []byte{TUICAddrNone}
		}
		data = append(data, ip...)
	case TUICAddrIPv6:
		ip := net.ParseIP(addr.Host).To16()
		if ip == nil {
			return []byte{TUICAddrNone}
		}
		data = append(data, ip...)
	case TUICAddrDomain:
		data = append(data, byte(len(addr.Host)))
		data = append(data, []byte(addr.Host)...)
	}

	// Add port
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, addr.Port)
	data = append(data, portBytes...)

	return data
}

// buildTUICCommand builds a TUIC command
func (p *TUICProxy) buildTUICCommand(cmdType uint8, data []byte) []byte {
	cmd := make([]byte, 2+len(data))
	cmd[0] = TUICVersion
	cmd[1] = cmdType
	if len(data) > 0 {
		copy(cmd[2:], data)
	}
	return cmd
}

// handleDissociate handles Dissociate command
func (p *TUICProxy) handleDissociate(clientAddr net.Addr, clientID string, cmd *TUICCommand) {
	logger.Debug("Handling TUIC Dissociate", "client", clientAddr)

	// Check if client is authenticated
	client := p.getAuthenticatedClient(clientID)
	if client == nil {
		logger.Error("Dissociate command from unauthenticated client", "client", clientAddr)
		return
	}

	if len(cmd.Data) < 2 {
		logger.Error("Dissociate data too short", "client", clientAddr)
		return
	}

	assocID := binary.BigEndian.Uint16(cmd.Data[0:2])
	logger.Debug("Handling TUIC Dissociate", "client", clientAddr, "assoc_id", assocID)

	// Remove UDP session
	p.udpSessionsMu.Lock()
	if clientSessions, exists := p.udpSessions[clientID]; exists {
		if session, exists := clientSessions[assocID]; exists {
			if session.TargetConn != nil {
				session.TargetConn.Close()
			}
			delete(clientSessions, assocID)
			logger.Info("UDP session dissociated", "client", clientAddr, "assoc_id", assocID)
		}
	}
	p.udpSessionsMu.Unlock()
}

// handleHeartbeat handles Heartbeat command
func (p *TUICProxy) handleHeartbeat(clientAddr net.Addr, clientID string, cmd *TUICCommand) {
	logger.Debug("Handling TUIC Heartbeat", "client", clientAddr)

	// Check if client is authenticated
	client := p.getAuthenticatedClient(clientID)
	if client == nil {
		logger.Error("Heartbeat command from unauthenticated client", "client", clientAddr)
		return
	}

	// Update client last seen time
	client.mu.Lock()
	client.LastSeen = time.Now()
	client.mu.Unlock()

	// Send heartbeat response
	response := p.buildTUICCommand(TUICCmdHeartbeat, nil)
	_, err := p.listener.WriteTo(response, clientAddr)
	if err != nil {
		logger.Error("Failed to send heartbeat response", "client", clientAddr, "err", err)
	}
}

// cleanupRoutine performs periodic cleanup
func (p *TUICProxy) cleanupRoutine() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.cleanupExpiredSessions()
			p.cleanupExpiredAssemblers()
		}
	}
}

// cleanupExpiredSessions cleans up expired sessions
func (p *TUICProxy) cleanupExpiredSessions() {
	now := time.Now()
	timeout := 5 * time.Minute

	// Cleanup clients
	p.clientsMu.Lock()
	for id, client := range p.authenticatedClients {
		client.mu.Lock()
		if now.Sub(client.LastSeen) > timeout {
			delete(p.authenticatedClients, id)
			logger.Debug("Cleaned up expired client", "client", client.RemoteAddr)
		}
		client.mu.Unlock()
	}
	p.clientsMu.Unlock()

	// Cleanup UDP sessions
	p.udpSessionsMu.Lock()
	for clientID, clientSessions := range p.udpSessions {
		for assocID, session := range clientSessions {
			session.mu.Lock()
			if now.Sub(session.LastUsed) > timeout {
				if session.TargetConn != nil {
					session.TargetConn.Close()
				}
				delete(clientSessions, assocID)
				logger.Debug("Cleaned up expired UDP session", "client", clientID, "assoc_id", assocID)
			}
			session.mu.Unlock()
		}
		if len(clientSessions) == 0 {
			delete(p.udpSessions, clientID)
		}
	}
	p.udpSessionsMu.Unlock()
}

// cleanupExpiredAssemblers cleans up expired packet assemblers
func (p *TUICProxy) cleanupExpiredAssemblers() {
	now := time.Now()
	timeout := 2 * time.Minute

	p.assemblersMu.Lock()
	for clientID, clientAssemblers := range p.packetAssemblers {
		for pktID, assembler := range clientAssemblers {
			assembler.mu.Lock()
			if now.Sub(assembler.CreatedAt) > timeout {
				delete(clientAssemblers, pktID)
				logger.Debug("Cleaned up expired packet assembler", "client", clientID, "pkt_id", pktID)
			}
			assembler.mu.Unlock()
		}
		if len(clientAssemblers) == 0 {
			delete(p.packetAssemblers, clientID)
		}
	}
	p.assemblersMu.Unlock()
}
