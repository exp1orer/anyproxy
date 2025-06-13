package protocols

import (
	"context"
	"crypto/sha256"
	"net"
	"testing"

	"github.com/buhuipao/anyproxy/pkg/config"
)

func TestNewTUICProxyWithAuth(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: ":9443",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	if proxy == nil {
		t.Fatal("Expected non-nil proxy")
	}

	tuicProxy := proxy.(*TUICProxy)
	if tuicProxy.config != cfg {
		t.Error("Config not set correctly")
	}

	// Verify token hash
	expectedHash := sha256.Sum256([]byte(cfg.Token))
	if string(tuicProxy.authToken) != string(expectedHash[:]) {
		t.Error("Auth token hash not computed correctly")
	}
}

func TestTUICProxy_StartStop(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: "127.0.0.1:0", // Use any available port
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	// Test start
	if err := proxy.Start(); err != nil {
		t.Fatalf("Failed to start TUIC proxy: %v", err)
	}

	// Test stop
	if err := proxy.Stop(); err != nil {
		t.Fatalf("Failed to stop TUIC proxy: %v", err)
	}
}

func TestTUICProxy_ValidateToken(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: ":9443",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	tuicProxy := proxy.(*TUICProxy)

	// Test valid token
	validToken := sha256.Sum256([]byte(cfg.Token))
	if !tuicProxy.validateToken(validToken[:]) {
		t.Error("Valid token should be accepted")
	}

	// Test invalid token
	invalidToken := sha256.Sum256([]byte("wrong-token"))
	if tuicProxy.validateToken(invalidToken[:]) {
		t.Error("Invalid token should be rejected")
	}

	// Test wrong length token
	if tuicProxy.validateToken([]byte("short")) {
		t.Error("Wrong length token should be rejected")
	}
}

func TestTUICProxy_ParseTUICCommand(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: ":9443",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	tuicProxy := proxy.(*TUICProxy)

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		version uint8
		cmdType uint8
	}{
		{
			name:    "valid authenticate command",
			data:    []byte{TUICVersion, TUICCmdAuthenticate, 0x01, 0x02, 0x03},
			wantErr: false,
			version: TUICVersion,
			cmdType: TUICCmdAuthenticate,
		},
		{
			name:    "valid heartbeat command",
			data:    []byte{TUICVersion, TUICCmdHeartbeat},
			wantErr: false,
			version: TUICVersion,
			cmdType: TUICCmdHeartbeat,
		},
		{
			name:    "too short",
			data:    []byte{TUICVersion},
			wantErr: true,
		},
		{
			name:    "wrong version",
			data:    []byte{0x04, TUICCmdHeartbeat},
			wantErr: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := tuicProxy.parseTUICCommand(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTUICCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if cmd.Version != tt.version {
					t.Errorf("Expected version %v, got %v", tt.version, cmd.Version)
				}
				if cmd.Type != tt.cmdType {
					t.Errorf("Expected command type %v, got %v", tt.cmdType, cmd.Type)
				}
			}
		})
	}
}

func TestTUICProxy_ParseAddress(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: ":9443",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	tuicProxy := proxy.(*TUICProxy)

	tests := []struct {
		name     string
		data     []byte
		wantErr  bool
		wantType uint8
		wantHost string
		wantPort uint16
	}{
		{
			name:     "IPv4 address",
			data:     []byte{TUICAddrIPv4, 192, 168, 1, 1, 0x00, 0x50}, // 192.168.1.1:80
			wantErr:  false,
			wantType: TUICAddrIPv4,
			wantHost: "192.168.1.1",
			wantPort: 80,
		},
		{
			name:     "domain address",
			data:     []byte{TUICAddrDomain, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}, // example.com:443
			wantErr:  false,
			wantType: TUICAddrDomain,
			wantHost: "example.com",
			wantPort: 443,
		},
		{
			name:     "none address",
			data:     []byte{TUICAddrNone},
			wantErr:  false,
			wantType: TUICAddrNone,
		},
		{
			name:    "too short",
			data:    []byte{TUICAddrIPv4, 192},
			wantErr: true,
		},
		{
			name:    "unknown type",
			data:    []byte{0x99, 192, 168, 1, 1, 0x00, 0x50},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := tuicProxy.parseAddress(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if addr.Type != tt.wantType {
					t.Errorf("Expected type %v, got %v", tt.wantType, addr.Type)
				}
				if addr.Type != TUICAddrNone {
					if addr.Host != tt.wantHost {
						t.Errorf("Expected host %v, got %v", tt.wantHost, addr.Host)
					}
					if addr.Port != tt.wantPort {
						t.Errorf("Expected port %v, got %v", tt.wantPort, addr.Port)
					}
				}
			}
		})
	}
}

func TestTUICProxy_Authentication(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: "127.0.0.1:0",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	tuicProxy := proxy.(*TUICProxy)

	// Create mock client address
	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Test authentication
	uuid := make([]byte, TUICUUIDLength)
	copy(uuid, []byte("test-uuid"))

	token := sha256.Sum256([]byte(cfg.Token))

	authData := make([]byte, TUICUUIDLength+TUICTokenLength)
	copy(authData[:TUICUUIDLength], uuid)
	copy(authData[TUICUUIDLength:], token[:])

	cmd := &TUICCommand{
		Version: TUICVersion,
		Type:    TUICCmdAuthenticate,
		Data:    authData,
	}

	// Handle authentication
	clientID := clientAddr.String()
	tuicProxy.handleAuthenticate(clientAddr, clientID, cmd)

	// Check if client is authenticated
	client := tuicProxy.getAuthenticatedClient(clientID)
	if client == nil {
		t.Error("Client should be authenticated")
	}

	if !client.Authenticated {
		t.Error("Client authenticated flag should be true")
	}

	if string(client.UUID) != string(uuid) {
		t.Error("Client UUID should match")
	}
}

func TestTUICProxy_BuildTUICCommand(t *testing.T) {
	cfg := &config.TUICConfig{
		ListenAddr: ":9443",
		Token:      "test-token",
		UUID:       "test-uuid",
	}

	dialFunc := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	}

	groupExtractor := func(username string) string {
		return "default"
	}

	proxy, err := NewTUICProxyWithAuth(cfg, dialFunc, groupExtractor)
	if err != nil {
		t.Fatalf("Failed to create TUIC proxy: %v", err)
	}

	tuicProxy := proxy.(*TUICProxy)

	// Test heartbeat command (no data)
	cmd := tuicProxy.buildTUICCommand(TUICCmdHeartbeat, nil)
	expected := []byte{TUICVersion, TUICCmdHeartbeat}
	if len(cmd) != len(expected) {
		t.Errorf("Expected length %d, got %d", len(expected), len(cmd))
	}
	for i, b := range expected {
		if cmd[i] != b {
			t.Errorf("Expected byte %d to be %02x, got %02x", i, b, cmd[i])
		}
	}

	// Test command with data
	data := []byte{0x01, 0x02, 0x03}
	cmd = tuicProxy.buildTUICCommand(TUICCmdAuthenticate, data)
	expected = []byte{TUICVersion, TUICCmdAuthenticate, 0x01, 0x02, 0x03}
	if len(cmd) != len(expected) {
		t.Errorf("Expected length %d, got %d", len(expected), len(cmd))
	}
	for i, b := range expected {
		if cmd[i] != b {
			t.Errorf("Expected byte %d to be %02x, got %02x", i, b, cmd[i])
		}
	}
}
