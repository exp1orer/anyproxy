package proxy

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConnWrapper(t *testing.T) {
	// Create a mock connection
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		network       string
		remoteAddress string
		expectedType  string
	}{
		{
			name:          "TCP connection with valid address",
			network:       "tcp",
			remoteAddress: "192.168.1.1:8080",
			expectedType:  "*net.TCPAddr",
		},
		{
			name:          "UDP connection with valid address",
			network:       "udp",
			remoteAddress: "192.168.1.1:53",
			expectedType:  "*net.UDPAddr",
		},
		{
			name:          "TCP connection with hostname",
			network:       "tcp",
			remoteAddress: "example.com:80",
			expectedType:  "*net.TCPAddr", // Should fallback to default
		},
		{
			name:          "TCP connection with invalid address",
			network:       "tcp",
			remoteAddress: "invalid-address",
			expectedType:  "*net.TCPAddr", // Should fallback to default
		},
		{
			name:          "UDP connection with invalid address",
			network:       "udp",
			remoteAddress: "invalid-address",
			expectedType:  "*net.UDPAddr", // Should fallback to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(mockConn, tt.network, tt.remoteAddress)

			require.NotNil(t, wrapper)
			assert.Equal(t, mockConn, wrapper.Conn)

			// Check local address
			localAddr := wrapper.LocalAddr()
			assert.NotNil(t, localAddr)
			assert.IsType(t, &net.TCPAddr{}, localAddr)
			tcpAddr := localAddr.(*net.TCPAddr)
			assert.True(t, tcpAddr.IP.Equal(net.IPv4(127, 0, 0, 1)))
			assert.Equal(t, 0, tcpAddr.Port)

			// Check remote address type
			remoteAddr := wrapper.RemoteAddr()
			assert.NotNil(t, remoteAddr)

			switch tt.network {
			case "tcp":
				assert.IsType(t, &net.TCPAddr{}, remoteAddr)
			case "udp":
				assert.IsType(t, &net.UDPAddr{}, remoteAddr)
			}
		})
	}
}

func TestConnWrapper_TCPAddressParsing(t *testing.T) {
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		remoteAddress string
		expectedIP    net.IP
		expectedPort  int
	}{
		{
			name:          "IPv4 address with port",
			remoteAddress: "192.168.1.100:8080",
			expectedIP:    net.IPv4(192, 168, 1, 100),
			expectedPort:  8080,
		},
		{
			name:          "IPv6 address with port",
			remoteAddress: "[::1]:8080",
			expectedIP:    net.IPv6loopback,
			expectedPort:  8080,
		},
		{
			name:          "localhost with port",
			remoteAddress: "127.0.0.1:80",
			expectedIP:    net.IPv4(127, 0, 0, 1),
			expectedPort:  80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(mockConn, "tcp", tt.remoteAddress)

			remoteAddr := wrapper.RemoteAddr()
			require.IsType(t, &net.TCPAddr{}, remoteAddr)

			tcpAddr := remoteAddr.(*net.TCPAddr)
			assert.True(t, tcpAddr.IP.Equal(tt.expectedIP))
			assert.Equal(t, tt.expectedPort, tcpAddr.Port)
		})
	}
}

func TestConnWrapper_UDPAddressParsing(t *testing.T) {
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		remoteAddress string
		expectedIP    net.IP
		expectedPort  int
	}{
		{
			name:          "IPv4 address with port",
			remoteAddress: "8.8.8.8:53",
			expectedIP:    net.IPv4(8, 8, 8, 8),
			expectedPort:  53,
		},
		{
			name:          "IPv6 address with port",
			remoteAddress: "[2001:4860:4860::8888]:53",
			expectedIP:    net.ParseIP("2001:4860:4860::8888"),
			expectedPort:  53,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(mockConn, "udp", tt.remoteAddress)

			remoteAddr := wrapper.RemoteAddr()
			require.IsType(t, &net.UDPAddr{}, remoteAddr)

			udpAddr := remoteAddr.(*net.UDPAddr)
			assert.True(t, udpAddr.IP.Equal(tt.expectedIP))
			assert.Equal(t, tt.expectedPort, udpAddr.Port)
		})
	}
}

func TestConnWrapper_FallbackAddresses(t *testing.T) {
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		network       string
		remoteAddress string
		expectedIP    net.IP
		expectedPort  int
	}{
		{
			name:          "TCP fallback for invalid address",
			network:       "tcp",
			remoteAddress: "invalid:address:format",
			expectedIP:    net.IPv4(127, 0, 0, 1),
			expectedPort:  80,
		},
		{
			name:          "UDP fallback for invalid address",
			network:       "udp",
			remoteAddress: "invalid:address:format",
			expectedIP:    net.IPv4(127, 0, 0, 1),
			expectedPort:  80,
		},
		{
			name:          "TCP fallback for hostname",
			network:       "tcp",
			remoteAddress: "example.com:80",
			expectedIP:    net.IPv4(127, 0, 0, 1),
			expectedPort:  80,
		},
		{
			name:          "TCP fallback for invalid port",
			network:       "tcp",
			remoteAddress: "192.168.1.1:invalid",
			expectedIP:    net.IPv4(127, 0, 0, 1),
			expectedPort:  80,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(mockConn, tt.network, tt.remoteAddress)

			remoteAddr := wrapper.RemoteAddr()
			assert.NotNil(t, remoteAddr)

			switch tt.network {
			case "tcp":
				require.IsType(t, &net.TCPAddr{}, remoteAddr)
				tcpAddr := remoteAddr.(*net.TCPAddr)
				assert.True(t, tcpAddr.IP.Equal(tt.expectedIP))
				assert.Equal(t, tt.expectedPort, tcpAddr.Port)
			case "udp":
				require.IsType(t, &net.UDPAddr{}, remoteAddr)
				udpAddr := remoteAddr.(*net.UDPAddr)
				assert.True(t, udpAddr.IP.Equal(tt.expectedIP))
				assert.Equal(t, tt.expectedPort, udpAddr.Port)
			}
		})
	}
}

func TestConnWrapper_InterfaceCompliance(t *testing.T) {
	mockConn := &mockConn{}
	wrapper := NewConnWrapper(mockConn, "tcp", "192.168.1.1:8080")

	// Verify that ConnWrapper implements net.Conn interface
	var _ net.Conn = wrapper

	// Test that all net.Conn methods are accessible
	assert.NotNil(t, wrapper.LocalAddr())
	assert.NotNil(t, wrapper.RemoteAddr())

	// Test that underlying connection methods are still accessible
	assert.Equal(t, mockConn, wrapper.Conn)
}

func TestConnWrapper_LocalAddr(t *testing.T) {
	mockConn := &mockConn{}
	wrapper := NewConnWrapper(mockConn, "tcp", "192.168.1.1:8080")

	localAddr := wrapper.LocalAddr()
	require.IsType(t, &net.TCPAddr{}, localAddr)

	tcpAddr := localAddr.(*net.TCPAddr)
	assert.True(t, tcpAddr.IP.Equal(net.IPv4(127, 0, 0, 1)))
	assert.Equal(t, 0, tcpAddr.Port)
}

func TestConnWrapper_RemoteAddr(t *testing.T) {
	mockConn := &mockConn{}
	wrapper := NewConnWrapper(mockConn, "tcp", "192.168.1.1:8080")

	remoteAddr := wrapper.RemoteAddr()
	require.IsType(t, &net.TCPAddr{}, remoteAddr)

	tcpAddr := remoteAddr.(*net.TCPAddr)
	assert.True(t, tcpAddr.IP.Equal(net.IPv4(192, 168, 1, 1)))
	assert.Equal(t, 8080, tcpAddr.Port)
}

func TestConnWrapper_EdgeCases(t *testing.T) {
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		network       string
		remoteAddress string
		description   string
	}{
		{
			name:          "empty address",
			network:       "tcp",
			remoteAddress: "",
			description:   "should handle empty address gracefully",
		},
		{
			name:          "address without port",
			network:       "tcp",
			remoteAddress: "192.168.1.1",
			description:   "should handle address without port",
		},
		{
			name:          "port only",
			network:       "tcp",
			remoteAddress: ":8080",
			description:   "should handle port-only address",
		},
		{
			name:          "unknown network type",
			network:       "unknown",
			remoteAddress: "192.168.1.1:8080",
			description:   "should handle unknown network type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			wrapper := NewConnWrapper(mockConn, tt.network, tt.remoteAddress)
			assert.NotNil(t, wrapper)
			assert.NotNil(t, wrapper.LocalAddr())
			assert.NotNil(t, wrapper.RemoteAddr())
		})
	}
}

func TestConnWrapper_PortLookup(t *testing.T) {
	mockConn := &mockConn{}

	tests := []struct {
		name          string
		network       string
		remoteAddress string
		description   string
	}{
		{
			name:          "standard HTTP port",
			network:       "tcp",
			remoteAddress: "192.168.1.1:http",
			description:   "should handle named ports",
		},
		{
			name:          "standard HTTPS port",
			network:       "tcp",
			remoteAddress: "192.168.1.1:https",
			description:   "should handle named ports",
		},
		{
			name:          "DNS port for UDP",
			network:       "udp",
			remoteAddress: "8.8.8.8:domain",
			description:   "should handle UDP named ports",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper := NewConnWrapper(mockConn, tt.network, tt.remoteAddress)
			assert.NotNil(t, wrapper)

			remoteAddr := wrapper.RemoteAddr()
			assert.NotNil(t, remoteAddr)

			// The actual port resolution depends on the system's service database
			// We just verify that the wrapper was created successfully
		})
	}
}
