package common

import (
	"net"
)

// ConnWrapper wraps a net.Conn and provides custom LocalAddr and RemoteAddr
// (migrated from v1, maintaining identical functionality)
type ConnWrapper struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.Conn = (*ConnWrapper)(nil)

// NewConnWrapper creates a new connection wrapper with custom addresses (same as v1)
func NewConnWrapper(conn net.Conn, network, remoteAddress string) *ConnWrapper {
	// Create a fake local address (SOCKS5 server binding address)
	localAddr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 0, // Let the system assign a port
	}

	// Parse the remote address
	var remoteAddr net.Addr
	if host, port, err := net.SplitHostPort(remoteAddress); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if network == "tcp" {
				if portNum, err := net.LookupPort("tcp", port); err == nil {
					remoteAddr = &net.TCPAddr{IP: ip, Port: portNum}
				}
			} else if network == "udp" {
				if portNum, err := net.LookupPort("udp", port); err == nil {
					remoteAddr = &net.UDPAddr{IP: ip, Port: portNum}
				}
			}
		}
	}

	// Fallback to a default remote address if parsing failed
	if remoteAddr == nil {
		if network == "tcp" {
			remoteAddr = &net.TCPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 80,
			}
		} else {
			remoteAddr = &net.UDPAddr{
				IP:   net.IPv4(127, 0, 0, 1),
				Port: 80,
			}
		}
	}

	wrapper := &ConnWrapper{
		Conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}

	return wrapper
}

// LocalAddr returns the local network address (same as v1)
func (cw *ConnWrapper) LocalAddr() net.Addr {
	return cw.localAddr
}

// RemoteAddr returns the remote network address (same as v1)
func (cw *ConnWrapper) RemoteAddr() net.Addr {
	return cw.remoteAddr
}
