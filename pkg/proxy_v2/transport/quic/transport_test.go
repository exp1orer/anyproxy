package quic

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/buhuipao/anyproxy/pkg/proxy_v2/transport"
)

func TestNewQUICTransport(t *testing.T) {
	trans := NewQUICTransport()

	if trans == nil {
		t.Fatal("Expected non-nil transport")
	}

	quicTrans, ok := trans.(*quicTransport)
	if !ok {
		t.Fatal("Transport is not quicTransport type")
	}

	if quicTrans.authConfig != nil {
		t.Error("Auth config should be nil for default transport")
	}
}

func TestNewQUICTransportWithAuth(t *testing.T) {
	authConfig := &transport.AuthConfig{
		Username: "testuser",
		Password: "testpass",
	}

	trans := NewQUICTransportWithAuth(authConfig)

	if trans == nil {
		t.Fatal("Expected non-nil transport")
	}

	quicTrans, ok := trans.(*quicTransport)
	if !ok {
		t.Fatal("Transport is not quicTransport type")
	}

	if quicTrans.authConfig == nil {
		t.Fatal("Auth config should not be nil")
	}

	if quicTrans.authConfig.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", quicTrans.authConfig.Username)
	}
}

// generateTestCert generates a self-signed certificate for testing
func generateTestCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func TestQUICTransport_ListenAndServe(t *testing.T) {
	// QUIC requires TLS, so this should fail
	trans := NewQUICTransport()

	err := trans.ListenAndServe(":0", func(conn transport.Connection) {
		conn.Close()
	})

	if err == nil {
		t.Error("Expected error when starting QUIC without TLS")
		trans.Close()
	}
}

func TestQUICTransport_ListenAndServeWithTLS(t *testing.T) {
	// Generate test certificate
	cert, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-transport"},
	}

	trans := NewQUICTransport()

	// Start server in goroutine
	go func() {
		err := trans.ListenAndServeWithTLS(":0", func(conn transport.Connection) {
			// Just close the connection
			conn.Close()
		}, tlsConfig)
		if err != nil {
			t.Errorf("ListenAndServeWithTLS failed: %v", err)
		}
	}()

	// Wait a bit for server to start
	time.Sleep(100 * time.Millisecond)

	// Get the actual server address
	quicTrans := trans.(*quicTransport)
	quicTrans.mu.Lock()
	listener := quicTrans.listener
	quicTrans.mu.Unlock()

	if listener == nil {
		t.Fatal("Listener not started")
	}

	// Stop server
	err = trans.Close()
	if err != nil {
		t.Errorf("Failed to close transport: %v", err)
	}
}

func TestQUICTransport_DialWithConfig(t *testing.T) {
	// QUIC dial requires a proper server setup with TLS
	// Skipping for now as it needs more infrastructure
	t.Skip("Skipping QUIC dial test - requires proper TLS setup")
}

func TestQUICTransport_Close(t *testing.T) {
	trans := NewQUICTransport()

	// Test closing without starting
	err := trans.Close()
	if err != nil {
		t.Errorf("Expected no error when closing non-running transport, got: %v", err)
	}

	// Double close should be safe
	err = trans.Close()
	if err != nil {
		t.Errorf("Double close failed: %v", err)
	}
}

func TestQUICConnection_BasicOperations(t *testing.T) {
	// This test requires a full QUIC server-client setup
	// Skipping for now as it needs more infrastructure
	t.Skip("Skipping QUIC connection test - requires full server setup")
}

func TestQUICTransport_Authentication(t *testing.T) {
	// This test requires a full QUIC server setup with authentication
	// Skipping for now as it needs proper TLS configuration
	t.Skip("Skipping QUIC authentication test - requires proper TLS setup")
}

func TestQUICTransport_ErrorCases(t *testing.T) {
	trans := NewQUICTransport()

	// Test nil TLS config
	err := trans.ListenAndServeWithTLS(":0", func(conn transport.Connection) { conn.Close() }, nil)
	if err == nil {
		t.Error("Expected error for nil TLS config")
	}

	// Test ListenAndServe without TLS (should fail as QUIC requires TLS)
	err = trans.ListenAndServe(":0", func(conn transport.Connection) { conn.Close() })
	if err == nil {
		t.Error("Expected error when starting QUIC without proper TLS")
	}
}

func TestQUICConnection_StreamOperations(t *testing.T) {
	// Test would require a full QUIC connection setup
	// For now, we can test that the connection type exists
	t.Skip("Skipping QUIC stream operations test - requires full server setup")
}
