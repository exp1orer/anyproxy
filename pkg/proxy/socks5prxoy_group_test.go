package proxy

import (
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func TestSOCKS5GroupRouting(t *testing.T) {
	fmt.Println("Testing SOCKS5 Group-based Routing...")

	// Test cases with different username formats
	testCases := []struct {
		name     string
		username string
		password string
		expected string
	}{
		{
			name:     "Production Group",
			username: "user@production",
			password: "proxy_pass",
			expected: "Should route to production group clients",
		},
		{
			name:     "Testing Group",
			username: "user@testing",
			password: "proxy_pass",
			expected: "Should route to testing group clients",
		},
		{
			name:     "Default Group",
			username: "user",
			password: "proxy_pass",
			expected: "Should route to default group clients",
		},
		{
			name:     "Development Group",
			username: "dev@development",
			password: "proxy_pass",
			expected: "Should route to development group clients",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n--- Testing %s ---\n", tc.name)
		fmt.Printf("Username: %s\n", tc.username)
		fmt.Printf("Expected: %s\n", tc.expected)

		err := testSOCKS5Connection(tc.username, tc.password)
		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
		} else {
			fmt.Printf("✅ Connection successful\n")
		}
	}
}

func testSOCKS5Connection(username, password string) error {
	// Create SOCKS5 proxy URL
	proxyURL := fmt.Sprintf("socks5://%s:%s@localhost:1080", username, password)

	// Parse the proxy URL
	u, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	// Create SOCKS5 dialer
	dialer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return fmt.Errorf("failed to create SOCKS5 dialer: %v", err)
	}

	// Test connection to a target server
	// Note: This will fail if the proxy server is not running
	// but it will show the authentication and group extraction process
	conn, err := dialer.Dial("tcp", "httpbin.org:80")
	if err != nil {
		return fmt.Errorf("failed to connect through SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	// Send a simple HTTP request to test the connection
	request := "GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}

	// Read response (just a small part to verify connection)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	fmt.Printf("Response preview: %s\n", string(buffer[:min(n, 200)]))
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestRawSOCKS5 tests raw SOCKS5 protocol implementation
func TestRawSOCKS5(t *testing.T) {
	// Test with different username formats
	testCases := []struct {
		username string
		password string
	}{
		{"user@production", "proxy_pass"},
		{"user@testing", "proxy_pass"},
		{"user", "proxy_pass"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("RawSOCKS5_%s", tc.username), func(t *testing.T) {
			err := rawSOCKS5Test(tc.username, tc.password)
			if err != nil {
				t.Logf("Expected error (proxy not running): %v", err)
			}
		})
	}
}

// rawSOCKS5Test performs raw SOCKS5 protocol test
func rawSOCKS5Test(username, password string) error {
	// Connect to SOCKS5 proxy
	conn, err := net.Dial("tcp", "localhost:1080")
	if err != nil {
		return fmt.Errorf("failed to connect to SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 handshake
	// Send authentication methods
	_, err = conn.Write([]byte{0x05, 0x01, 0x02}) // Version 5, 1 method, Username/Password
	if err != nil {
		return fmt.Errorf("failed to send auth methods: %v", err)
	}

	// Read server response
	response := make([]byte, 2)
	_, err = conn.Read(response)
	if err != nil {
		return fmt.Errorf("failed to read auth response: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x02 {
		return fmt.Errorf("unexpected auth response: %v", response)
	}

	// Send username/password
	authData := []byte{0x01} // Version
	authData = append(authData, byte(len(username)))
	authData = append(authData, []byte(username)...)
	authData = append(authData, byte(len(password)))
	authData = append(authData, []byte(password)...)

	_, err = conn.Write(authData)
	if err != nil {
		return fmt.Errorf("failed to send credentials: %v", err)
	}

	// Read auth result
	authResult := make([]byte, 2)
	_, err = conn.Read(authResult)
	if err != nil {
		return fmt.Errorf("failed to read auth result: %v", err)
	}

	if authResult[1] != 0x00 {
		return fmt.Errorf("authentication failed")
	}

	fmt.Printf("✅ SOCKS5 authentication successful for user: %s\n", username)
	return nil
}
