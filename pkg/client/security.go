package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/buhuipao/anyproxy/pkg/logger"
)

// compileHostPatterns pre-compiles all host regular expressions
func (c *Client) compileHostPatterns() error {
	// Compile forbidden hosts regular expressions
	c.forbiddenHostsRe = make([]*regexp.Regexp, 0, len(c.config.ForbiddenHosts))
	for _, pattern := range c.config.ForbiddenHosts {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid forbidden host pattern '%s': %v", pattern, err)
		}
		c.forbiddenHostsRe = append(c.forbiddenHostsRe, re)
	}

	// Compile allowed hosts regular expressions
	c.allowedHostsRe = make([]*regexp.Regexp, 0, len(c.config.AllowedHosts))
	for _, pattern := range c.config.AllowedHosts {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid allowed host pattern '%s': %v", pattern, err)
		}
		c.allowedHostsRe = append(c.allowedHostsRe, re)
	}

	return nil
}

// isConnectionAllowed checks if connection is allowed
func (c *Client) isConnectionAllowed(address string) bool {
	// First check if it's forbidden
	for _, re := range c.forbiddenHostsRe {
		if re.MatchString(address) {
			logger.Warn("🚫 CONNECTION BLOCKED - Forbidden host", "client_id", c.getClientID(), "address", address, "pattern", re.String(), "action", "Connection rejected due to forbidden host policy")
			return false
		}
	}

	// If no allowed hosts are configured, allow all non-forbidden connections
	if len(c.allowedHostsRe) == 0 {
		logger.Debug("Connection allowed - no allowed hosts configured", "client_id", c.getClientID(), "address", address)
		return true
	}

	// Check if it's in the allowed list
	for _, re := range c.allowedHostsRe {
		if re.MatchString(address) {
			logger.Debug("Connection allowed - matches allowed pattern", "client_id", c.getClientID(), "address", address, "pattern", re.String())
			return true
		}
	}

	logger.Warn("Connection blocked - not in allowed hosts", "client_id", c.getClientID(), "address", address, "action", "Connection rejected - host not in allowed list")
	return false
}

// createTLSConfig creates TLS configuration
func (c *Client) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// If TLS certificate is provided, load it
	if c.config.GatewayTLSCert != "" {
		certPEM, err := os.ReadFile(c.config.GatewayTLSCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read TLS certificate: %v", err)
		}

		certPool := x509.NewCertPool()
		if ok := certPool.AppendCertsFromPEM(certPEM); !ok {
			return nil, fmt.Errorf("failed to parse TLS certificate")
		}

		tlsConfig.RootCAs = certPool

		// Extract server name from certificate file path
		serverName := strings.TrimSuffix(c.config.GatewayAddr, ":443")
		if colonIndex := strings.LastIndex(serverName, ":"); colonIndex != -1 {
			serverName = serverName[:colonIndex]
		}
		tlsConfig.ServerName = serverName
	}

	return tlsConfig, nil
}
