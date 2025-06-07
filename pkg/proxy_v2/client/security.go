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

// compileHostPatterns 预编译所有主机正则表达式
func (c *Client) compileHostPatterns() error {
	// 编译禁止主机的正则表达式
	c.forbiddenHostsRe = make([]*regexp.Regexp, 0, len(c.config.ForbiddenHosts))
	for _, pattern := range c.config.ForbiddenHosts {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("invalid forbidden host pattern '%s': %v", pattern, err)
		}
		c.forbiddenHostsRe = append(c.forbiddenHostsRe, re)
	}

	// 编译允许主机的正则表达式
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

// isConnectionAllowed 检查连接是否被允许
func (c *Client) isConnectionAllowed(address string) bool {
	// 首先检查是否被禁止
	for _, re := range c.forbiddenHostsRe {
		if re.MatchString(address) {
			logger.Warn("🚫 CONNECTION BLOCKED - Forbidden host", "client_id", c.getClientID(), "address", address, "pattern", re.String(), "action", "Connection rejected due to forbidden host policy")
			return false
		}
	}

	// 如果没有配置允许的主机，则允许所有未被禁止的连接
	if len(c.allowedHostsRe) == 0 {
		logger.Debug("Connection allowed - no allowed hosts configured", "client_id", c.getClientID(), "address", address)
		return true
	}

	// 检查是否在允许列表中
	for _, re := range c.allowedHostsRe {
		if re.MatchString(address) {
			logger.Debug("Connection allowed - matches allowed pattern", "client_id", c.getClientID(), "address", address, "pattern", re.String())
			return true
		}
	}

	logger.Warn("Connection blocked - not in allowed hosts", "client_id", c.getClientID(), "address", address, "action", "Connection rejected - host not in allowed list")
	return false
}

// createTLSConfig 创建 TLS 配置 (与 v1 相同)
func (c *Client) createTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// 如果提供了 TLS 证书，加载它 (与 v1 相同)
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

		// 从证书文件路径中提取服务器名称 (与 v1 相同)
		serverName := strings.TrimSuffix(c.config.GatewayAddr, ":443")
		if colonIndex := strings.LastIndex(serverName, ":"); colonIndex != -1 {
			serverName = serverName[:colonIndex]
		}
		tlsConfig.ServerName = serverName
	}

	return tlsConfig, nil
}
