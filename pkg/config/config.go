package config

import (
	"os"

	"gopkg.in/yaml.v2"
)

// Config represents the main configuration
type Config struct {
	Proxy   ProxyConfig   `yaml:"proxy"`
	Gateway GatewayConfig `yaml:"gateway"`
	Client  ClientConfig  `yaml:"client"`
}

// ProxyConfig represents the configuration for the proxy
type ProxyConfig struct {
	SOCKS5 SOCKS5Config `yaml:"socks5"`
	HTTP   HTTPConfig   `yaml:"http"`
}

// GatewayConfig represents the configuration for the proxy gateway
type GatewayConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	TLSCert      string `yaml:"tls_cert"`
	TLSKey       string `yaml:"tls_key"`
	AuthUsername string `yaml:"auth_username"`
	AuthPassword string `yaml:"auth_password"`
}

// SOCKS5Config represents the configuration for the SOCKS5 proxy
type SOCKS5Config struct {
	ListenAddr   string `yaml:"listen_addr"`
	AuthUsername string `yaml:"auth_username"`
	AuthPassword string `yaml:"auth_password"`
}

// HTTPConfig represents the configuration for the HTTP proxy
type HTTPConfig struct {
	ListenAddr   string `yaml:"listen_addr"`
	AuthUsername string `yaml:"auth_username"`
	AuthPassword string `yaml:"auth_password"`
}

// ServiceLimit defines allowed services for the client
type ServiceLimit struct {
	Name     string `yaml:"name"`
	Addr     string `yaml:"addr"`
	Protocol string `yaml:"protocol"` // "tcp" or "udp"
}

// ClientConfig represents the configuration for the proxy client
type ClientConfig struct {
	GatewayAddr        string         `yaml:"gateway_addr"`
	GatewayTLSCert     string         `yaml:"gateway_tls_cert"`
	ClientID           string         `yaml:"client_id"`
	Replicas           int            `yaml:"replicas"`
	MaxConcurrentConns int            `yaml:"max_concurrent_conns"`
	AuthUsername       string         `yaml:"auth_username"`
	AuthPassword       string         `yaml:"auth_password"`
	ForbiddenHosts     []string       `yaml:"forbidden_hosts"`
	Limits             []ServiceLimit `yaml:"limit"`
}

var conf *Config

// LoadConfig loads configuration from a YAML file
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	conf = &config

	return &config, nil
}

func GetConfig() *Config {
	return conf
}
