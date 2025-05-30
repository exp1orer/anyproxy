package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		configYAML  string
		wantErr     bool
		expectedCfg *Config
	}{
		{
			name: "valid complete config",
			configYAML: `
proxy:
  socks5:
    listen_addr: "127.0.0.1:1080"
    auth_username: "testuser"
    auth_password: "testpass"
  http:
    listen_addr: "127.0.0.1:8080"
    auth_username: "httpuser"
    auth_password: "httppass"
gateway:
  listen_addr: "0.0.0.0:8443"
  tls_cert: "/path/to/cert.pem"
  tls_key: "/path/to/key.pem"
  auth_username: "gatewayuser"
  auth_password: "gatewaypass"
client:
  gateway_addr: "gateway.example.com:8443"
  gateway_tls_cert: "/path/to/gateway-cert.pem"
  client_id: "test-client-id"
  replicas: 3
  auth_username: "clientuser"
  auth_password: "clientpass"
  forbidden_hosts:
    - "forbidden.example.com"
    - "blocked.test"
  allowed_hosts:
    - "allowed.example.com"
    - "trusted.test"
log:
  level: "info"
  format: "json"
  output: "stdout"
  file: "/var/log/anyproxy.log"
  max_size: 100
  max_backups: 3
  max_age: 28
  compress: true
`,
			wantErr: false,
			expectedCfg: &Config{
				Proxy: ProxyConfig{
					SOCKS5: SOCKS5Config{
						ListenAddr:   "127.0.0.1:1080",
						AuthUsername: "testuser",
						AuthPassword: "testpass",
					},
					HTTP: HTTPConfig{
						ListenAddr:   "127.0.0.1:8080",
						AuthUsername: "httpuser",
						AuthPassword: "httppass",
					},
				},
				Gateway: GatewayConfig{
					ListenAddr:   "0.0.0.0:8443",
					TLSCert:      "/path/to/cert.pem",
					TLSKey:       "/path/to/key.pem",
					AuthUsername: "gatewayuser",
					AuthPassword: "gatewaypass",
				},
				Client: ClientConfig{
					GatewayAddr:    "gateway.example.com:8443",
					GatewayTLSCert: "/path/to/gateway-cert.pem",
					ClientID:       "test-client-id",
					Replicas:       3,
					AuthUsername:   "clientuser",
					AuthPassword:   "clientpass",
					ForbiddenHosts: []string{"forbidden.example.com", "blocked.test"},
					AllowedHosts:   []string{"allowed.example.com", "trusted.test"},
				},
				Log: LogConfig{
					Level:      "info",
					Format:     "json",
					Output:     "stdout",
					File:       "/var/log/anyproxy.log",
					MaxSize:    100,
					MaxBackups: 3,
					MaxAge:     28,
					Compress:   true,
				},
			},
		},
		{
			name: "minimal valid config",
			configYAML: `
proxy:
  socks5:
    listen_addr: "127.0.0.1:1080"
gateway:
  listen_addr: "0.0.0.0:8443"
client:
  gateway_addr: "gateway.example.com:8443"
log:
  level: "info"
`,
			wantErr: false,
			expectedCfg: &Config{
				Proxy: ProxyConfig{
					SOCKS5: SOCKS5Config{
						ListenAddr: "127.0.0.1:1080",
					},
				},
				Gateway: GatewayConfig{
					ListenAddr: "0.0.0.0:8443",
				},
				Client: ClientConfig{
					GatewayAddr: "gateway.example.com:8443",
				},
				Log: LogConfig{
					Level: "info",
				},
			},
		},
		{
			name:        "empty config",
			configYAML:  ``,
			wantErr:     false,
			expectedCfg: &Config{},
		},
		{
			name: "config with only logging",
			configYAML: `
log:
  level: "debug"
  format: "text"
  output: "stderr"
  max_size: 50
  max_backups: 5
  max_age: 7
  compress: false
`,
			wantErr: false,
			expectedCfg: &Config{
				Log: LogConfig{
					Level:      "debug",
					Format:     "text",
					Output:     "stderr",
					MaxSize:    50,
					MaxBackups: 5,
					MaxAge:     7,
					Compress:   false,
				},
			},
		},
		{
			name: "invalid YAML",
			configYAML: `
proxy:
  socks5:
    listen_addr: "127.0.0.1:1080"
    invalid_indent_here
gateway:
  listen_addr: "0.0.0.0:8443"
`,
			wantErr: true,
		},
		{
			name:       "invalid YAML structure",
			configYAML: `[this is not a valid config structure]`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with test YAML content
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configFile, []byte(tt.configYAML), 0644)
			require.NoError(t, err)

			// Test LoadConfig
			cfg, err := LoadConfig(configFile)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
				assert.Equal(t, tt.expectedCfg, cfg)
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	// Test with non-existent file
	cfg, err := LoadConfig("non-existent-file.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "no such file or directory")
}

func TestLoadConfig_EmptyFilename(t *testing.T) {
	// Test with empty filename
	cfg, err := LoadConfig("")
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfig_Directory(t *testing.T) {
	// Test with directory instead of file
	tmpDir := t.TempDir()
	cfg, err := LoadConfig(tmpDir)
	assert.Error(t, err)
	assert.Nil(t, cfg)
}

func TestLoadConfig_PermissionDenied(t *testing.T) {
	// Skip this test on Windows as it behaves differently with file permissions
	if os.Getenv("GOOS") == "windows" {
		t.Skip("Skipping permission test on Windows")
	}

	// Create a file without read permissions
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	err := os.WriteFile(configFile, []byte("test: config"), 0000)
	require.NoError(t, err)

	cfg, err := LoadConfig(configFile)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestGetConfig(t *testing.T) {
	// Reset global config
	conf = nil

	// Test GetConfig when no config is loaded
	cfg := GetConfig()
	assert.Nil(t, cfg)

	// Load a config
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	configYAML := `
log:
  level: "debug"
  format: "json"
`

	err := os.WriteFile(configFile, []byte(configYAML), 0644)
	require.NoError(t, err)

	loadedCfg, err := LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, loadedCfg)

	// Test GetConfig returns the loaded config
	cfg = GetConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, loadedCfg, cfg)
	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)

	// Load another config and verify GetConfig returns the new one
	newConfigYAML := `
log:
  level: "error"
  format: "text"
gateway:
  listen_addr: "127.0.0.1:9999"
`

	newConfigFile := filepath.Join(tmpDir, "new_config.yaml")
	err = os.WriteFile(newConfigFile, []byte(newConfigYAML), 0644)
	require.NoError(t, err)

	newLoadedCfg, err := LoadConfig(newConfigFile)
	require.NoError(t, err)
	require.NotNil(t, newLoadedCfg)

	// Verify GetConfig now returns the new config
	cfg = GetConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, newLoadedCfg, cfg)
	assert.Equal(t, "error", cfg.Log.Level)
	assert.Equal(t, "text", cfg.Log.Format)
	assert.Equal(t, "127.0.0.1:9999", cfg.Gateway.ListenAddr)
}

func TestConfigStructs(t *testing.T) {
	// Test that all config structs can be instantiated
	t.Run("Config instantiation", func(t *testing.T) {
		cfg := &Config{
			Proxy: ProxyConfig{
				SOCKS5: SOCKS5Config{
					ListenAddr:   "127.0.0.1:1080",
					AuthUsername: "user",
					AuthPassword: "pass",
				},
				HTTP: HTTPConfig{
					ListenAddr:   "127.0.0.1:8080",
					AuthUsername: "httpuser",
					AuthPassword: "httppass",
				},
			},
			Gateway: GatewayConfig{
				ListenAddr:   "0.0.0.0:8443",
				TLSCert:      "/cert.pem",
				TLSKey:       "/key.pem",
				AuthUsername: "gw",
				AuthPassword: "gwpass",
			},
			Client: ClientConfig{
				GatewayAddr:    "gw.example.com:8443",
				GatewayTLSCert: "/gw-cert.pem",
				ClientID:       "client1",
				Replicas:       2,
				AuthUsername:   "client",
				AuthPassword:   "clientpass",
				ForbiddenHosts: []string{"bad.com"},
				AllowedHosts:   []string{"good.com"},
			},
			Log: LogConfig{
				Level:      "info",
				Format:     "json",
				Output:     "file",
				File:       "/tmp/log.txt",
				MaxSize:    100,
				MaxBackups: 3,
				MaxAge:     30,
				Compress:   true,
			},
		}

		assert.NotNil(t, cfg)
		assert.Equal(t, "127.0.0.1:1080", cfg.Proxy.SOCKS5.ListenAddr)
		assert.Equal(t, "127.0.0.1:8080", cfg.Proxy.HTTP.ListenAddr)
		assert.Equal(t, "0.0.0.0:8443", cfg.Gateway.ListenAddr)
		assert.Equal(t, "gw.example.com:8443", cfg.Client.GatewayAddr)
		assert.Equal(t, "info", cfg.Log.Level)
		assert.Len(t, cfg.Client.ForbiddenHosts, 1)
		assert.Len(t, cfg.Client.AllowedHosts, 1)
	})

	t.Run("Zero values", func(t *testing.T) {
		cfg := &Config{}
		assert.Equal(t, "", cfg.Proxy.SOCKS5.ListenAddr)
		assert.Equal(t, "", cfg.Gateway.ListenAddr)
		assert.Equal(t, "", cfg.Client.GatewayAddr)
		assert.Equal(t, "", cfg.Log.Level)
		assert.Equal(t, 0, cfg.Client.Replicas)
		assert.Nil(t, cfg.Client.ForbiddenHosts)
		assert.Nil(t, cfg.Client.AllowedHosts)
		assert.False(t, cfg.Log.Compress)
	})
}

func TestConfigYAMLTags(t *testing.T) {
	// Test that YAML tags work correctly by loading and comparing configs
	configYAML := `
proxy:
  socks5:
    listen_addr: "test:1080"
    auth_username: "socks5user"
    auth_password: "socks5pass"
  http:
    listen_addr: "test:8080"
    auth_username: "httpuser"
    auth_password: "httppass"
gateway:
  listen_addr: "test:8443"
  tls_cert: "test.crt"
  tls_key: "test.key"
  auth_username: "gwuser"
  auth_password: "gwpass"
client:
  gateway_addr: "gw.test:8443"
  gateway_tls_cert: "gw.crt"
  client_id: "test-client"
  replicas: 5
  auth_username: "clientuser"
  auth_password: "clientpass"
  forbidden_hosts: ["bad1.com", "bad2.com"]
  allowed_hosts: ["good1.com", "good2.com"]
log:
  level: "debug"
  format: "text"
  output: "file"
  file: "test.log"
  max_size: 200
  max_backups: 10
  max_age: 60
  compress: true
`

	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "test_config.yaml")

	err := os.WriteFile(configFile, []byte(configYAML), 0644)
	require.NoError(t, err)

	cfg, err := LoadConfig(configFile)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify all fields are loaded correctly
	assert.Equal(t, "test:1080", cfg.Proxy.SOCKS5.ListenAddr)
	assert.Equal(t, "socks5user", cfg.Proxy.SOCKS5.AuthUsername)
	assert.Equal(t, "socks5pass", cfg.Proxy.SOCKS5.AuthPassword)

	assert.Equal(t, "test:8080", cfg.Proxy.HTTP.ListenAddr)
	assert.Equal(t, "httpuser", cfg.Proxy.HTTP.AuthUsername)
	assert.Equal(t, "httppass", cfg.Proxy.HTTP.AuthPassword)

	assert.Equal(t, "test:8443", cfg.Gateway.ListenAddr)
	assert.Equal(t, "test.crt", cfg.Gateway.TLSCert)
	assert.Equal(t, "test.key", cfg.Gateway.TLSKey)
	assert.Equal(t, "gwuser", cfg.Gateway.AuthUsername)
	assert.Equal(t, "gwpass", cfg.Gateway.AuthPassword)

	assert.Equal(t, "gw.test:8443", cfg.Client.GatewayAddr)
	assert.Equal(t, "gw.crt", cfg.Client.GatewayTLSCert)
	assert.Equal(t, "test-client", cfg.Client.ClientID)
	assert.Equal(t, 5, cfg.Client.Replicas)
	assert.Equal(t, "clientuser", cfg.Client.AuthUsername)
	assert.Equal(t, "clientpass", cfg.Client.AuthPassword)
	assert.Equal(t, []string{"bad1.com", "bad2.com"}, cfg.Client.ForbiddenHosts)
	assert.Equal(t, []string{"good1.com", "good2.com"}, cfg.Client.AllowedHosts)

	assert.Equal(t, "debug", cfg.Log.Level)
	assert.Equal(t, "text", cfg.Log.Format)
	assert.Equal(t, "file", cfg.Log.Output)
	assert.Equal(t, "test.log", cfg.Log.File)
	assert.Equal(t, 200, cfg.Log.MaxSize)
	assert.Equal(t, 10, cfg.Log.MaxBackups)
	assert.Equal(t, 60, cfg.Log.MaxAge)
	assert.True(t, cfg.Log.Compress)
}

// TestConcurrentAccess tests that GetConfig is safe for concurrent access
func TestConcurrentAccess(t *testing.T) {
	// Reset global config
	conf = nil

	// Load initial config
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	configYAML := `
log:
  level: "info"
`

	err := os.WriteFile(configFile, []byte(configYAML), 0644)
	require.NoError(t, err)

	_, err = LoadConfig(configFile)
	require.NoError(t, err)

	// Test concurrent access to GetConfig
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				cfg := GetConfig()
				assert.NotNil(t, cfg)
				assert.Equal(t, "info", cfg.Log.Level)
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
