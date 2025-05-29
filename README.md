# AnyProxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Release](https://img.shields.io/badge/Release-v1.0.0-green.svg)](https://github.com/buhuipao/anyproxy/releases)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)]()

AnyProxy is a secure, high-performance WebSocket + TLS based proxy system that enables developers to safely expose local services to public users through encrypted tunnels. It supports both HTTP/HTTPS and SOCKS5 proxy protocols simultaneously, providing flexible and secure access to internal resources.

## 🌟 Key Features

### 🔐 Security First
- **End-to-End TLS Encryption**: All communications use TLS 1.2+ encryption
- **Multi-Layer Authentication**: Support for client authentication, proxy authentication, and access control
- **Certificate-Based Security**: Support for custom domain certificates and client certificates
- **Access Control Lists**: Configurable blacklist and whitelist mechanisms

### 🚀 High Performance
- **Dual Proxy Support**: Run HTTP/HTTPS and SOCKS5 proxies simultaneously
- **Load Balancing**: Automatic distribution across multiple client connections
- **Connection Pooling**: Efficient WebSocket connection reuse
- **Concurrent Processing**: Support for thousands of concurrent connections

### 🛠️ Developer Friendly
- **Easy Deployment**: Simple configuration and deployment process
- **Comprehensive Monitoring**: Built-in logging and metrics
- **Flexible Configuration**: YAML-based configuration with environment variable support
- **Production Ready**: Systemd integration and service management tools

### 🌐 Protocol Support
- **HTTP/HTTPS Proxy**: Full HTTP proxy protocol support including CONNECT method
- **SOCKS5 Proxy**: Complete SOCKS5 implementation with authentication and **client-side DNS resolution**
- **WebSocket Tunneling**: Secure WebSocket + TLS communication channel
- **Multi-Protocol**: TCP and UDP traffic support

## 📋 System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Public Users  │───▶│   Proxy Gateway  │───▶│   WebSocket     │───▶│  Target Service │
│   (Internet)    │    │  HTTP + SOCKS5   │    │   TLS Tunnel    │    │   (LAN/WAN)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Components

1. **Gateway**: Accepts HTTP/SOCKS5 connections from public users and manages WebSocket connections from clients
2. **Client**: Establishes secure WebSocket connections to the gateway and forwards requests to target services
3. **Proxy Services**: HTTP and SOCKS5 proxy servers with independent configuration and authentication

### Data Flow

1. **Client Registration**: Client proactively connects to gateway via WebSocket + TLS
2. **User Connection**: Public users connect through HTTP or SOCKS5 proxy
3. **Request Forwarding**: Gateway forwards requests to available clients
4. **Service Access**: Client accesses target services and returns responses

## 🛠️ Installation and Setup

### Prerequisites

- **Go 1.21+**: For building from source
- **OpenSSL**: For certificate generation
- **Linux/macOS/Windows**: Cross-platform support (Linux recommended for production)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# Generate TLS certificates
make certs

# Build the project
make build

# Start gateway (in one terminal)
make run-gateway

# Start client (in another terminal)
make run-client
```

### Production Installation

```bash
# Run the automated setup script (requires sudo)
sudo ./scripts/setup_runtime_dirs.sh

# Or use the service manager
./scripts/service_manager.sh install
./scripts/service_manager.sh start
```

## ⚙️ Configuration

### Basic Configuration

The main configuration file is located at `configs/config.yaml`:

```yaml
# Log configuration
log:
  level: "info"
  format: "text"
  output: "stdout"

# Proxy configuration - supports both HTTP and SOCKS5
proxy:
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_password"
  socks5:
    listen_addr: ":1080"
    auth_username: "socks_user"
    auth_password: "socks_password"

# Gateway configuration
gateway:
  listen_addr: ":8443"
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway_user"
  auth_password: "gateway_password"

# Client configuration
client:
  gateway_addr: "127.0.0.1:8443"
  gateway_tls_cert: "certs/server.crt"
  client_id: "client-001"
  replicas: 1
  max_concurrent_conns: 100
  auth_username: "gateway_user"
  auth_password: "gateway_password"
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "192.168.0.0/16"
  limit:
    - name: "web-server"
      addr: "localhost:8080"
      protocol: "tcp"
```

### Advanced Configuration

For production deployments, see:
- [Deployment Guide](docs/DEPLOYMENT.md) - Complete production setup
- [Configuration Examples](configs/) - Various configuration templates
- [Security Hardening](docs/DEPLOYMENT.md#security-hardening) - Security best practices

## 🚀 Usage Examples

### HTTP Proxy Usage

```bash
# Using curl with HTTP proxy
curl -x http://http_user:http_password@127.0.0.1:8080 https://example.com

# Setting environment variables
export http_proxy=http://http_user:http_password@127.0.0.1:8080
export https_proxy=http://http_user:http_password@127.0.0.1:8080
curl https://example.com

# Browser configuration
# Proxy Type: HTTP
# Address: 127.0.0.1
# Port: 8080
# Username: http_user
# Password: http_password
```

### SOCKS5 Proxy Usage

AnyProxy's SOCKS5 proxy supports **client-side DNS resolution**, which means domain names are resolved by the client rather than the proxy server. This provides better privacy and allows clients to use their own DNS servers.

```bash
# Using curl with SOCKS5 proxy (client-side DNS resolution)
curl --socks5 socks_user:socks_password@127.0.0.1:1080 https://example.com

# Setting environment variables
export ALL_PROXY=socks5://socks_user:socks_password@127.0.0.1:1080
curl https://example.com

# SSH tunneling through SOCKS5
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" user@target-server
```

#### Client-Side DNS Resolution Benefits

- **Privacy Protection**: The proxy server doesn't see the actual target IP addresses
- **DNS Flexibility**: Clients can use any DNS server (including custom/private DNS)
- **Bypass DNS Restrictions**: Avoid DNS pollution and censorship
- **Local Network Support**: Resolve local network hostnames
- **Reduced Server Load**: DNS resolution work is distributed to clients

For detailed information about client-side DNS resolution, see [SOCKS5 Client DNS Documentation](docs/SOCKS5_CLIENT_DNS.md).

### Mobile Client Configuration

For mobile devices using Clash for Android:
- [Clash Configuration Guide](configs/clash-android-usage.md)
- [Simple Configuration](configs/clash-android-simple.yaml)
- [Advanced Configuration](configs/clash-android.yaml)

## 📁 Project Structure

```
anyproxy/
├── cmd/                    # Application entry points
│   ├── gateway/           # Gateway application
│   └── client/            # Client application
├── pkg/                   # Core packages
│   ├── config/           # Configuration management
│   ├── proxy/            # Proxy implementations
│   └── websocket/        # WebSocket handling
├── configs/              # Configuration files and examples
├── certs/               # TLS certificates
├── docs/                # Comprehensive documentation
├── design/              # Architecture and design documents
├── scripts/             # Deployment and management scripts
├── examples/            # Usage examples
├── Makefile            # Build automation
└── generate_certs.sh   # Certificate generation script
```

## 🔧 Development

### Building from Source

```bash
# Install dependencies
go mod download

# Run tests
make test

# Build for current platform
make build

# Build for all platforms
make build-all

# Clean build artifacts
make clean
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
make test-coverage

# Run specific package tests
go test ./pkg/proxy/

# Run benchmarks
go test -bench=. ./pkg/proxy/
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📖 Documentation

### User Documentation
- [Quick Start Guide](docs/README.md) - Get started quickly
- [Deployment Guide](docs/DEPLOYMENT.md) - Production deployment
- [Configuration Reference](docs/API.md) - Complete configuration options
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Common issues and solutions

### Technical Documentation
- [Architecture Design](docs/ARCHITECTURE.md) - System architecture and design
- [API Documentation](docs/API.md) - WebSocket API and message formats
- [Dual Proxy Support](docs/DUAL_PROXY.md) - HTTP and SOCKS5 proxy details
- [SOCKS5 Client DNS](docs/SOCKS5_CLIENT_DNS.md) - Client-side DNS resolution guide
- [Logging Guide](docs/LOGGING.md) - Logging configuration and best practices

### Specialized Guides
- [HTTP Proxy Troubleshooting](docs/HTTP_PROXY_TROUBLESHOOTING.md) - HTTP proxy specific issues
- [Security Considerations](docs/DEPLOYMENT.md#security-hardening) - Security best practices
- [Performance Tuning](docs/DEPLOYMENT.md#performance-optimization) - Performance optimization

## 🔍 Monitoring and Operations

### Service Management

```bash
# Using the service manager script
./scripts/service_manager.sh status          # Check service status
./scripts/service_manager.sh start           # Start all services
./scripts/service_manager.sh stop gateway    # Stop specific service
./scripts/service_manager.sh logs client     # View service logs
./scripts/service_manager.sh restart         # Restart all services
```

### Health Monitoring

```bash
# Check service health
systemctl status anyproxy-gateway anyproxy-client

# View real-time logs
journalctl -u anyproxy-gateway -f

# Monitor resource usage
top -p $(pgrep anyproxy)
```

### Performance Metrics

- Connection count and success rate
- Request/response latency
- Bandwidth utilization
- Error rates and types
- Resource consumption (CPU, memory, network)

## 🛡️ Security Features

### Transport Security
- **TLS 1.2+ Encryption**: All WebSocket communications encrypted
- **Certificate Validation**: Server certificate verification
- **Perfect Forward Secrecy**: Ephemeral key exchange

### Authentication & Authorization
- **Multi-Level Authentication**: Gateway, proxy, and client authentication
- **Access Control Lists**: Host-based and IP-based restrictions
- **Service Limitations**: Configurable service access controls

### Network Security
- **Firewall Integration**: Proper port management
- **Rate Limiting**: Protection against abuse
- **Connection Limits**: Configurable concurrent connection limits

## 🚨 Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if services are running
   systemctl status anyproxy-gateway anyproxy-client
   
   # Check port availability
   netstat -tlnp | grep -E ':(8080|1080|8443)'
   ```

2. **Authentication Failures**
   ```bash
   # Verify configuration
   grep -A5 -B5 auth configs/config.yaml
   
   # Check logs for auth errors
   journalctl -u anyproxy-gateway | grep auth
   ```

3. **TLS Certificate Issues**
   ```bash
   # Regenerate certificates
   make certs
   
   # Verify certificate validity
   openssl x509 -in certs/server.crt -text -noout
   ```

For comprehensive troubleshooting, see:
- [General Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- [HTTP Proxy Issues](docs/HTTP_PROXY_TROUBLESHOOTING.md)

## 📊 Performance Benchmarks

### Typical Performance Metrics
- **Throughput**: 1,000+ concurrent connections
- **Latency**: <10ms additional latency
- **Memory Usage**: <100MB for typical workloads
- **CPU Usage**: <5% on modern hardware

### Optimization Tips
- Use multiple client replicas for high load
- Configure appropriate buffer sizes
- Enable connection pooling
- Monitor and tune system limits

## 🔄 Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.

### Current Release: v1.0.0
- ✅ Dual proxy support (HTTP + SOCKS5)
- ✅ Enhanced security features
- ✅ Production deployment tools
- ✅ Comprehensive documentation
- ✅ Complete English documentation

## 🤝 Community and Support

### Getting Help
- **Documentation**: Comprehensive guides in the `docs/` directory
- **Issues**: Report bugs and request features on [GitHub Issues](https://github.com/buhuipao/anyproxy/issues)
- **Discussions**: Join community discussions on [GitHub Discussions](https://github.com/buhuipao/anyproxy/discussions)

### Contributing
We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors who have helped improve AnyProxy
- Special thanks to the Go community for excellent libraries and tools
- Inspired by various proxy and tunneling solutions in the open source community

---

**Made with ❤️ by the AnyProxy team**

For more information, visit our [documentation](docs/README.md) or check out the [examples](examples/) directory. 