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

## 🚀 Quick Navigation

### New to AnyProxy?
1. **[Quick Start Guide](#quick-start)** - Get up and running in 5 minutes
2. **[Quick Start with Docker](#quick-start-with-docker)** - Even faster setup with official Docker image
3. **[System Architecture](#system-architecture)** - Understand how AnyProxy works
4. **[Basic Configuration](#basic-configuration)** - Essential configuration steps
5. **[Usage Examples](#usage-examples)** - Test your setup with practical examples

### Ready for Production?
1. **[Docker Deployment](#docker-deployment)** - Containerized deployment for gateway and client
2. **[Production Installation](#production-installation)** - Traditional installation methods
3. **[Deployment Guide](docs/DEPLOYMENT.md)** - Complete production setup
4. **[Security Hardening](docs/DEPLOYMENT.md#security-hardening)** - Secure your installation
5. **[Performance Tuning](docs/DEPLOYMENT.md#performance-optimization)** - Optimize performance

### Need Help?
1. **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions
2. **[HTTP Proxy Issues](docs/HTTP_PROXY_TROUBLESHOOTING.md)** - HTTP-specific problems
3. **[FAQ](#frequently-asked-questions)** - Frequently asked questions
4. **[Community Support](#community-and-support)** - Get help from the community

## 📚 Complete Documentation

### 🏗️ Architecture and Design
- **[System Architecture](docs/ARCHITECTURE.md)** - Detailed system architecture and design principles
- **[API Documentation](docs/API.md)** - WebSocket API and message formats
- **[Project Requirements](design/requirement.md)** - Original project requirements and specifications

### 🛠️ Installation and Setup
- **[Quick Start Guide](#quick-start)** - Get started in minutes
- **[Docker Deployment](#docker-deployment)** - Containerized deployment guide
- **[Production Installation](#production-installation)** - Traditional installation methods
- **[Certificate Setup](#generating-certificates)** - TLS certificate configuration

### ⚙️ Configuration and Usage
- **[Basic Configuration](#basic-configuration)** - Essential settings
- **[Advanced Configuration](docs/DEPLOYMENT.md#advanced-configuration)** - Production-ready settings
- **[Usage Examples](#usage-examples)** - HTTP and SOCKS5 proxy examples
- **[Mobile Client Setup](#mobile-client-configuration)** - Mobile device configuration

### 🌐 Proxy Services
- **[Dual Proxy Support](docs/DUAL_PROXY.md)** - HTTP and SOCKS5 proxy documentation
- **[SOCKS5 Client DNS](docs/SOCKS5_CLIENT_DNS.md)** - Client-side DNS resolution guide
- **[HTTP Proxy Features](#http-proxy-usage)** - Detailed HTTP proxy usage
- **[SOCKS5 Proxy Features](#socks5-proxy-usage)** - Comprehensive SOCKS5 documentation

### 🚀 Deployment and Operations
- **[Production Deployment](docs/DEPLOYMENT.md)** - Complete production setup guide
- **[Service Management](#service-management)** - Managing AnyProxy services
- **[Monitoring and Logging](docs/LOGGING.md)** - Comprehensive logging guide
- **[Performance Monitoring](#performance-metrics)** - Performance monitoring guide

### 🔍 Troubleshooting and Support
- **[General Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[HTTP Proxy Troubleshooting](docs/HTTP_PROXY_TROUBLESHOOTING.md)** - HTTP-specific issues
- **[Docker Troubleshooting](#docker-troubleshooting)** - Container-specific issues
- **[Performance Issues](#performance-metrics)** - Performance optimization

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

### Quick Start with Docker

For a faster setup using the official Docker image:

```bash
# Pull the official image
docker pull buhuipao/anyproxy:latest

# Create workspace
mkdir anyproxy-docker && cd anyproxy-docker
mkdir -p configs logs

# Note: The official image includes built-in certificates
# No need to generate certificates manually

# Create basic configuration
cat > configs/config.yaml << EOF
log:
  level: "info"
proxy:
  http:
    listen_addr: ":8080"
    auth_username: "test"
    auth_password: "test123"
  socks5:
    listen_addr: ":1080"
    auth_username: "test"
    auth_password: "test123"
gateway:
  listen_addr: ":8443"
  # Using built-in certificates
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway"
  auth_password: "gateway123"
client:
  gateway_addr: "127.0.0.1:8443"
  # Using built-in certificate
  gateway_tls_cert: "certs/server.crt"
  client_id: "test-client"
  auth_username: "gateway"
  auth_password: "gateway123"
EOF

# Start gateway
docker run -d --name anyproxy-test-gateway \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/config.yaml

# Start client
sleep 2
docker run -d --name anyproxy-test-client \
  --network container:anyproxy-test-gateway \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/config.yaml

# Test the setup
curl -x http://test:test123@127.0.0.1:8080 https://httpbin.org/ip
```

### Production Installation

```bash
# Run the automated setup script (requires sudo)
sudo ./scripts/setup_runtime_dirs.sh

# Or use the service manager
./scripts/service_manager.sh install
./scripts/service_manager.sh start
```

### Docker Deployment

Docker provides an easy way to deploy AnyProxy components separately for network tunneling scenarios. Gateway and client should be deployed independently on different servers.

#### Prerequisites
- **Docker**: Docker Engine 20.0+
- **Network Access**: Gateway needs public network access, client needs access to gateway

#### Gateway Deployment (Public Server)

Deploy the gateway on a server with public network access:

```bash
# Pull the official AnyProxy image
docker pull buhuipao/anyproxy:latest

# Create directories for configuration and logs
mkdir -p configs logs

# Note: The official Docker image already includes built-in certificates
# You only need to provide custom certificates if you want to use your own

# Create gateway configuration
cat > configs/gateway-config.yaml << EOF
log:
  level: "info"
  format: "text"
  output: "stdout"

proxy:
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_password"
  socks5:
    listen_addr: ":1080"
    auth_username: "socks_user"
    auth_password: "socks_password"

gateway:
  listen_addr: ":8443"
  # Using built-in certificates (default)
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway_user"
  auth_password: "gateway_password"
EOF

# Run gateway container (using built-in certificates)
docker run -d \
  --name anyproxy-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 1080:1080 \
  -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/logs:/app/logs \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/gateway-config.yaml

# Check gateway status
docker logs anyproxy-gateway
```

**Using Custom Certificates (Optional):**

If you want to use your own certificates instead of the built-in ones:

```bash
# Create certs directory and add your custom certificates
mkdir -p certs
# Copy your certificates to the certs directory
cp /path/to/your/server.crt certs/
cp /path/to/your/server.key certs/

# Run with custom certificates mounted
docker run -d \
  --name anyproxy-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 1080:1080 \
  -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/logs:/app/logs \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/gateway-config.yaml
```

#### Client Deployment (Internal Network)

Deploy the client on internal network servers that need to be accessed:

```bash
# Pull the official AnyProxy image
docker pull buhuipao/anyproxy:latest

# Create directories for configuration and logs
mkdir -p configs logs

# Create client configuration
cat > configs/client-config.yaml << EOF
log:
  level: "info"
  format: "text"
  output: "stdout"

client:
  gateway_addr: "YOUR_GATEWAY_SERVER_IP:8443"  # Replace with actual gateway IP
  # Using built-in certificate (same as gateway's built-in certificate)
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
EOF

# Run client container (using built-in certificates)
docker run -d \
  --name anyproxy-client \
  --restart unless-stopped \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/logs:/app/logs \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml

# Check client status
docker logs anyproxy-client
```

**Important Notes:**
- The client uses the same built-in certificate as the gateway by default
- Both gateway and client containers include the same certificate files
- For production, consider using custom certificates with proper domain names

#### Quick Start with Official Image

For a quick test setup:

```bash
# Pull the image
docker pull buhuipao/anyproxy:latest

# Create a simple test setup (single machine)
mkdir -p anyproxy-test/{configs,logs}
cd anyproxy-test

# Note: Using built-in certificates for testing
# No need to generate certificates - they're included in the image

# Create basic config
cat > configs/config.yaml << 'EOF'
log:
  level: "info"
proxy:
  http:
    listen_addr: ":8080"
    auth_username: "test"
    auth_password: "test123"
  socks5:
    listen_addr: ":1080"
    auth_username: "test"
    auth_password: "test123"
gateway:
  listen_addr: ":8443"
  # Using built-in certificates
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway"
  auth_password: "gateway123"
client:
  gateway_addr: "127.0.0.1:8443"
  # Using built-in certificate
  gateway_tls_cert: "certs/server.crt"
  client_id: "test-client"
  auth_username: "gateway"
  auth_password: "gateway123"
EOF

# Run gateway
docker run -d --name test-gateway \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/config.yaml

# Run client (after gateway starts)
sleep 3
docker run -d --name test-client \
  --network container:test-gateway \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/config.yaml

# Test the setup
curl -x http://test:test123@127.0.0.1:8080 https://httpbin.org/ip
```

#### Multiple Clients Setup

For load balancing and redundancy, deploy multiple clients:

```bash
# Deploy additional clients with different IDs
docker run -d \
  --name anyproxy-client-2 \
  --restart unless-stopped \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/logs:/app/logs \
  -e CLIENT_ID=client-002 \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml

docker run -d \
  --name anyproxy-client-3 \
  --restart unless-stopped \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/logs:/app/logs \
  -e CLIENT_ID=client-003 \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml
```

#### Environment Variables for Docker

Both gateway and client support environment variable overrides:

```bash
# Gateway environment variables
docker run -d \
  --name anyproxy-gateway \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -e LOG_LEVEL=debug \
  -e HTTP_AUTH_USER=myuser \
  -e HTTP_AUTH_PASS=mypass \
  -e GATEWAY_AUTH_USER=gwuser \
  -e GATEWAY_AUTH_PASS=gwpass \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/gateway-config.yaml

# Client environment variables
docker run -d \
  --name anyproxy-client \
  -e LOG_LEVEL=debug \
  -e GATEWAY_ADDR=gateway.example.com:8443 \
  -e CLIENT_ID=my-client \
  -e GATEWAY_AUTH_USER=gwuser \
  -e GATEWAY_AUTH_PASS=gwpass \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml
```

#### Docker Management Commands

**Gateway Management:**
```bash
# View gateway logs
docker logs -f anyproxy-gateway

# Restart gateway
docker restart anyproxy-gateway

# Update gateway configuration
docker exec anyproxy-gateway cat /app/configs/gateway-config.yaml

# Monitor resource usage
docker stats anyproxy-gateway

# Update to latest image
docker pull buhuipao/anyproxy:latest
docker stop anyproxy-gateway
docker rm anyproxy-gateway
# Then re-run with new image
```

**Client Management:**
```bash
# View client logs
docker logs -f anyproxy-client

# Restart client
docker restart anyproxy-client

# Check connectivity to gateway
docker exec anyproxy-client ping gateway-server-ip

# Scale clients
docker run -d --name anyproxy-client-4 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -e CLIENT_ID=client-004 \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml

# Update all clients to latest image
docker pull buhuipao/anyproxy:latest
for client in anyproxy-client anyproxy-client-2 anyproxy-client-3; do
  docker stop $client
  docker rm $client
  # Re-run with updated commands
done
```

#### Docker Security Best Practices

**For Production Deployment:**
```bash
# Use specific image tags instead of 'latest'
docker pull buhuipao/anyproxy:v1.0.0

# Run with resource limits
docker run -d \
  --name anyproxy-gateway \
  --memory="256m" \
  --cpus="1.0" \
  --ulimit nofile=65536:65536 \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  buhuipao/anyproxy:v1.0.0

# Use Docker secrets for sensitive data (Docker Swarm)
echo "gateway_password" | docker secret create gateway-pass -
docker service create \
  --name anyproxy-gateway \
  --secret gateway-pass \
  --publish 8080:8080 \
  --publish 1080:1080 \
  --publish 8443:8443 \
  buhuipao/anyproxy:latest

# Run with non-root user (already configured in the image)
# The official image runs as user 'anyproxy' with UID 1001

# Use read-only root filesystem
docker run -d \
  --name anyproxy-gateway \
  --read-only \
  --tmpfs /tmp \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  -v $(pwd)/logs:/app/logs \
  buhuipao/anyproxy:latest
```

#### Testing the Setup

After deploying both gateway and client:

```bash
# Test HTTP proxy (from any internet location)
curl -x http://http_user:http_password@GATEWAY_SERVER_IP:8080 \
     http://internal-service.local

# Test SOCKS5 proxy
curl --socks5 socks_user:socks_password@GATEWAY_SERVER_IP:1080 \
     http://internal-service.local

# Test connectivity
docker exec anyproxy-client nc -zv GATEWAY_SERVER_IP 8443

# Check container health
docker inspect anyproxy-gateway --format='{{.State.Health.Status}}'
docker inspect anyproxy-client --format='{{.State.Health.Status}}'

# Monitor logs for issues
docker logs anyproxy-gateway --tail 100
docker logs anyproxy-client --tail 100
```

#### Available Image Tags

The official Docker image supports multiple tags:

```bash
# Latest stable release
docker pull buhuipao/anyproxy:latest

# Specific version tags
docker pull buhuipao/anyproxy:v1.0.0
docker pull buhuipao/anyproxy:v1.0.1

# Development builds (if available)
docker pull buhuipao/anyproxy:dev

# Check available tags on Docker Hub:
# https://hub.docker.com/r/buhuipao/anyproxy/tags
```

For more deployment scenarios, see [Deployment Guide](docs/DEPLOYMENT.md).

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
- [Quick Start Guide](#quick-start) - Get started quickly
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

3. **Certificate Issues**
   ```bash
   # Verify certificate mount (if using custom certificates)
   docker exec anyproxy-gateway ls -la /app/certs/
   
   # Check built-in certificate validity
   docker exec anyproxy-gateway openssl x509 -in /app/certs/server.crt -text -noout
   
   # Test TLS connection
   docker exec anyproxy-client openssl s_client -connect GATEWAY_IP:8443
   
   # Note: Built-in certificates are for testing only
   # For production, mount your own certificates:
   # -v /path/to/your/certs:/app/certs:ro
   ```

For comprehensive troubleshooting, see:
- [General Troubleshooting Guide](docs/TROUBLESHOOTING.md)
- [HTTP Proxy Issues](docs/HTTP_PROXY_TROUBLESHOOTING.md)

## 🔐 Generating Certificates

AnyProxy requires TLS certificates for secure communication between gateway and clients.

### Automatic Certificate Generation

```bash
# Generate self-signed certificates (for development)
make certs

# Or manually with OpenSSL
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName = DNS:localhost,DNS:anyproxy,IP:127.0.0.1,IP:0.0.0.0"
```

### Production Certificates

For production deployment, use certificates from a trusted CA:

```bash
# Using Let's Encrypt with certbot
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates to AnyProxy directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem certs/server.key
sudo chown $(whoami):$(whoami) certs/server.*
```

### Certificate Distribution

For distributed deployment, ensure all clients use the same gateway certificate:

```bash
# On gateway server
scp certs/server.crt user@client-server:/path/to/anyproxy/certs/

# Or use a shared certificate authority
# Client configuration can verify against CA certificate
```

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

### Load Testing

```bash
# Test HTTP proxy performance
hey -n 10000 -c 100 -x http://user:pass@gateway-ip:8080 http://target-service

# Test SOCKS5 proxy performance
curl --socks5 user:pass@gateway-ip:1080 http://target-service

# Monitor system resources during testing
htop
netstat -i
iotop
```

## 🐳 Docker Troubleshooting

### Common Docker Issues

1. **Container Won't Start**
   ```bash
   # Check logs for startup errors
   docker logs anyproxy-gateway
   docker logs anyproxy-client
   
   # Verify configuration files
   docker exec anyproxy-gateway cat /app/configs/gateway-config.yaml
   
   # Check file permissions
   docker exec anyproxy-gateway ls -la /app/
   
   # Test image directly
   docker run --rm buhuipao/anyproxy:latest ./anyproxy-gateway --version
   ```

2. **Network Connection Issues**
   ```bash
   # Test connectivity between client and gateway
   docker exec anyproxy-client nc -zv GATEWAY_SERVER_IP 8443
   
   # Check port exposure
   docker port anyproxy-gateway
   
   # Verify DNS resolution
   docker exec anyproxy-client nslookup gateway.example.com
   
   # Test network from outside
   telnet GATEWAY_SERVER_IP 8443
   ```

3. **Certificate Issues**
   ```bash
   # Verify certificate mount (if using custom certificates)
   docker exec anyproxy-gateway ls -la /app/certs/
   
   # Check built-in certificate validity
   docker exec anyproxy-gateway openssl x509 -in /app/certs/server.crt -text -noout
   
   # Test TLS connection
   docker exec anyproxy-client openssl s_client -connect GATEWAY_IP:8443
   
   # Note: Built-in certificates are for testing only
   # For production, mount your own certificates:
   # -v /path/to/your/certs:/app/certs:ro
   ```

4. **Performance Issues**
   ```bash
   # Monitor resource usage
   docker stats anyproxy-gateway anyproxy-client
   
   # Check container limits
   docker inspect anyproxy-gateway | grep -A 10 "Resources"
   
   # View system resources
   docker system df
   docker system events
   
   # Check image size
   docker images buhuipao/anyproxy
   ```

5. **Image and Update Issues**
   ```bash
   # Check current image version
   docker inspect buhuipao/anyproxy:latest | grep -A 5 "Labels"
   
   # Force pull latest image
   docker pull buhuipao/anyproxy:latest --no-cache
   
   # Clean old images
   docker image prune -f
   
   # Verify image integrity
   docker run --rm buhuipao/anyproxy:latest ./anyproxy-gateway --version
   docker run --rm buhuipao/anyproxy:latest ./anyproxy-client --version
   ```

### Docker Best Practices for Troubleshooting

1. **Structured Logging**: Use JSON log format for easier parsing
   ```bash
   docker run -d \
     --log-driver=json-file \
     --log-opt max-size=10m \
     --log-opt max-file=3 \
     buhuipao/anyproxy:latest
   ```

2. **Health Checks**: Monitor container health
   ```bash
   # Check health status
   docker inspect anyproxy-gateway --format='{{.State.Health.Status}}'
   
   # View health check logs
   docker inspect anyproxy-gateway --format='{{range .State.Health.Log}}{{.Output}}{{end}}'
   ```

3. **Resource Monitoring**: Set up monitoring for container metrics
   ```bash
   # Monitor in real-time
   docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
   
   # Container resource limits
   docker update --memory=512m --cpus=1.5 anyproxy-gateway
   ```

4. **Log Aggregation**: Use centralized logging solutions
   ```bash
   # Example with syslog driver
   docker run -d \
     --log-driver=syslog \
     --log-opt syslog-address=tcp://log-server:514 \
     buhuipao/anyproxy:latest
   ```

## 📋 Frequently Asked Questions

### General Questions

**Q: What is AnyProxy?**
A: AnyProxy is a secure, high-performance proxy system that allows developers to safely expose local services to public users through encrypted WebSocket + TLS tunnels.

**Q: What protocols does AnyProxy support?**
A: AnyProxy supports HTTP/HTTPS and SOCKS5 proxy protocols, with WebSocket + TLS for client-gateway communication.

**Q: Is AnyProxy secure?**
A: Yes, AnyProxy uses TLS 1.2+ encryption, supports multiple authentication methods, and includes comprehensive access controls.

### Deployment Questions

**Q: Can I run both HTTP and SOCKS5 proxies simultaneously?**
A: Yes, AnyProxy supports dual proxy operation with independent configuration for each proxy type.

**Q: How do I deploy gateway and client on different servers?**
A: Use the [Docker Deployment](#docker-deployment) guide for separate deployments, or follow the [Production Installation](#production-installation) guide for traditional deployment.

**Q: How many concurrent connections can AnyProxy handle?**
A: AnyProxy can handle thousands of concurrent connections, with actual limits depending on system resources and configuration.

### Configuration Questions

**Q: How do I configure custom certificates?**
A: Generate certificates using `make certs` or see the [Certificate Configuration Guide](docs/DEPLOYMENT.md#certificate-configuration) for custom certificates.

**Q: Can I use environment variables for configuration?**
A: Yes, many configuration options can be overridden with environment variables. See the Docker deployment examples for common environment variables.

**Q: How do I enable debug logging?**
A: Set `log.level: "debug"` in your configuration file or use the environment variable `LOG_LEVEL=debug`.

**Q: What's the difference between client-side and server-side DNS resolution in SOCKS5?**
A: AnyProxy uses client-side DNS resolution by default, which means domain names are resolved by the client rather than the proxy server. This provides better privacy and flexibility. See [SOCKS5 Client DNS Documentation](docs/SOCKS5_CLIENT_DNS.md) for details.

### Technical Questions

**Q: Does AnyProxy support IPv6?**
A: Yes, AnyProxy supports both IPv4 and IPv6 addresses.

**Q: Can I use AnyProxy with load balancers?**
A: Yes, you can deploy multiple gateway instances behind a load balancer, and multiple clients can connect to the same gateway for redundancy.

**Q: How do I monitor AnyProxy performance?**
A: Use the built-in logging features, system monitoring tools, or see [Monitoring and Logging](docs/LOGGING.md) for comprehensive monitoring setup.

For more questions, check our [GitHub Discussions](https://github.com/buhuipao/anyproxy/discussions) or [create an issue](https://github.com/buhuipao/anyproxy/issues).

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

For more information, check out the [documentation](docs/) directory or see the [examples](examples/) directory. 