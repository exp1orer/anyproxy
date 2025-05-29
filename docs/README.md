# AnyProxy Documentation Center

Welcome to the comprehensive AnyProxy Documentation Center! This is your one-stop resource for everything you need to know about AnyProxy - from quick start guides to advanced deployment strategies.

## 🚀 Quick Navigation

### New to AnyProxy?
1. **[Project Overview](../README.md)** - Start here to understand what AnyProxy is
2. **[Quick Start Guide](#quick-start)** - Get up and running in 5 minutes
3. **[Basic Configuration](#basic-configuration)** - Essential configuration steps
4. **[First Proxy Connection](#first-proxy-connection)** - Test your setup

### Ready for Production?
1. **[Deployment Guide](DEPLOYMENT.md)** - Complete production deployment
2. **[Security Hardening](DEPLOYMENT.md#security-hardening)** - Secure your installation
3. **[Monitoring Setup](DEPLOYMENT.md#monitoring-and-logging)** - Monitor your services
4. **[Performance Tuning](DEPLOYMENT.md#performance-optimization)** - Optimize performance

### Need Help?
1. **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and solutions
2. **[HTTP Proxy Issues](HTTP_PROXY_TROUBLESHOOTING.md)** - HTTP-specific problems
3. **[FAQ](#frequently-asked-questions)** - Frequently asked questions
4. **[Community Support](#getting-help)** - Get help from the community

## 📚 Complete Documentation Index

### 🏗️ Architecture and Design
- **[System Architecture](ARCHITECTURE.md)** - Detailed system architecture and design principles
  - Core components and their interactions
  - Security mechanisms and protocols
  - Performance optimization strategies
  - Scalability considerations
- **[Project Requirements](../design/requirement.md)** - Original project requirements and specifications
- **[Architecture Diagram](../design/overall-arch.excalidraw)** - Visual system architecture

### 🛠️ Installation and Setup
- **[Quick Start Guide](#quick-start)** - Get started in minutes
- **[Installation Methods](#installation-methods)** - Multiple installation options
- **[Certificate Setup](#certificate-setup)** - TLS certificate configuration
- **[First Run](#first-run)** - Initial setup and verification

### ⚙️ Configuration
- **[Configuration Reference](API.md#configuration-api)** - Complete configuration options
- **[Basic Configuration](#basic-configuration)** - Essential settings
- **[Advanced Configuration](#advanced-configuration)** - Production-ready settings
- **[Environment Variables](#environment-variables)** - Environment-based configuration
- **[Configuration Examples](../configs/)** - Real-world configuration templates

### 🌐 Proxy Services
- **[Dual Proxy Support](DUAL_PROXY.md)** - HTTP and SOCKS5 proxy documentation
  - HTTP/HTTPS proxy configuration and usage
  - SOCKS5 proxy setup and authentication
  - Simultaneous proxy operation
  - Performance considerations
- **[HTTP Proxy Guide](#http-proxy-guide)** - Detailed HTTP proxy usage
- **[SOCKS5 Proxy Guide](#socks5-proxy-guide)** - Comprehensive SOCKS5 documentation
- **[Mobile Client Setup](#mobile-client-setup)** - Mobile device configuration

### 🔧 Development and API
- **[API Documentation](API.md)** - WebSocket API and message formats
  - WebSocket protocol specification
  - Message types and formats
  - Authentication mechanisms
  - Error handling
- **[Development Guide](#development-guide)** - Contributing to AnyProxy
- **[Testing Guide](#testing-guide)** - Running and writing tests
- **[Build System](#build-system)** - Build and compilation instructions

### 🚀 Deployment and Operations
- **[Production Deployment](DEPLOYMENT.md)** - Complete production setup guide
  - System requirements and preparation
  - Installation and configuration
  - Service management and monitoring
  - Security hardening
  - Performance optimization
- **[Service Management](#service-management)** - Managing AnyProxy services
- **[Monitoring and Logging](LOGGING.md)** - Comprehensive logging guide
- **[Backup and Recovery](#backup-and-recovery)** - Data protection strategies

### 🔍 Troubleshooting and Support
- **[General Troubleshooting](TROUBLESHOOTING.md)** - Common issues and solutions
  - Connection problems
  - Authentication failures
  - Performance issues
  - Configuration errors
- **[HTTP Proxy Troubleshooting](HTTP_PROXY_TROUBLESHOOTING.md)** - HTTP-specific issues
  - CONNECT tunnel failures
  - Authentication problems
  - Browser configuration
  - Performance optimization
- **[Diagnostic Tools](#diagnostic-tools)** - Tools for problem diagnosis
- **[Log Analysis](#log-analysis)** - Understanding and analyzing logs

## 🚀 Quick Start

### Prerequisites
- **Go 1.21+** for building from source
- **OpenSSL** for certificate generation
- **Linux/macOS/Windows** (Linux recommended for production)

### Installation
```bash
# Clone the repository
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# Generate certificates
make certs

# Build the project
make build
```

### Basic Configuration
Create or modify `configs/config.yaml`:
```yaml
# Basic dual proxy configuration
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
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway_user"
  auth_password: "gateway_password"

client:
  gateway_addr: "127.0.0.1:8443"
  gateway_tls_cert: "certs/server.crt"
  client_id: "my-client"
  auth_username: "gateway_user"
  auth_password: "gateway_password"
```

### First Run
```bash
# Terminal 1: Start the gateway
./bin/anyproxy-gateway --config configs/config.yaml

# Terminal 2: Start the client
./bin/anyproxy-client --config configs/config.yaml

# Terminal 3: Test the connection
curl -x http://http_user:http_password@127.0.0.1:8080 https://httpbin.org/ip
```

## 📖 Documentation by User Role

### 👨‍💼 System Administrators
**Recommended Reading Path:**
1. [Project Overview](../README.md) - Understand AnyProxy capabilities
2. [System Architecture](ARCHITECTURE.md) - Learn the system design
3. [Production Deployment](DEPLOYMENT.md) - Deploy in production
4. [Security Hardening](DEPLOYMENT.md#security-hardening) - Secure your installation
5. [Monitoring Setup](DEPLOYMENT.md#monitoring-and-logging) - Set up monitoring
6. [Troubleshooting Guide](TROUBLESHOOTING.md) - Master operational skills

**Key Resources:**
- [Service Management Scripts](../scripts/) - Automated service management
- [Configuration Templates](../configs/) - Production-ready configurations
- [Security Best Practices](DEPLOYMENT.md#security-hardening) - Security guidelines

### 👨‍💻 Developers
**Recommended Reading Path:**
1. [Project Overview](../README.md) - Understand the project
2. [System Architecture](ARCHITECTURE.md) - Learn the architecture
3. [API Documentation](API.md) - Understand the APIs
4. [Development Guide](#development-guide) - Set up development environment
5. [Testing Guide](#testing-guide) - Run and write tests

**Key Resources:**
- [WebSocket API](API.md) - Protocol specification
- [Configuration API](API.md#configuration-api) - Configuration options
- [Example Code](API.md#example-code) - Code examples

### 🏢 Enterprise Users
**Recommended Reading Path:**
1. [Project Requirements](../design/requirement.md) - Understand capabilities
2. [System Architecture](ARCHITECTURE.md) - Evaluate the solution
3. [Security Features](ARCHITECTURE.md#security-mechanisms) - Review security
4. [Production Deployment](DEPLOYMENT.md) - Plan deployment strategy
5. [Performance Benchmarks](../README.md#performance-benchmarks) - Evaluate performance

**Key Resources:**
- [High Availability Setup](DEPLOYMENT.md#high-availability-setup) - HA deployment
- [Performance Tuning](DEPLOYMENT.md#performance-optimization) - Optimization guide
- [Monitoring Integration](DEPLOYMENT.md#monitoring-integration) - Enterprise monitoring

### 📱 Mobile Users
**Recommended Reading Path:**
1. [Mobile Client Setup](#mobile-client-setup) - Configure mobile devices
2. [Clash for Android Guide](../configs/clash-android-usage.md) - Clash configuration
3. [Troubleshooting Mobile Issues](#mobile-troubleshooting) - Mobile-specific issues

**Key Resources:**
- [Clash Configuration Files](../configs/) - Ready-to-use configurations
- [Mobile Troubleshooting](#mobile-troubleshooting) - Common mobile issues

## 🔍 Documentation by Topic

### Security and Authentication
- [Security Architecture](ARCHITECTURE.md#security-mechanisms) - Security design
- [TLS Configuration](DEPLOYMENT.md#certificate-configuration) - Certificate setup
- [Authentication Methods](API.md#authentication) - Authentication options
- [Access Control](ARCHITECTURE.md#access-control) - Access control mechanisms
- [Security Hardening](DEPLOYMENT.md#security-hardening) - Security best practices

### Performance and Scalability
- [Performance Architecture](ARCHITECTURE.md#performance-optimization) - Performance design
- [Load Balancing](ARCHITECTURE.md#load-balancing) - Load balancing strategies
- [Performance Tuning](DEPLOYMENT.md#performance-optimization) - Optimization guide
- [Monitoring Performance](DEPLOYMENT.md#monitoring-and-logging) - Performance monitoring
- [Benchmarks](../README.md#performance-benchmarks) - Performance metrics

### Networking and Protocols
- [Protocol Support](DUAL_PROXY.md) - Supported protocols
- [HTTP Proxy Protocol](DUAL_PROXY.md#http-proxy-features) - HTTP proxy details
- [SOCKS5 Protocol](DUAL_PROXY.md#socks5-proxy-features) - SOCKS5 implementation
- [WebSocket Communication](API.md#websocket-connection) - WebSocket protocol
- [Network Troubleshooting](TROUBLESHOOTING.md#network-issues) - Network issues

### Configuration and Management
- [Configuration Reference](API.md#configuration-api) - All configuration options
- [Service Management](DEPLOYMENT.md#system-service-configuration) - Service management
- [Log Management](LOGGING.md) - Logging configuration
- [Certificate Management](DEPLOYMENT.md#certificate-configuration) - Certificate handling
- [Environment Configuration](#environment-variables) - Environment setup

## 🛠️ Installation Methods

### Method 1: Quick Start (Development)
```bash
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy
make certs && make build
```

### Method 2: Production Installation
```bash
# Automated installation
sudo ./scripts/setup_runtime_dirs.sh

# Service management
./scripts/service_manager.sh install
./scripts/service_manager.sh start
```

### Method 3: Manual Installation
See [Production Deployment Guide](DEPLOYMENT.md) for detailed manual installation steps.

## ⚙️ Configuration Guides

### Basic Configuration
Essential settings for getting started:
- [Proxy Configuration](DUAL_PROXY.md#configuration) - Basic proxy setup
- [Gateway Configuration](API.md#gateway-configuration) - Gateway settings
- [Client Configuration](API.md#client-configuration) - Client settings

### Advanced Configuration
Production-ready configurations:
- [Security Configuration](DEPLOYMENT.md#security-hardening) - Security settings
- [Performance Configuration](DEPLOYMENT.md#performance-optimization) - Performance tuning
- [Monitoring Configuration](LOGGING.md) - Logging and monitoring

### Environment Variables
Override configuration with environment variables:
```bash
export ANYPROXY_LOG_LEVEL=debug
export ANYPROXY_GATEWAY_ADDR=0.0.0.0:8443
export ANYPROXY_HTTP_AUTH_USER=myuser
export ANYPROXY_HTTP_AUTH_PASS=mypassword
```

## 🌐 Proxy Usage Guides

### HTTP Proxy Guide
Complete guide to using HTTP/HTTPS proxy:

#### Browser Configuration
1. **Chrome/Chromium**:
   - Settings → Advanced → System → Open proxy settings
   - Configure HTTP proxy: `127.0.0.1:8080`
   - Username: `http_user`, Password: `http_password`

2. **Firefox**:
   - Settings → Network Settings → Manual proxy configuration
   - HTTP Proxy: `127.0.0.1`, Port: `8080`
   - Check "Use this proxy server for all protocols"

#### Command Line Usage
```bash
# Using curl
curl -x http://http_user:http_password@127.0.0.1:8080 https://example.com

# Using wget
wget --proxy-user=http_user --proxy-password=http_password \
     --proxy=on -e http_proxy=127.0.0.1:8080 https://example.com

# Environment variables
export http_proxy=http://http_user:http_password@127.0.0.1:8080
export https_proxy=http://http_user:http_password@127.0.0.1:8080
```

### SOCKS5 Proxy Guide
Complete guide to using SOCKS5 proxy:

#### Application Configuration
Most applications support SOCKS5 proxy configuration through their network settings.

#### Command Line Usage
```bash
# Using curl
curl --socks5 socks_user:socks_password@127.0.0.1:1080 https://example.com

# Using ssh
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" user@target-server

# Environment variables
export ALL_PROXY=socks5://socks_user:socks_password@127.0.0.1:1080
```

### Mobile Client Setup

#### Clash for Android
1. **Download Configuration**:
   - Use [Simple Configuration](../configs/clash-android-simple.yaml) for basic setup
   - Use [Advanced Configuration](../configs/clash-android.yaml) for full features

2. **Modify Server Address**:
   ```yaml
   proxies:
     - name: "AnyProxy-HTTP"
       server: YOUR_SERVER_IP  # Change this
       port: 8080
   ```

3. **Import to Clash**:
   - Open Clash for Android
   - Profiles → Add → Import from file
   - Select the configuration file

For detailed instructions, see [Clash Configuration Guide](../configs/clash-android-usage.md).

## 🔧 Development and Testing

### Development Guide
Set up your development environment:

```bash
# Clone and setup
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# Install dependencies
go mod download

# Run tests
make test

# Build for development
make build

# Run with hot reload (if available)
make dev
```

### Testing Guide
Comprehensive testing instructions:

```bash
# Run all tests
go test ./...

# Run with coverage
make test-coverage

# Run specific tests
go test ./pkg/proxy/ -v

# Run benchmarks
go test -bench=. ./pkg/proxy/

# Integration tests
make test-integration
```

### Build System
Understanding the build system:

```bash
# Available make targets
make help

# Build for current platform
make build

# Build for all platforms
make build-all

# Clean build artifacts
make clean

# Generate certificates
make certs

# Run services
make run-gateway
make run-client
```

## 🔍 Troubleshooting Resources

### Diagnostic Tools
Built-in diagnostic tools:

```bash
# Service status
./scripts/service_manager.sh status

# Connection testing
./scripts/test_connection.sh

# Log analysis
./scripts/analyze_logs.sh

# Performance monitoring
./scripts/monitor_performance.sh
```

### Log Analysis
Understanding AnyProxy logs:

1. **Log Levels**: `debug`, `info`, `warn`, `error`
2. **Log Formats**: `text` (human-readable) or `json` (machine-readable)
3. **Log Locations**: 
   - Development: stdout/stderr
   - Production: `/var/log/anyproxy/`

Common log patterns:
```bash
# Connection issues
grep "connection" /var/log/anyproxy/gateway.log

# Authentication failures
grep "auth" /var/log/anyproxy/gateway.log

# Performance issues
grep "timeout\|slow" /var/log/anyproxy/*.log
```

### Common Issues and Solutions

#### Connection Problems
1. **"Connection refused"**
   - Check if services are running
   - Verify firewall settings
   - Confirm port availability

2. **"TLS handshake failed"**
   - Verify certificate validity
   - Check certificate paths
   - Ensure time synchronization

#### Authentication Issues
1. **"Authentication failed"**
   - Verify username/password
   - Check configuration files
   - Review authentication logs

#### Performance Issues
1. **Slow connections**
   - Check system resources
   - Review network connectivity
   - Optimize configuration

For detailed troubleshooting, see:
- [General Troubleshooting](TROUBLESHOOTING.md)
- [HTTP Proxy Issues](HTTP_PROXY_TROUBLESHOOTING.md)

## 📊 Monitoring and Maintenance

### Service Management
Using the service manager:

```bash
# Check status
./scripts/service_manager.sh status

# Start/stop services
./scripts/service_manager.sh start
./scripts/service_manager.sh stop gateway

# View logs
./scripts/service_manager.sh logs
./scripts/service_manager.sh logs client

# Restart services
./scripts/service_manager.sh restart
```

### Health Monitoring
Monitor service health:

```bash
# System health
systemctl status anyproxy-gateway anyproxy-client

# Resource usage
top -p $(pgrep anyproxy)

# Network connections
netstat -tlnp | grep -E ':(8080|1080|8443)'

# Log monitoring
journalctl -u anyproxy-gateway -f
```

### Backup and Recovery
Protect your configuration and data:

```bash
# Backup configuration
cp -r /etc/anyproxy /backup/anyproxy-$(date +%Y%m%d)

# Backup certificates
cp -r /etc/anyproxy/certs /backup/certs-$(date +%Y%m%d)

# Restore configuration
sudo cp -r /backup/anyproxy-20240115/* /etc/anyproxy/
sudo systemctl restart anyproxy-gateway anyproxy-client
```

## 🆘 Getting Help

### Self-Help Resources
1. **Documentation**: Start with this documentation center
2. **Troubleshooting Guides**: Check specific troubleshooting guides
3. **Configuration Examples**: Review example configurations
4. **Log Analysis**: Analyze service logs for clues

### Community Support
1. **GitHub Issues**: [Report bugs and request features](https://github.com/buhuipao/anyproxy/issues)
2. **GitHub Discussions**: [Join community discussions](https://github.com/buhuipao/anyproxy/discussions)
3. **Documentation**: [Contribute to documentation](https://github.com/buhuipao/anyproxy/blob/main/CONTRIBUTING.md)

### Professional Support
For enterprise users requiring professional support:
- Priority issue resolution
- Custom feature development
- Professional consulting services
- Training and workshops

Contact: [support@anyproxy.example.com](mailto:support@anyproxy.example.com)

## 📝 Contributing to Documentation

We welcome contributions to improve this documentation:

### How to Contribute
1. **Report Issues**: Found an error or unclear section? [Create an issue](https://github.com/buhuipao/anyproxy/issues)
2. **Suggest Improvements**: Have ideas for better documentation? [Start a discussion](https://github.com/buhuipao/anyproxy/discussions)
3. **Submit Changes**: Ready to contribute? [Submit a pull request](https://github.com/buhuipao/anyproxy/pulls)

### Documentation Standards
- **Clear and Concise**: Write clearly and concisely
- **Examples**: Include practical examples
- **Cross-References**: Link to related documentation
- **Testing**: Test all examples and procedures
- **Accessibility**: Ensure documentation is accessible to all users

## 📋 Frequently Asked Questions

### General Questions

**Q: What is AnyProxy?**
A: AnyProxy is a secure, high-performance proxy system that allows developers to safely expose local services to public users through encrypted WebSocket + TLS tunnels.

**Q: What protocols does AnyProxy support?**
A: AnyProxy supports HTTP/HTTPS and SOCKS5 proxy protocols, with WebSocket + TLS for client-gateway communication.

**Q: Is AnyProxy secure?**
A: Yes, AnyProxy uses TLS 1.2+ encryption, supports multiple authentication methods, and includes comprehensive access controls.

### Technical Questions

**Q: Can I run both HTTP and SOCKS5 proxies simultaneously?**
A: Yes, AnyProxy supports dual proxy operation with independent configuration for each proxy type.

**Q: How many concurrent connections can AnyProxy handle?**
A: AnyProxy can handle thousands of concurrent connections, with actual limits depending on system resources and configuration.

**Q: Does AnyProxy support IPv6?**
A: Yes, AnyProxy supports both IPv4 and IPv6 addresses.

### Configuration Questions

**Q: How do I configure custom certificates?**
A: See the [Certificate Configuration Guide](DEPLOYMENT.md#certificate-configuration) for detailed instructions.

**Q: Can I use environment variables for configuration?**
A: Yes, many configuration options can be overridden with environment variables. See [Environment Variables](#environment-variables).

**Q: How do I enable debug logging?**
A: Set `log.level: "debug"` in your configuration file or use the environment variable `ANYPROXY_LOG_LEVEL=debug`.

For more questions, check our [GitHub Discussions](https://github.com/buhuipao/anyproxy/discussions) or [create an issue](https://github.com/buhuipao/anyproxy/issues).

## 🔗 Related Resources

### External Documentation
- [WebSocket Protocol (RFC 6455)](https://tools.ietf.org/html/rfc6455)
- [SOCKS5 Protocol (RFC 1928)](https://tools.ietf.org/html/rfc1928)
- [HTTP/1.1 Specification (RFC 7230)](https://tools.ietf.org/html/rfc7230)
- [TLS 1.3 Specification (RFC 8446)](https://tools.ietf.org/html/rfc8446)

### Tools and Utilities
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [Go Documentation](https://golang.org/doc/)
- [systemd Documentation](https://systemd.io/)
- [YAML Specification](https://yaml.org/spec/)

### Related Projects
- [Clash](https://github.com/Dreamacro/clash) - A rule-based tunnel in Go
- [V2Ray](https://github.com/v2fly/v2ray-core) - A platform for building proxies
- [Shadowsocks](https://github.com/shadowsocks) - A secure socks5 proxy

---

## 📄 Documentation Changelog

### Latest Updates
- **2025-01-XX**: Complete documentation overhaul with English translation
- **2025-01-XX**: Added comprehensive troubleshooting guides
- **2025-01-XX**: Enhanced configuration documentation
- **2025-01-XX**: Added mobile client setup guides
- **2025-01-XX**: Improved navigation and cross-references

### Planned Updates
- [ ] Video tutorials and walkthroughs
- [ ] Interactive configuration generator
- [ ] Multi-language documentation support
- [ ] Advanced deployment scenarios
- [ ] Performance optimization cookbook

---

💡 **Tip**: Bookmark this documentation center for easy reference. If you're new to AnyProxy, start with the [Project Overview](../README.md) and follow the [Quick Start Guide](#quick-start). 