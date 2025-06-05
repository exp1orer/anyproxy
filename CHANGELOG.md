# Changelog

All notable changes to AnyProxy will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Web-based management interface
- Prometheus metrics integration
- Kubernetes deployment manifests
- Configuration hot reload
- Advanced load balancing algorithms

## [v2.0.0] - 2025-01-XX

### 🚀 Major Release - AnyProxy v2

AnyProxy v2 is a complete rewrite with modern architecture, multiple transport protocols, and enhanced security.

#### ✨ New Features

**Multi-Transport Support**
- **WebSocket**: Firewall-friendly transport with HTTP/HTTPS compatibility
- **gRPC**: High-performance transport with HTTP/2 multiplexing
- **QUIC**: Ultra-low latency transport for mobile and unreliable networks

**Enhanced Architecture** 
- Group-based routing for multi-environment support
- Port forwarding with direct service access
- Modular transport layer design
- Improved security with per-service access control

**Deployment Improvements**
- Docker containers with multi-architecture support
- Simplified configuration with YAML format
- Better separation of Gateway (public) and Client (private) deployments
- Built-in certificate generation

#### ⚙️ Configuration Changes

**Breaking Changes from v1**
- Configuration format changed from mixed to pure YAML
- Transport selection required (websocket/grpc/quic)
- Separate binary names: `anyproxy-gateway-v2` and `anyproxy-client-v2`

**New Configuration Options**
```yaml
transport:
  type: "websocket"  # or "grpc", "quic"

client:
  group_id: "production"  # For group-based routing
  open_ports: []          # For port forwarding
  allowed_hosts: []       # Explicit allow list
  forbidden_hosts: []     # Security blacklist
```

#### 🔐 Security Enhancements

- **Transport-level TLS**: All protocols use TLS encryption
- **Host-based Access Control**: Allow/deny lists for target services
- **Group Isolation**: Traffic routing based on client groups
- **Certificate Management**: Automated certificate handling

#### 🐳 Docker Support

- Multi-architecture Docker images (linux/amd64, linux/arm64)
- Optimized Alpine-based runtime images
- Health check integration
- Non-root user execution

#### 📊 Performance Improvements

- **QUIC Transport**: 0-RTT handshake for faster connections
- **gRPC Transport**: HTTP/2 multiplexing for better throughput
- **Connection Pooling**: Efficient resource utilization
- **Memory Optimization**: Reduced memory footprint

### 🔧 Technical Details

#### Build System
- Go 1.21+ requirement
- Cross-platform builds (Linux, macOS, Windows)
- Automated CI/CD with GitHub Actions
- Docker multi-arch builds

#### Dependencies
- Updated to latest stable versions
- Removed legacy dependencies
- Added QUIC and gRPC support libraries

### 🐛 Bug Fixes

- Fixed connection leaks in long-running sessions
- Improved error handling for network failures
- Resolved race conditions in concurrent connections
- Enhanced logging for better debugging

### 📚 Documentation

- Completely rewritten README with practical examples
- Architecture diagrams for visual understanding
- Docker deployment guides
- Configuration reference

---

## [v1.0.0] - 2025-05-20

### 🚀 Initial Release

First stable release of AnyProxy with WebSocket-based tunneling.

#### Core Features
- **HTTP/HTTPS Proxy**: Complete HTTP proxy implementation
- **SOCKS5 Proxy**: RFC 1928 compliant SOCKS5 support
- **WebSocket Tunneling**: Secure client-gateway communication
- **TLS Security**: End-to-end encryption
- **Access Control**: Host-based filtering

#### Architecture
- Gateway-Client architecture
- WebSocket-only transport
- Single binary design
- YAML configuration

#### Platform Support
- Linux (primary platform)
- macOS (development)
- Windows (basic support)

---

## Version Support

### Current Versions
- **v2.x**: Active development and support (Recommended)
- **v1.x**: Maintenance mode (Security fixes only)

### Upgrade Path
- **v1.x → v2.x**: Configuration migration required
- **Docker**: Use `buhuipao/anyproxy:latest` for v2
- **Binaries**: Use `anyproxy-*-v2` binaries

### System Requirements
- **Go**: 1.21+ (for building from source)
- **OS**: Linux (primary), macOS, Windows
- **Memory**: 50MB+ per instance
- **Network**: Internet connectivity for tunneling

## Contributing

We welcome contributions! Please:
1. Read our [Contributing Guidelines](CONTRIBUTING.md)
2. Check existing [issues](https://github.com/buhuipao/anyproxy/issues)
3. Follow our code style and testing requirements
4. Submit pull requests with clear descriptions

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 **Documentation**: [README.md](README.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/buhuipao/anyproxy/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/buhuipao/anyproxy/discussions)
- 📧 **Contact**: Create an issue for support requests 