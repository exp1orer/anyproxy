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

## [v1.0.0] - 2025-06-11

### 🚀 Initial Release - AnyProxy

A secure tunneling solution with modern architecture, multiple transport protocols, and enhanced security through significant code structure optimizations.

#### ✨ Core Features

**Multi-Transport Support**
- **WebSocket**: Firewall-friendly transport with HTTP/HTTPS compatibility
- **gRPC**: High-performance transport with HTTP/2 multiplexing
- **QUIC**: Ultra-low latency transport for mobile and unreliable networks

**Modern Architecture** 
- Group-based routing for multi-environment support
- Port forwarding with direct service access
- Modular transport layer design
- Comprehensive security with per-service access control

**Production-Ready Deployment**
- Docker containers with multi-architecture support
- Clean YAML configuration format
- Optimized Gateway (public) and Client (private) separation
- Automated certificate generation

#### ⚙️ Configuration

**Configuration Features**
- Pure YAML configuration format for clarity
- Transport selection (websocket/grpc/quic)
- Clean binary naming: `anyproxy-gateway` and `anyproxy-client`

**Configuration Options**
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

### 🔧 Technical Implementation

#### Build System
- Go 1.23+ requirement
- Cross-platform builds (Linux, macOS, Windows)
- Automated CI/CD with GitHub Actions
- Docker multi-arch builds
- Clean binary naming: `anyproxy-gateway` and `anyproxy-client`

#### Code Structure
- Modern Go module organization
- Clean package structure under `pkg/`
- Optimized import paths
- Well-structured dependency management
- Comprehensive test coverage

### 🛡️ Reliability Features

- Robust connection management for long-running sessions
- Comprehensive error handling for network failures
- Thread-safe concurrent connection handling
- Enhanced logging system for debugging and monitoring
- Clean import paths and module organization
- Optimized protobuf generation and management

### 📚 Documentation

- Comprehensive README with practical examples
- Clear architecture documentation
- Complete Docker deployment guides
- Detailed configuration reference for all transport types
- Consistent naming conventions throughout

---

## Version Support

### Current Version
- **v1.x**: Active development and support (Current stable)

### Usage
- **Docker**: Use `buhuipao/anyproxy:latest`
- **Binaries**: Use `anyproxy-gateway` and `anyproxy-client`
- **Source**: Build from source with Go 1.23+

### System Requirements
- **Go**: 1.23+ (for building from source)
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