# AnyProxy Configuration Examples

This directory contains simplified, practical configuration examples for common AnyProxy use cases.

## Available Examples

### 🔧 `basic-config.yaml`
**Basic HTTP/SOCKS5 proxy setup with WebSocket transport**
- Simple gateway and client configuration
- Both HTTP and SOCKS5 proxy support
- Perfect for getting started

### 🔐 `ssh-access.yaml`
**Secure SSH access through SOCKS5 proxy**
- Expose SSH server securely to the internet
- SOCKS5 proxy configuration for SSH connections
- Includes SSH client connection examples

### 🤖 `ai-services.yaml`
**AI/ML services exposure with gRPC transport**
- Optimized for AI model APIs (OpenAI, Ollama, Gradio)
- Uses gRPC transport for better performance
- Multiple AI service port support

### 🏢 `group-routing.yaml`
**Group-based routing for multi-environment setup**
- Route traffic to different environments (prod/staging/dev)
- Username-based group selection
- Multiple client configurations

### 🚪 `port-forwarding.yaml`
**Direct port forwarding configuration**
- Direct port mapping from gateway to local services
- No proxy authentication needed
- SSH, web, and database forwarding examples

## Quick Start

1. **Choose an example** that matches your use case
2. **Copy the configuration** to your configs directory
3. **Update variables**:
   - Replace `YOUR_GATEWAY_IP` with your public gateway IP
   - Update passwords and usernames
   - Adjust allowed/forbidden hosts as needed
4. **Generate certificates**:
   ```bash
   make certs
   ```
5. **Deploy**:
   - Gateway on public server
   - Client on private network

## Usage Patterns

| Use Case | Example File | Transport | Best For |
|----------|-------------|-----------|----------|
| General proxy | `basic-config.yaml` | WebSocket | Getting started |
| SSH access | `ssh-access.yaml` | WebSocket | Remote administration |
| AI services | `ai-services.yaml` | gRPC | High performance APIs |
| Multi-env | `group-routing.yaml` | WebSocket | Development teams |
| Direct access | `port-forwarding.yaml` | WebSocket | Simple port mapping |

## Transport Selection

- **WebSocket**: Most compatible, works through firewalls
- **gRPC**: Best performance for high-throughput scenarios  
- **QUIC**: Ultra-low latency, good for mobile/unstable networks

Each configuration uses only ONE transport type per Gateway/Client pair.

## Security Notes

- Change all default passwords
- Use strong authentication credentials
- Restrict `allowed_hosts` to only needed services
- Always include cloud metadata in `forbidden_hosts`
- Consider using Let's Encrypt certificates for production

For more detailed documentation, see the main [README.md](../README.md). 