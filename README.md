# AnyProxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![Build Status](https://img.shields.io/badge/Build-Passing-green.svg)]()
[![Release](https://img.shields.io/badge/Release-v1.0.0-green.svg)](https://github.com/buhuipao/anyproxy/releases)

AnyProxy is a secure proxy system based on WebSocket + TLS that supports HTTP/HTTPS and SOCKS5 proxy protocols, helping you safely expose local services to external users.

## ✨ Key Features

- 🔐 **End-to-End TLS Encryption**: All communications use TLS 1.2+ encryption
- 🚀 **Dual Protocol Support**: Supports both HTTP and SOCKS5 proxy simultaneously
- 🌐 **Multi-Client Support**: Supports multiple client connections with automatic load balancing
- 🛡️ **Access Control**: Supports host blacklist and whitelist
- 📱 **Cross-Platform**: Supports Linux, macOS, Windows
- 🐳 **Docker Support**: Provides official Docker images

## 🚀 Quick Start

### Method 1: Docker Quick Deployment (Recommended)

```bash
# 1. Pull official image
docker pull buhuipao/anyproxy:latest

# 2. Create working directory
mkdir anyproxy-test && cd anyproxy-test
mkdir -p configs

# 3. Create configuration file
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
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway"
  auth_password: "gateway123"

client:
  gateway_addr: "127.0.0.1:8443"
  gateway_tls_cert: "certs/server.crt"
  client_id: "test-client"
  auth_username: "gateway"
  auth_password: "gateway123"
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
EOF

# 4. Start gateway
docker run -d --name anyproxy-gateway \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/config.yaml

# 5. Start client
sleep 2
docker run -d --name anyproxy-client \
  --network container:anyproxy-gateway \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/config.yaml

# 6. Test connection
curl -x http://test:test123@127.0.0.1:8080 https://httpbin.org/ip
```

### Method 2: Build from Source

```bash
# 1. Clone repository
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# 2. Generate certificates
make certs

# 3. Build project
make build

# 4. Start gateway (Terminal 1)
make run-gateway

# 5. Start client (Terminal 2)
make run-client
```

## ⚙️ Basic Configuration

### Configuration File (`configs/config.yaml`)

```yaml
# Log configuration
log:
  level: "info"           # Log level: debug, info, warn, error
  format: "text"          # Log format: text, json
  output: "stdout"        # Output: stdout, stderr, file

# Proxy configuration
proxy:
  # HTTP proxy
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_password"
  
  # SOCKS5 proxy
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
  auth_username: "gateway_user"
  auth_password: "gateway_password"
  
  # Forbidden hosts list (highest priority, will be directly rejected)
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "192.168.0.0/16"
  
  # Allowed hosts list (optional)
  # Note: If allowed_hosts is empty, all hosts are allowed (except those in forbidden_hosts)
  # If allowed_hosts is not empty, only hosts in the list are allowed (but still overridden by forbidden_hosts)
  allowed_hosts:
    - "example.com"
    - "*.google.com"
```

## 🔧 Basic Usage

### HTTP Proxy

```bash
# Basic usage
curl -x http://http_user:http_password@127.0.0.1:8080 https://example.com

# Set environment variables
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

### SOCKS5 Proxy

```bash
# Basic usage
curl --socks5 socks_user:socks_password@127.0.0.1:1080 https://example.com

# Set environment variables
export ALL_PROXY=socks5://socks_user:socks_password@127.0.0.1:1080
curl https://example.com

# SSH tunneling
ssh -o ProxyCommand="nc -X 5 -x 127.0.0.1:1080 %h %p" user@target-server
```

## 🐳 Basic Docker Deployment

### Separate Gateway and Client Deployment

#### Gateway Deployment (Public Server)

```bash
# Create configuration file
mkdir -p configs
cat > configs/gateway-config.yaml << EOF
log:
  level: "info"

proxy:
  http:
    listen_addr: ":8080"
    auth_username: "proxy_user"
    auth_password: "proxy_password"
  socks5:
    listen_addr: ":1080"
    auth_username: "proxy_user"
    auth_password: "proxy_password"

gateway:
  listen_addr: ":8443"
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway_user"
  auth_password: "gateway_password"
EOF

# Start gateway
docker run -d \
  --name anyproxy-gateway \
  --restart unless-stopped \
  -p 8080:8080 \
  -p 1080:1080 \
  -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-gateway --config configs/gateway-config.yaml
```

#### Client Deployment (Internal Server)

```bash
# Create configuration file
mkdir -p configs
cat > configs/client-config.yaml << EOF
log:
  level: "info"

client:
  gateway_addr: "YOUR_GATEWAY_SERVER_IP:8443"  # Replace with actual gateway IP
  gateway_tls_cert: "certs/server.crt"
  client_id: "client-001"
  replicas: 1
  auth_username: "gateway_user"
  auth_password: "gateway_password"
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "192.168.0.0/16"
EOF

# Start client
docker run -d \
  --name anyproxy-client \
  --restart unless-stopped \
  -v $(pwd)/configs:/app/configs:ro \
  buhuipao/anyproxy:latest ./anyproxy-client --config configs/client-config.yaml
```

## 🔐 Certificate Configuration

### Using Built-in Certificates (Testing)

Docker images already include built-in certificates for testing.

### Generate Self-Signed Certificates

```bash
# Use project script
make certs

# Or generate manually
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName = DNS:localhost,DNS:anyproxy,IP:127.0.0.1"
```

### Using Let's Encrypt Certificates

```bash
# Install certbot
sudo apt install -y certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem certs/server.key
```

## 📱 Client Configuration

### Windows

```
Proxy Settings -> Manual Proxy Setup
HTTP Proxy: 127.0.0.1:8080
SOCKS Proxy: 127.0.0.1:1080
Username: your_username
Password: your_password
```

### macOS

```bash
# System proxy settings
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setsocksfirewallproxy "Wi-Fi" 127.0.0.1 1080
```

### Android (Clash)

```yaml
proxies:
  - name: "AnyProxy-HTTP"
    type: http
    server: 127.0.0.1
    port: 8080
    username: "your_username"
    password: "your_password"
    
  - name: "AnyProxy-SOCKS5"
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: "your_username"
    password: "your_password"
```

## 🔍 Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check service status
   docker logs anyproxy-gateway
   docker logs anyproxy-client
   
   # Check port usage
   netstat -tlnp | grep -E ':(8080|1080|8443)'
   ```

2. **Authentication Failed**
   ```bash
   # Check configuration file
   grep -A5 auth configs/config.yaml
   
   # View authentication error logs
   docker logs anyproxy-gateway | grep auth
   ```

3. **Certificate Issues**
   ```bash
   # Test TLS connection
   openssl s_client -connect YOUR_GATEWAY_IP:8443
   
   # Check certificate validity
   openssl x509 -in certs/server.crt -text -noout
   ```

### View Logs

```bash
# View real-time logs
docker logs -f anyproxy-gateway
docker logs -f anyproxy-client

# View error logs
docker logs anyproxy-gateway 2>&1 | grep ERROR
```

## 📊 Performance Monitoring

```bash
# Monitor resource usage
docker stats anyproxy-gateway anyproxy-client

# Check connection count
netstat -an | grep :8080 | wc -l
netstat -an | grep :1080 | wc -l
```

## 🛡️ Security Recommendations

1. **Use Strong Passwords**: Configure strong passwords for all authentication
2. **Limit Access**: Configure `forbidden_hosts` to restrict client access
3. **Regular Updates**: Keep software versions up to date
4. **Certificate Management**: Use valid TLS certificates and update regularly
5. **Network Isolation**: Deploy gateway in dedicated network

---

## 🏗️ Advanced Features - System Architecture

### Multi-Client Group Routing Architecture

```
                                    ┌─────────────────────────────────────────────────────────────┐
                                    │                    Proxy Gateway                            │
                                    │  ┌─────────────────┐    ┌─────────────────┐                 │
┌─────────────────┐                 │  │   HTTP Proxy    │    │  SOCKS5 Proxy   │                 │
│   Public Users  │────────────────▶│  │   Port: 8080    │    │   Port: 1080    │                 │
│   (Internet)    │                 │  │ user.group:pass │    │ user.group:pass │                 │
│                 │                 │  └─────────────────┘    └─────────────────┘                 │
│ • HTTP Requests │                 │           │                       │                         │
│ • SOCKS5 Reqs   │                 │           └───────────┬───────────┘                         │
│ • Group-based   │                 │                       │                                     │
│   Authentication│                 │              ┌─────────────────┐                            │
└─────────────────┘                 │              │  Group Router   │                            │
                                    │              │                 │                            │
                                    │              │ • Extract .group│                            │
                                    │              │ • Select clients│                            │
                                    │              │ • Load balancing│                            │
                                    │              └─────────────────┘                            │
                                    │                       │                                     │
                                    │              ┌─────────────────┐                            │
                                    │              │ WebSocket + TLS │                            │
                                    │              │   Port: 8443    │                            │
                                    │              └─────────────────┘                            │
                                    └─────────────────────┼───────────────────────────────────────┘
                                                          │
                    ┌─────────────────────────────────────┼─────────────────────────────────────┐
                    │                                     │                                     │
                    ▼                                     ▼                                     ▼
        ┌─────────────────────┐              ┌─────────────────────┐              ┌─────────────────────┐
        │   Client Group A    │              │   Client Group B    │              │   Default Group     │
        │   (Production)      │              │   (Testing)         │              │   (Development)     │
        │                     │              │                     │              │                     │
        │ ┌─────────────────┐ │              │ ┌─────────────────┐ │              │ ┌─────────────────┐ │
        │ │ Client A1       │ │              │ │ Client B1       │ │              │ │ Client C1       │ │
        │ │ ID: prod-01     │ │              │ │ ID: test-01     │ │              │ │ ID: dev-01      │ │
        │ │ Group: prod     │ │              │ │ Group: testing  │ │              │ │ Group: ""       │ │
        │ └─────────────────┘ │              │ └─────────────────┘ │              │ └─────────────────┘ │
        │ ┌─────────────────┐ │              │ ┌─────────────────┐ │              │ ┌─────────────────┐ │
        │ │ Client A2       │ │              │ │ Client B2       │ │              │ │ Client C2       │ │
        │ │ ID: prod-02     │ │              │ │ ID: test-02     │ │              │ │ ID: dev-02      │ │
        │ │ Group: prod     │ │              │ │ Group: testing  │ │              │ │ Group: ""       │ │
        │ └─────────────────┘ │              │ └─────────────────┘ │              │ └─────────────────┘ │
        └─────────────────────┘              └─────────────────────┘              └─────────────────────┘
                    │                                     │                                     │
                    ▼                                     ▼                                     ▼
        ┌─────────────────────┐              ┌─────────────────────┐              ┌─────────────────────┐
        │  Production Env     │              │   Testing Env       │              │  Development Env    │
        │                     │              │                     │              │                     │
        │ • Database Servers  │              │ • Test Databases    │              │ • Local Services    │
        │ • API Services      │              │ • Staging APIs      │              │ • Debug Tools       │
        │ • Internal Tools    │              │ • QA Tools          │              │ • Mock Services     │
        └─────────────────────┘              └─────────────────────┘              └─────────────────────┘
```

### Group Authentication Flow

```
User Request: curl -x http://user.production:pass@gateway:8080 https://api.example.com
                                    │
                                    ▼
                        ┌─────────────────────┐
                        │   Parse Username    │
                        │                     │
                        │ user.production     │
                        │      ↓              │
                        │ Base: user          │
                        │ Group: production   │
                        └─────────────────────┘
                                    │
                                    ▼
                        ┌─────────────────────┐
                        │   Authenticate      │
                        │                     │
                        │ Validate: user:pass │
                        │ Against config      │
                        └─────────────────────┘
                                    │
                                    ▼
                        ┌─────────────────────┐
                        │   Route to Group    │
                        │                     │
                        │ Select client from  │
                        │ "production" group  │
                        │ Fallback: default   │
                        └─────────────────────┘
                                    │
                                    ▼
                        ┌─────────────────────┐
                        │   Forward Request   │
                        │                     │
                        │ Via WebSocket+TLS   │
                        │ To selected client  │
                        └─────────────────────┘
```

## 🌐 Advanced Features - Group Routing

### Group Routing Examples

AnyProxy supports group routing, allowing you to route requests to specific client groups based on the username format `username.group-id`.

#### Multi-Environment Deployment

```bash
# Route to production environment clients
curl -x http://user.production:password@127.0.0.1:8080 https://api.example.com

# Route to testing environment clients  
curl -x http://user.testing:password@127.0.0.1:8080 https://api.example.com

# Route to development environment clients
curl -x http://user.development:password@127.0.0.1:8080 https://api.example.com

# Use default group (backward compatibility)
curl -x http://user:password@127.0.0.1:8080 https://api.example.com
```

#### Geographic Distribution

```bash
# Route through US East clients
curl -x http://user.us-east:password@127.0.0.1:8080 https://api.example.com

# Route through EU West clients
curl -x http://user.eu-west:password@127.0.0.1:8080 https://api.example.com

# Route through Asia Pacific clients
curl -x http://user.asia-pacific:password@127.0.0.1:8080 https://api.example.com
```

### Group Client Configuration

```yaml
# Production environment client configuration
client:
  client_id: "prod-client-001"
  group_id: "production"  # This client belongs to the production group
  gateway_addr: "gateway.example.com:8443"
  # ... other configurations

# Testing environment client configuration  
client:
  client_id: "test-client-001"
  group_id: "testing"     # This client belongs to the testing group
  gateway_addr: "gateway.example.com:8443"
  # ... other configurations

# Default group client (not specified group_id)
client:
  client_id: "default-client-001"
  # group_id: ""          # Default group (can be omitted)
  gateway_addr: "gateway.example.com:8443"
  # ... other configurations
```

## 🏢 Enterprise Features

### Multi-Tenant SaaS Platform

```bash
# Tenant A routes to dedicated client group
curl -x http://tenant-a.prod:secret@proxy:8080 https://api.saas.com/tenant-a/data

# Tenant B routes to different client groups  
curl -x http://tenant-b.prod:secret@proxy:8080 https://api.saas.com/tenant-b/data

# Development tenant routes to development environment
curl -x http://tenant-dev.dev:secret@proxy:8080 https://api.saas.com/dev/data
```

### Microservice Architecture

```bash
# Route to API gateway client
curl -x http://api.prod:pass@proxy:8080 https://api.internal.com

# Route to database proxy client
curl -x http://db.prod:pass@proxy:8080 https://db.internal.com

# Route to cache proxy client  
curl -x http://cache.prod:pass@proxy:8080 https://cache.internal.com
```

### Geographic Load Distribution

```bash
# Route to nearest region based on group
curl -x http://user.us-west:pass@proxy:8080 https://api.example.com    # Route to US West client
curl -x http://user.eu-central:pass@proxy:8080 https://api.example.com # Route to EU Central client
curl -x http://user.asia-east:pass@proxy:8080 https://api.example.com  # Route to Asia East client
```

## 🐳 Advanced Docker Configuration

### Multi-Group Docker Compose Configuration

```yaml
# docker-compose.yml
version: '3.8'

services:
  gateway:
    image: buhuipao/anyproxy:latest
    command: ./anyproxy-gateway --config configs/gateway-config.yaml
    ports:
      - "8080:8080"
      - "1080:1080"
      - "8443:8443"
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    restart: unless-stopped

  # Production clients
  prod-client-1:
    image: buhuipao/anyproxy:latest
    command: ./anyproxy-client --config configs/production-client.yaml
    environment:
      - CLIENT_ID=prod-client-001
      - GROUP_ID=production
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    depends_on:
      - gateway
    restart: unless-stopped

  prod-client-2:
    image: buhuipao/anyproxy:latest
    command: ./anyproxy-client --config configs/production-client.yaml
    environment:
      - CLIENT_ID=prod-client-002
      - GROUP_ID=production
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    depends_on:
      - gateway
    restart: unless-stopped

  # Testing clients
  test-client-1:
    image: buhuipao/anyproxy:latest
    command: ./anyproxy-client --config configs/testing-client.yaml
    environment:
      - CLIENT_ID=test-client-001
      - GROUP_ID=testing
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    depends_on:
      - gateway
    restart: unless-stopped

  # Development clients
  dev-client-1:
    image: buhuipao/anyproxy:latest
    command: ./anyproxy-client --config configs/development-client.yaml
    environment:
      - CLIENT_ID=dev-client-001
      - GROUP_ID=development
    volumes:
      - ./configs:/app/configs:ro
      - ./logs:/app/logs
    depends_on:
      - gateway
    restart: unless-stopped
```

### Docker Environment Variable Configuration

```bash
# Gateway environment variables
export LOG_LEVEL=info
export HTTP_AUTH_USER=http_user
export HTTP_AUTH_PASS=http_password
export SOCKS5_AUTH_USER=socks_user
export SOCKS5_AUTH_PASS=socks_password
export GATEWAY_AUTH_USER=gateway_user
export GATEWAY_AUTH_PASS=gateway_password

# Client environment variables
export GATEWAY_ADDR=gateway.example.com:8443
export CLIENT_ID=prod-client-001
export GROUP_ID=production
export CLIENT_REPLICAS=3
export GATEWAY_AUTH_USER=gateway_user
export GATEWAY_AUTH_PASS=gateway_password
```

### Docker Production Security Best Practices

```bash
# Use specific image tag instead of 'latest'
docker pull buhuipao/anyproxy:v1.0.0

# Set resource limits at runtime
docker run -d \
  --name anyproxy-gateway \
  --memory="256m" \
  --cpus="1.0" \
  --ulimit nofile=65536:65536 \
  -p 8080:8080 -p 1080:1080 -p 8443:8443 \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  buhuipao/anyproxy:v1.0.0

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

## 💻 Advanced Programming Use Case

### Go HTTP Client Group Routing

```go
package main

import (
    "fmt"
    "net/http"
    "net/url"
)

func main() {
    // Configure HTTP proxy with group routing
    proxyURL, _ := url.Parse("http://user.production:password@gateway.example.com:8080")
    
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
    }
    
    client := &http.Client{
        Transport: transport,
    }
    
    // All requests will be routed through production group clients
    resp, err := client.Get("https://api.example.com/data")
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    defer resp.Body.Close()
    
    fmt.Printf("Response status: %s\n", resp.Status)
}
```

### Go SOCKS5 Client Group Routing

```go
package main

import (
    "fmt"
    "net/url"
    
    "golang.org/x/net/proxy"
)

func main() {
    // Configure SOCKS5 proxy with group routing
    proxyURL := "socks5://user.production:password@gateway.example.com:1080"
    u, _ := url.Parse(proxyURL)
    
    // Create SOCKS5 dialer
    dialer, err := proxy.FromURL(u, proxy.Direct)
    if err != nil {
        fmt.Printf("Error creating dialer: %v\n", err)
        return
    }
    
    // Connect through production group clients
    conn, err := dialer.Dial("tcp", "api.example.com:443")
    if err != nil {
        fmt.Printf("Error connecting: %v\n", err)
        return
    }
    defer conn.Close()
    
    fmt.Println("Connected through production group!")
}
```

### Production Environment Configuration Example

```yaml
# Production environment recommended configuration
log:
  level: "info"
  format: "json"
  output: "file"
  file: "logs/anyproxy.log"
  max_size: 100
  max_backups: 5
  max_age: 30
  compress: true

proxy:
  http:
    listen_addr: "0.0.0.0:8080"
    auth_username: "prod_user"
    auth_password: "your_strong_password"
  socks5:
    listen_addr: "0.0.0.0:1080"
    auth_username: "prod_user"
    auth_password: "your_strong_password"

gateway:
  listen_addr: "0.0.0.0:8443"
  tls_cert: "/etc/ssl/certs/your-domain.crt"
  tls_key: "/etc/ssl/private/your-domain.key"
  auth_username: "gateway_user"
  auth_password: "gateway_strong_password"

client:
  gateway_addr: "your-gateway-domain.com:8443"
  gateway_tls_cert: "/etc/ssl/certs/your-domain.crt"
  client_id: "prod-client-001"
  group_id: "production"
  replicas: 3
  auth_username: "gateway_user"
  auth_password: "gateway_strong_password"
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

## 📚 Complete Documentation

### 📖 Detailed Documentation
- [Deployment Guide](docs/DEPLOYMENT.md) - Production Environment Deployment
- [Group Routing Guide](docs/GROUP_BASED_ROUTING.md) - Complete Group Routing Configuration
- [API Documentation](docs/API.md) - WebSocket API Reference
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Detailed Troubleshooting Guide
- [Architecture Design](docs/ARCHITECTURE.md) - System Architecture Description

### 🔧 Technical Documentation
- [Dual Proxy Support](docs/DUAL_PROXY.md) - HTTP and SOCKS5 Proxy Detailed Description
- [SOCKS5 Client DNS](docs/SOCKS5_CLIENT_DNS.md) - Client DNS Resolution Guide
- [Logging Configuration](docs/LOGGING.md) - Logging Configuration and Best Practices
- [HTTP Proxy Troubleshooting](docs/HTTP_PROXY_TROUBLESHOOTING.md) - HTTP Specific Issues

## 🤝 Community Support

- **Issue Feedback**: [GitHub Issues](https://github.com/buhuipao/anyproxy/issues)
- **Feature Suggestions**: [GitHub Discussions](https://github.com/buhuipao/anyproxy/discussions)
- **Contribute Code**: View [Contribution Guide](CONTRIBUTING.md)

## 📋 Version History

View [CHANGELOG.md](CHANGELOG.md) for detailed version update records.

## 📄 License

This project uses the MIT License - View [LICENSE](LICENSE) file for details.

---

**❤️ Made with love by the AnyProxy team** 
