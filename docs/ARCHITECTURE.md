# AnyProxy Architecture Design

## Overview

AnyProxy is a reverse proxy system based on WebSocket + TLS, designed to securely expose internal services to public users. The system uses a client-initiated connection approach, avoiding the security risks of traditional port forwarding. It supports running both HTTP/HTTPS and SOCKS5 proxy services simultaneously.

## System Architecture

### Overall Architecture

```
┌─────────────┐  HTTP/SOCKS5  ┌─────────────┐    WebSocket+TLS    ┌─────────────┐    TCP/UDP    ┌─────────────┐
│ Public Users │ ──────────────→ │   Gateway   │ ──────────────────→ │   Client    │ ──────────────→ │ Target Service │
│ (Internet)  │               │             │                    │             │               │ (LAN/WAN)   │
└─────────────┘               └─────────────┘                    └─────────────┘               └─────────────┘
```

### Dual Proxy Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   HTTP Client   │───▶│   HTTP Proxy     │    │                 │
└─────────────────┘    │   (Port 8080)    │───▶│   Gateway       │
                       └──────────────────┘    │                 │
┌─────────────────┐    ┌──────────────────┐    │  ┌───────────┐  │
│  SOCKS5 Client  │───▶│  SOCKS5 Proxy    │───▶│  │ WebSocket │  │
└─────────────────┘    │   (Port 1080)    │    │  │ Clients   │  │
                       └──────────────────┘    │  └───────────┘  │
                                               └─────────────────┘
```

## Core Components

### 1. Gateway

The gateway is the core component of the system, responsible for:

- **HTTP/HTTPS Proxy Service**: Listens for HTTP proxy connection requests from public users
- **SOCKS5 Proxy Service**: Listens for SOCKS5 connection requests from public users
- **WebSocket Server**: Accepts WebSocket connections from clients
- **Request Routing**: Routes public user requests to appropriate clients
- **Load Balancing**: Distributes requests among multiple clients
- **Authentication & Authorization**: Verifies client and user identities

#### Main Functional Modules

```go
type Gateway struct {
    httpServer      *http.Server        // WebSocket server
    proxies         []GatewayProxy      // Proxy server list (HTTP + SOCKS5)
    clientManager   *ClientManager      // Client connection manager
    config          *config.GatewayConfig
}
```

#### Workflow

1. Start HTTP and/or SOCKS5 proxy services based on configuration, listening for public user connections
2. Start WebSocket server, waiting for client connections
3. When clients connect, perform TLS handshake and authentication
4. When public users initiate proxy requests, select an available client
5. Forward requests to clients via WebSocket
6. Return client responses to public users

#### Dual Proxy Support

The gateway now supports running multiple proxy types simultaneously:

**HTTP/HTTPS Proxy**:
- Supports standard HTTP proxy protocol
- Supports CONNECT method for HTTPS tunneling
- Supports Basic Authentication
- Handles HTTP request and response headers

**SOCKS5 Proxy**:
- Supports SOCKS5 protocol standard
- Supports username/password authentication
- Supports TCP and UDP connections
- Compatible with various SOCKS5 clients

**Configuration Flexibility**:
- Can start both proxy types simultaneously
- Can start only one proxy type
- Each proxy type has independent listening ports and authentication configuration
- Shares the same client connection pool

### 2. Client

The client runs in the internal network environment, responsible for:

- **Proactive Connection**: Proactively connects to the gateway's WebSocket server
- **Request Processing**: Receives and processes requests forwarded by the gateway
- **Service Access**: Accesses target services in internal or public networks
- **Access Control**: Restricts accessible services based on configuration

#### Main Functional Modules

```go
type ProxyClient struct {
    wsConn          *websocket.Conn     // WebSocket connection
    connManager     *ConnectionManager  // Connection manager
    config          *config.ClientConfig
}
```

#### Workflow

1. Establish WebSocket + TLS connection to the gateway
2. Perform authentication
3. Listen for proxy requests sent by the gateway
4. Establish connections to target services for each request
5. Forward data between gateway and target services
6. Handle connection closures and error conditions

### 3. Connection Management

#### Connection Wrapper

```go
type ConnectionWrapper struct {
    ID          string
    Conn        net.Conn
    CreatedAt   time.Time
    LastActive  time.Time
}
```

Responsible for:
- Connection lifecycle management
- Connection state tracking
- Timeout handling

#### WebSocket Writer

```go
type WebSocketWriter struct {
    conn   *websocket.Conn
    connID string
    mu     sync.Mutex
}
```

Responsible for:
- Safe WebSocket message writing
- Concurrent write control
- Error handling

## Data Flow

### 1. Client Registration Flow

```
Client                    Gateway
  │                         │
  │──── WebSocket Connect ──→│
  │                         │
  │←──── TLS Handshake ─────│
  │                         │
  │──── Auth Request ───────→│
  │                         │
  │←──── Auth Response ─────│
  │                         │
  │──── Keep Alive ─────────→│
```

### 2. Proxy Request Flow

#### HTTP Proxy Request Flow

```
User          Gateway         Client          Target
  │              │              │              │
  │─ HTTP ───────→│              │              │
  │              │─ WebSocket ──→│              │
  │              │              │─ HTTP/HTTPS ─→│
  │              │              │←─ Response ──│
  │              │←─ WebSocket ──│              │
  │←─ HTTP ──────│              │              │
```

#### SOCKS5 Proxy Request Flow

```
User          Gateway         Client          Target
  │              │              │              │
  │─ SOCKS5 ─────→│              │              │
  │              │─ WebSocket ──→│              │
  │              │              │─ TCP/UDP ────→│
  │              │              │←─ Response ──│
  │              │←─ WebSocket ──│              │
  │←─ SOCKS5 ────│              │              │
```

## Security Mechanisms

### 1. Transport Security

- **TLS Encryption**: All WebSocket connections use TLS 1.2+ encryption
- **Certificate Verification**: Clients verify the gateway's TLS certificate
- **Mutual Authentication**: Supports client certificate authentication (optional)

### 2. Identity Authentication

- **Username/Password**: Username and password-based authentication mechanism
- **HTTP Proxy Authentication**: Supports Basic Authentication for HTTP proxy
- **SOCKS5 Authentication**: Supports user authentication for SOCKS5 protocol
- **Client Authentication**: Authentication when clients connect to the gateway
- **Independent Authentication**: Each proxy type can configure independent authentication information

### 3. Access Control

- **Blacklist**: Prohibits access to specific hosts or IP ranges
- **Whitelist**: Only allows access to configured service lists
- **Protocol Restrictions**: Restricts usable protocol types (TCP/UDP)

## Configuration Management

### Configuration Structure

```go
type Config struct {
    Proxy   ProxyConfig   `yaml:"proxy"`
    Gateway GatewayConfig `yaml:"gateway"`
    Client  ClientConfig  `yaml:"client"`
}

type ProxyConfig struct {
    HTTP   HTTPConfig   `yaml:"http"`
    SOCKS5 SOCKS5Config `yaml:"socks5"`
}

type HTTPConfig struct {
    ListenAddr   string `yaml:"listen_addr"`
    AuthUsername string `yaml:"auth_username"`
    AuthPassword string `yaml:"auth_password"`
}

type SOCKS5Config struct {
    ListenAddr   string `yaml:"listen_addr"`
    AuthUsername string `yaml:"auth_username"`
    AuthPassword string `yaml:"auth_password"`
}
```

### Configuration Hot Reload

- Supports hot reloading of configuration files
- Apply new configurations without restarting services
- Smooth transition of configuration changes

## Performance Optimization

### 1. Connection Pool

- Reuse WebSocket connections
- Configurable connection pool size
- Automatic cleanup of idle connections

### 2. Concurrency Control

- Limit maximum concurrent connections
- Request queue management
- Backpressure control mechanism

### 3. Memory Management

- Buffer reuse
- Timely resource release
- Memory usage monitoring

## Monitoring and Logging

### 1. Logging

- Structured log output
- Different levels of logging
- Sensitive information masking

### 2. Metrics Monitoring

- Connection count statistics
- Request response time
- Error rate monitoring
- Traffic statistics

## Scalability

### 1. Horizontal Scaling

- Supports multiple gateway instances
- Automatic client reconnection
- Load balancing strategies

### 2. Protocol Extension

- Plugin-based protocol support
- Custom protocol handlers
- Protocol conversion capabilities

## Fault Handling

### 1. Connection Recovery

- Automatic reconnection mechanism
- Exponential backoff strategy
- Connection health checks

### 2. Error Handling

- Graceful error handling
- Error information propagation
- Fault isolation mechanisms 