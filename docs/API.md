# AnyProxy API Documentation

## Overview

AnyProxy uses WebSocket + TLS protocol for communication between clients and gateways, while supporting both HTTP/HTTPS and SOCKS5 proxy services. This document describes the communication protocol, message formats, and API interfaces.

## WebSocket Connection

### Connection Establishment

Clients connect to the gateway via WebSocket:

```
wss://gateway-host:8443/ws
```

### Authentication

After connection establishment, clients need to send authentication messages:

```json
{
  "type": "auth",
  "data": {
    "username": "client_username",
    "password": "client_password",
    "client_id": "unique_client_id"
  }
}
```

Gateway response:

```json
{
  "type": "auth_response",
  "data": {
    "success": true,
    "message": "Authentication successful"
  }
}
```

## Message Format

All messages use JSON format with the following basic structure:

```json
{
  "type": "message_type",
  "data": {
    // Message data
  }
}
```

## Message Types

### 1. Authentication Message (auth)

**Client → Gateway**

```json
{
  "type": "auth",
  "data": {
    "username": "string",
    "password": "string", 
    "client_id": "string"
  }
}
```

**Gateway → Client**

```json
{
  "type": "auth_response",
  "data": {
    "success": boolean,
    "message": "string"
  }
}
```

### 2. Connection Request (connect)

**Gateway → Client**

When there's a new proxy request, the gateway sends a connection request:

```json
{
  "type": "connect",
  "data": {
    "connection_id": "unique_connection_id",
    "target_host": "target.example.com",
    "target_port": 80,
    "protocol": "tcp"
  }
}
```

**Client → Gateway**

Client responds with connection result:

```json
{
  "type": "connect_response",
  "data": {
    "connection_id": "unique_connection_id",
    "success": boolean,
    "message": "string"
  }
}
```

### 3. Data Transfer (data)

**Bidirectional**

Used for transferring proxy data between gateway and client:

```json
{
  "type": "data",
  "data": {
    "connection_id": "unique_connection_id",
    "payload": "base64_encoded_data"
  }
}
```

### 4. Connection Close (close)

**Bidirectional**

Notifies the other party to close a specific connection:

```json
{
  "type": "close",
  "data": {
    "connection_id": "unique_connection_id",
    "reason": "string"
  }
}
```

### 5. Heartbeat Messages (ping/pong)

**Client → Gateway**

```json
{
  "type": "ping",
  "data": {
    "timestamp": 1640995200
  }
}
```

**Gateway → Client**

```json
{
  "type": "pong",
  "data": {
    "timestamp": 1640995200
  }
}
```

### 6. Error Messages (error)

**Bidirectional**

```json
{
  "type": "error",
  "data": {
    "code": "error_code",
    "message": "error_description",
    "connection_id": "optional_connection_id"
  }
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `AUTH_FAILED` | Authentication failed |
| `INVALID_MESSAGE` | Invalid message format |
| `CONNECTION_FAILED` | Failed to connect to target |
| `FORBIDDEN_HOST` | Forbidden host access |
| `RATE_LIMITED` | Request rate limited |
| `INTERNAL_ERROR` | Internal error |

## Connection Lifecycle

### 1. Establishing Connection

```mermaid
sequenceDiagram
    participant C as Client
    participant G as Gateway
    
    C->>G: WebSocket Connect
    G->>C: Connection Established
    C->>G: Auth Message
    G->>C: Auth Response (Success)
    
    loop Keep Alive
        C->>G: Ping
        G->>C: Pong
    end
```

### 2. Proxy Request Processing

```mermaid
sequenceDiagram
    participant U as User
    participant G as Gateway
    participant C as Client
    participant T as Target
    
    U->>G: Proxy Connect Request (HTTP/SOCKS5)
    G->>C: Connect Message
    C->>T: TCP Connect
    T->>C: Connection Established
    C->>G: Connect Response (Success)
    G->>U: Proxy Response (Success)
    
    loop Data Transfer
        U->>G: Data
        G->>C: Data Message
        C->>T: Forward Data
        T->>C: Response Data
        C->>G: Data Message
        G->>U: Response Data
    end
    
    U->>G: Close Connection
    G->>C: Close Message
    C->>T: Close Connection
```

## Configuration API

### Proxy Configuration

Supports simultaneous configuration of HTTP and SOCKS5 proxies:

```yaml
proxy:
  # HTTP proxy configuration
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_password"
  
  # SOCKS5 proxy configuration
  socks5:
    listen_addr: ":1080"
    auth_username: "socks_user"
    auth_password: "socks_password"
```

**Configuration Notes**:
- Can configure both proxy types simultaneously
- Can configure only one proxy type
- Each proxy has independent listening addresses and authentication configuration

### Gateway Configuration

```yaml
gateway:
  listen_addr: ":8443"
  tls_cert: "path/to/cert.pem"
  tls_key: "path/to/key.pem"
  auth_username: "gateway_user"
  auth_password: "gateway_password"
```

### Client Configuration

```yaml
client:
  gateway_addr: "gateway.example.com:8443"
  gateway_tls_cert: "path/to/gateway_cert.pem"
  client_id: "unique_client_identifier"
  replicas: 1
  max_concurrent_conns: 100
  auth_username: "gateway_user"
  auth_password: "gateway_password"
  forbidden_hosts:
    - "internal.company.com"
    - "192.168.0.0/16"
  limit:
    - name: "web-server"
      addr: "localhost:8080"
      protocol: "tcp"
```

## Security Considerations

### 1. TLS Configuration

- Use TLS 1.2 or higher
- Verify server certificates
- Support client certificate authentication

### 2. Authentication Mechanisms

- Username and password-based authentication
- Support for custom authentication plugins
- Retry limits after authentication failures

### 3. Access Control

- Hostname-based blacklist and whitelist
- IP address-based access control
- Protocol-level restrictions

## Performance Optimization

### 1. Connection Reuse

- WebSocket connection reuse
- Connection pool management
- Automatic cleanup of idle connections

### 2. Data Compression

- Support for WebSocket compression extensions
- Configurable compression levels
- Adaptive compression strategies

### 3. Buffer Management

- Configurable buffer sizes
- Backpressure control mechanisms
- Memory usage optimization

## Monitoring Metrics

### Connection Metrics

- Active connection count
- Connection establishment rate
- Connection failure rate
- Average connection duration

### Traffic Metrics

- Inbound/outbound bytes
- Message processing rate
- Latency statistics
- Error rate

### Performance Metrics

- CPU usage
- Memory consumption
- Network bandwidth usage
- Concurrent connection count

## Example Code

### Client Connection Example

```go
package main

import (
    "crypto/tls"
    "encoding/json"
    "log"
    "net/url"
    
    "github.com/gorilla/websocket"
)

type Message struct {
    Type string      `json:"type"`
    Data interface{} `json:"data"`
}

type AuthData struct {
    Username string `json:"username"`
    Password string `json:"password"`
    ClientID string `json:"client_id"`
}

func main() {
    // Connect to gateway
    u := url.URL{Scheme: "wss", Host: "gateway.example.com:8443", Path: "/ws"}
    
    dialer := websocket.Dialer{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: false,
        },
    }
    
    conn, _, err := dialer.Dial(u.String(), nil)
    if err != nil {
        log.Fatal("dial:", err)
    }
    defer conn.Close()
    
    // Send authentication message
    authMsg := Message{
        Type: "auth",
        Data: AuthData{
            Username: "client_user",
            Password: "client_password",
            ClientID: "client_001",
        },
    }
    
    if err := conn.WriteJSON(authMsg); err != nil {
        log.Fatal("write auth:", err)
    }
    
    // Read authentication response
    var response Message
    if err := conn.ReadJSON(&response); err != nil {
        log.Fatal("read auth response:", err)
    }
    
    log.Printf("Auth response: %+v", response)
    
    // Message processing loop
    for {
        var msg Message
        if err := conn.ReadJSON(&msg); err != nil {
            log.Printf("read error: %v", err)
            break
        }
        
        // Handle different message types
        switch msg.Type {
        case "connect":
            handleConnect(conn, msg)
        case "data":
            handleData(conn, msg)
        case "close":
            handleClose(conn, msg)
        case "ping":
            handlePing(conn, msg)
        }
    }
}

func handleConnect(conn *websocket.Conn, msg Message) {
    // Handle connection request
    log.Printf("Received connect request: %+v", msg.Data)
    
    // Respond with connection result
    response := Message{
        Type: "connect_response",
        Data: map[string]interface{}{
            "connection_id": "extracted_from_msg",
            "success":       true,
            "message":       "Connection established",
        },
    }
    
    conn.WriteJSON(response)
}

func handleData(conn *websocket.Conn, msg Message) {
    // Handle data transfer
    log.Printf("Received data: %+v", msg.Data)
}

func handleClose(conn *websocket.Conn, msg Message) {
    // Handle connection close
    log.Printf("Received close: %+v", msg.Data)
}

func handlePing(conn *websocket.Conn, msg Message) {
    // Respond to heartbeat
    response := Message{
        Type: "pong",
        Data: msg.Data,
    }
    conn.WriteJSON(response)
}
```

## Troubleshooting

### Common Issues

1. **WebSocket Connection Failure**
   - Check network connectivity
   - Verify TLS certificates
   - Confirm port accessibility

2. **Authentication Failure**
   - Check username and password
   - Verify client ID
   - Review authentication logs

3. **Message Format Errors**
   - Validate JSON format
   - Check required fields
   - Confirm data types

## HTTP Proxy Usage Examples

### Basic HTTP Requests

```bash
# Use curl through HTTP proxy
curl -x http://http_user:http_password@localhost:8080 https://example.com

# Set environment variables
export http_proxy=http://http_user:http_password@localhost:8080
export https_proxy=http://http_user:http_password@localhost:8080
curl https://example.com
```

### HTTPS Tunnel (CONNECT Method)

```bash
# Use CONNECT method to establish HTTPS tunnel
curl -x http://http_user:http_password@localhost:8080 https://secure.example.com
```

### Browser Configuration

Configure HTTP proxy in browser:
- Proxy Type: HTTP
- Proxy Address: localhost
- Proxy Port: 8080
- Username: http_user
- Password: http_password

## SOCKS5 Proxy Usage Examples

### Basic SOCKS5 Requests

```bash
# Use curl through SOCKS5 proxy
curl --socks5 socks_user:socks_password@localhost:1080 https://example.com

# Set environment variables
export ALL_PROXY=socks5://socks_user:socks_password@localhost:1080
curl https://example.com
```

### Debugging Tools

```bash
# Use wscat to test WebSocket connection
npm install -g wscat
wscat -c wss://gateway.example.com:8443/ws

# Use openssl to test TLS connection
openssl s_client -connect gateway.example.com:8443

# View network connections
netstat -an | grep 8443
``` 