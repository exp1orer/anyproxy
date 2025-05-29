# Dual Proxy Support

AnyProxy now supports running both HTTP/HTTPS and SOCKS5 proxy servers simultaneously.

## Features

- **HTTP/HTTPS Proxy**: Supports standard HTTP proxy protocol, including CONNECT method for HTTPS tunneling
- **SOCKS5 Proxy**: Supports SOCKS5 protocol
- **Simultaneous Operation**: Can start both proxy types at the same time
- **Independent Configuration**: Each proxy type has independent listening addresses and authentication configuration
- **Unified Backend**: Both proxies use the same WebSocket client connection pool

## Configuration

### Start Both Proxy Types

```yaml
proxy:
  # HTTP proxy configuration
  http:
    listen_addr: "0.0.0.0:8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  
  # SOCKS5 proxy configuration
  socks5:
    listen_addr: "0.0.0.0:1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
```

### HTTP Proxy Only

```yaml
proxy:
  http:
    listen_addr: "0.0.0.0:8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  # Leave socks5 section empty or don't configure listen_addr
```

### SOCKS5 Proxy Only

```yaml
proxy:
  socks5:
    listen_addr: "0.0.0.0:1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
  # Leave http section empty or don't configure listen_addr
```

## HTTP Proxy Features

### Supported Methods

- **GET, POST, PUT, DELETE** and other standard HTTP methods
- **CONNECT** method for HTTPS tunneling

### Authentication

HTTP proxy supports Basic Authentication:

```
Proxy-Authorization: Basic <base64(username:password)>
```

### Usage Examples

```bash
# Use curl through HTTP proxy to access websites
curl -x http://http_user:http_pass@localhost:8080 https://example.com

# Set environment variables
export http_proxy=http://http_user:http_pass@localhost:8080
export https_proxy=http://http_user:http_pass@localhost:8080
```

## SOCKS5 Proxy Features

### Authentication Methods

- No authentication
- Username/password authentication

### Usage Examples

```bash
# Use curl through SOCKS5 proxy
curl --socks5 socks_user:socks_pass@localhost:1080 https://example.com

# Set environment variables
export ALL_PROXY=socks5://socks_user:socks_pass@localhost:1080
```

## Architecture

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

## Log Output

At startup, the system displays the created proxy types:

```
2025/05/27 16:05:08 Created HTTP proxy on 0.0.0.0:8080
2025/05/27 16:05:08 Created SOCKS5 proxy on 0.0.0.0:1080
```

## Error Handling

- If neither proxy type has `listen_addr` configured, the system returns an error
- If one proxy fails to start, already started proxies will be stopped
- Errors for each proxy type are logged independently

## Performance Considerations

- Both proxy types share the same client connection pool
- Connection load balancing is performed at the client level
- Each proxy type has independent listening ports to avoid port conflicts

## Example Configuration File

For complete configuration examples, please refer to `examples/dual-proxy-config.yaml`. 