# Group-Based Client Routing

## Overview

AnyProxy supports group-based client routing, allowing users to select specific groups of clients for forwarding services based on the username provided during proxy authentication. This feature enables multi-tenant environments and service isolation.

## Features

### 1. Username Format Support
- **Standard Format**: `username.group-id`
- **Backward Compatible**: Plain `username` (uses default group)
- **Automatic Parsing**: Extracts group-id from username automatically

### 2. Multi-Group Management
- **Dynamic Groups**: Groups are created automatically when clients join
- **Client Assignment**: Clients specify their group via `group_id` configuration
- **Default Group**: Clients without group assignment join the default group (`""`)

### 3. Smart Routing
- **Group Selection**: Routes requests to clients in the specified group
- **Fallback Mechanism**: Falls back to default group if specified group has no clients
- **Load Distribution**: Distributes requests among available clients in the group

### 4. Protocol Support
- **HTTP Proxy**: Full support for group-based routing
- **SOCKS5 Proxy**: Full support with enhanced authentication context
- **Dual Protocol**: Both protocols can be used simultaneously

## Configuration

### Client Configuration

Configure clients to join specific groups:

```yaml
client:
  gateway_addr: "gateway.example.com:8443"
  gateway_tls_cert: "certs/server.crt"
  client_id: "prod-client-001"
  group_id: "production"  # Specify the group this client belongs to
  replicas: 1
  auth_username: "gateway_user"
  auth_password: "gateway_password"
```

### Gateway Configuration

No special configuration required for the gateway. Group management is automatic:

```yaml
gateway:
  listen_addr: ":8443"
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"
  auth_username: "gateway_user"
  auth_password: "gateway_password"

proxy:
  http:
    listen_addr: ":8080"
    auth_username: "proxy_user"  # Ignored for group extraction
    auth_password: "proxy_pass"  # Password validation
  socks5:
    listen_addr: ":1080"
    auth_username: "proxy_user"  # Ignored for group extraction
    auth_password: "proxy_pass"  # Password validation
```

## Usage Examples

### HTTP Proxy

```bash
# Route to production group
curl -x http://user.production:proxy_pass@gateway:8080 https://api.example.com

# Route to testing group
curl -x http://user.testing:proxy_pass@gateway:8080 https://api.example.com

# Route to default group
curl -x http://user:proxy_pass@gateway:8080 https://api.example.com

# Environment variables
export http_proxy=http://user.production:proxy_pass@gateway:8080
export https_proxy=http://user.production:proxy_pass@gateway:8080
curl https://api.example.com
```

### SOCKS5 Proxy

```bash
# Route to production group
curl --socks5 user.production:proxy_pass@gateway:1080 https://api.example.com

# Route to testing group
curl --socks5 user.testing:proxy_pass@gateway:1080 https://api.example.com

# Route to default group
curl --socks5 user:proxy_pass@gateway:1080 https://api.example.com

# Environment variables
export ALL_PROXY=socks5://user.production:proxy_pass@gateway:1080
curl https://api.example.com
```

### Programmatic Usage

#### Go with net/http

```go
import (
    "net/http"
    "net/url"
)

func main() {
    // Configure HTTP proxy with group routing
    proxyURL, _ := url.Parse("http://user.production:proxy_pass@gateway:8080")
    
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxyURL),
    }
    
    client := &http.Client{Transport: transport}
    
    resp, err := client.Get("https://api.example.com")
}

#### Go with SOCKS5

```go
import (
    "net/url"
    
    "golang.org/x/net/proxy"
)

func main() {
    // Configure SOCKS5 proxy with group routing
    proxyURL := "socks5://user.production:proxy_pass@gateway:1080"
    u, _ := url.Parse(proxyURL)
    
    // Create SOCKS5 dialer
    dialer, err := proxy.FromURL(u, proxy.Direct)
    if err != nil {
        fmt.Printf("Error creating dialer: %v\n", err)
        return
    }
    
    // Connect through production group clients
    conn, err := dialer.Dial("tcp", "api.example.com:443")
}

## Deployment Scenarios

### Multi-Environment Setup

Deploy different client groups for different environments:

#### Production Environment
```yaml
# production-client.yaml
client:
  client_id: "prod-client-001"
  group_id: "production"
  replicas: 3
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "192.168.0.0/16"
```

#### Testing Environment
```yaml
# testing-client.yaml
client:
  client_id: "test-client-001"
  group_id: "testing"
  replicas: 2
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
```

#### Development Environment
```yaml
# development-client.yaml
client:
  client_id: "dev-client-001"
  group_id: "development"
  replicas: 1
  allowed_hosts:
    - ".*"  # Allow all hosts for development
```

### Geographic Distribution

Deploy clients in different regions:

```yaml
# us-east-client.yaml
client:
  client_id: "us-east-001"
  group_id: "us-east"

# eu-west-client.yaml
client:
  client_id: "eu-west-001"
  group_id: "eu-west"

# asia-pacific-client.yaml
client:
  client_id: "ap-001"
  group_id: "asia-pacific"
```

Usage:
```bash
# Route through US East clients
curl -x http://user.us-east:pass@gateway:8080 https://api.example.com

# Route through EU West clients
curl -x http://user.eu-west:pass@gateway:8080 https://api.example.com
```

## Technical Implementation

### Authentication with Group-Based Usernames

Both HTTP and SOCKS5 proxies have been enhanced to properly handle authentication when usernames contain group information in the `username.group-id` format.

#### Authentication Logic

**Before Fix**: Authentication would fail because the full `username.group-id` was compared against the configured username.

**After Fix**: 
1. Extract the base username (part before `.`) for authentication
2. Validate the base username and password against configuration
3. Store the full username (including group-id) for group extraction
4. Maintain backward compatibility with plain usernames

#### HTTP Proxy Authentication

```go
// Extract base username for authentication
baseUsername := username
if strings.Contains(username, ".") {
    userParts := strings.SplitN(username, ".", 2)
    baseUsername = userParts[0]
}

// Authenticate using base username
authenticated := baseUsername == h.config.AuthUsername && password == h.config.AuthPassword
```

#### SOCKS5 Proxy Authentication

SOCKS5 uses a custom authenticator that implements the proper SOCKS5 authentication protocol:

```go
type CustomUserPassAuthenticator struct {
    ConfigUsername string
    ConfigPassword string
}

func (c *CustomUserPassAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*socks5.AuthContext, error) {
    // Read username and password from SOCKS5 protocol
    // Extract base username for authentication
    baseUsername := usernameStr
    if strings.Contains(usernameStr, ".") {
        userParts := strings.SplitN(usernameStr, ".", 2)
        baseUsername = userParts[0]
    }
    
    // Authenticate and return full username in context
    authenticated := baseUsername == c.ConfigUsername && passwordStr == c.ConfigPassword
    
    return &socks5.AuthContext{
        Payload: map[string]string{
            "username": usernameStr, // Full username with group-id
            "password": passwordStr,
        },
    }, nil
}
```

### Group Management

The gateway maintains an internal mapping of groups to clients:

```go
type Gateway struct {
    clients map[string]*ClientConn           // client_id -> client
    groups  map[string]map[string]struct{}   // group_id -> set of client_ids
}
```

### Username Parsing

The `extractGroupFromUsername` function parses usernames:

```go
func (g *Gateway) extractGroupFromUsername(username string) string {
    parts := strings.Split(username, ".")
    if len(parts) == 2 {
        return parts[1] // Return group-id part
    }
    return "" // Default group
}
```

### Client Selection Algorithm

1. **Extract Group**: Parse group-id from username
2. **Find Clients**: Look up clients in the specified group
3. **Fallback**: If no clients in group, try default group
4. **Select Client**: Return first available client (round-robin can be implemented)

### SOCKS5 Enhancement

SOCKS5 support uses the enhanced `WithDialAndRequest` function:

```go
wrappedDialFunc := func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
    var userCtx *UserContext
    
    // Extract user information from request's AuthContext
    if request.AuthContext != nil && request.AuthContext.Payload != nil {
        if username, exists := request.AuthContext.Payload["username"]; exists {
            groupID := groupExtractor(username)
            userCtx = &UserContext{
                Username: username,
                GroupID:  groupID,
            }
        }
    }
    
    ctx = context.WithValue(ctx, "user", userCtx)
    return dialFunc(ctx, network, addr)
}
```

## Monitoring and Logging

### Connection Logging

The system provides detailed logging for group-based routing:

```
INFO Gateway received request user=user.production group=production
INFO Selected client from group group=production client_id=prod-client-001
INFO SOCKS5 extracted user info username=user.production group_id=production
```

### Fallback Logging

When fallback occurs:

```
WARN No clients available in group group=nonexistent, falling back to default
INFO Selected client from default group client_id=default-client-001
```

### Client Management Logging

```
INFO Client connected client_id=prod-client-001 group_id=production
INFO Client disconnected client_id=prod-client-001
```

## Troubleshooting

### Common Issues

#### 1. No Clients Available

**Error**: `no clients available in group 'production' or default group`

**Solutions**:
- Verify clients are running and connected
- Check client `group_id` configuration
- Ensure gateway connectivity

#### 2. Authentication Failures

**Error**: Authentication failed for group-based username

**Solutions**:
- Verify password is correct (username format is ignored for auth)
- Check proxy configuration
- Review authentication logs

#### 3. Group Not Found

**Behavior**: Requests fall back to default group

**Solutions**:
- Verify group name spelling
- Check if clients with specified group are connected
- Review client configuration

### Debugging Commands

```bash
# Check client connections
docker logs anyproxy-gateway | grep "Client connected"

# Monitor group selection
docker logs anyproxy-gateway | grep "Selected client from group"

# Check authentication
docker logs anyproxy-gateway | grep "extracted user info"

# Test connectivity
curl -v -x http://user.testgroup:pass@gateway:8080 https://httpbin.org/ip
```

## Best Practices

### 1. Group Naming
- Use descriptive names: `production`, `testing`, `development`
- Avoid special characters except hyphens and underscores
- Keep names short and memorable

### 2. Client Distribution
- Deploy multiple clients per group for redundancy
- Consider geographic distribution for performance
- Monitor client health and availability

### 3. Security Considerations
- Use strong passwords for proxy authentication
- Implement proper network segmentation
- Monitor access patterns and logs

### 4. Performance Optimization
- Deploy clients close to target services
- Use appropriate client replica counts
- Monitor connection patterns and adjust accordingly

## Version Requirements

- **AnyProxy**: v1.0.0+
- **Go**: 1.23.0+
- **go-socks5**: v0.0.6+
- **golang.org/x/net**: Latest

## Migration Guide

### From Basic Setup

1. **Update Client Configuration**: Add `group_id` to client configurations
2. **Update Usage**: Modify usernames to include group information
3. **Test Connectivity**: Verify group-based routing works as expected
4. **Monitor Logs**: Check for proper group selection in logs

### Backward Compatibility

- Existing configurations continue to work without modification
- Plain usernames route to default group
- No breaking changes to existing functionality

## API Reference

### Configuration Fields

#### Client Configuration
- `group_id` (string): Group identifier for the client
- Default: `""` (default group)

#### Username Format
- Format: `username.group-id`
- Example: `user.prod-uuid-123`, `admin.test-env-456`
- Fallback: Plain username uses default group

### Environment Variables

```bash
# Client group override
export CLIENT_GROUP_ID=production

# Proxy authentication with group
export HTTP_PROXY=http://user.production:pass@gateway:8080
export HTTPS_PROXY=http://user.production:pass@gateway:8080
export ALL_PROXY=socks5://user.production:pass@gateway:1080
```

## Examples Repository

Complete examples are available in the `examples/` directory:

- `group-based-proxy-config.yaml`: Complete configuration example
- `socks5-group-test.go`: Testing tool for SOCKS5 group routing
- Production deployment scripts
- Docker Compose configurations

For more examples and advanced configurations, see the [examples directory](../examples/) in the repository. 