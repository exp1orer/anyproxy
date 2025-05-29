# HTTP Proxy Troubleshooting Guide

## Common Errors and Solutions

### 1. ERR_TUNNEL_CONNECTION_FAILED

**Error Description**: 
```
This site can't be reached
The webpage at https://example.com/ might be temporarily down or it may have moved permanently to a new web address.
ERR_TUNNEL_CONNECTION_FAILED
```

**Root Cause Analysis**:
- HTTPS CONNECT tunnel establishment failed
- Proxy server cannot connect to target server
- Proxy server configuration error

**Solutions**:

#### 1.1 Check Proxy Configuration

Ensure HTTP proxy is correctly configured:

```yaml
proxy:
  http:
    listen_addr: "0.0.0.0:8080"  # Ensure port is correct
    auth_username: "your_user"   # Optional
    auth_password: "your_pass"   # Optional
```

#### 1.2 Check Client Connection

Ensure at least one client is connected to the gateway:

```bash
# Check gateway logs, should see similar information:
# Client connected: client-001
```

#### 1.3 Check Network Connectivity

Test if proxy server is reachable:

```bash
# Test if proxy port is open
telnet your-proxy-server 8080

# Test simple HTTP request
curl -v -x http://your-proxy-server:8080 http://httpbin.org/ip
```

#### 1.4 Check Target Server

Ensure target server is accessible from client:

```bash
# Test on client machine
curl -v https://www.bilibili.com/
```

### 2. 407 Proxy Authentication Required

**Error Description**:
```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Proxy"
```

**Solutions**:

#### 2.1 Provide Correct Authentication

```bash
# Use username and password
curl -x http://username:password@proxy-server:8080 https://example.com

# Or set environment variables
export http_proxy=http://username:password@proxy-server:8080
export https_proxy=http://username:password@proxy-server:8080
```

#### 2.2 Browser Configuration

In browser proxy settings:
- Proxy Type: HTTP
- Proxy Address: your-proxy-server
- Proxy Port: 8080
- Username: your_username
- Password: your_password

### 3. 502 Bad Gateway

**Error Description**:
```
HTTP/1.1 502 Bad Gateway
```

**Root Cause Analysis**:
- Proxy cannot connect to target server
- Client connection disconnected
- Network routing issues

**Solutions**:

#### 3.1 Check Client Status

```bash
# Check gateway logs
tail -f gateway.log

# Should see client connection information
# Client connected: client-001
```

#### 3.2 Check Target Server Reachability

```bash
# Test on client machine
ping target-server.com
telnet target-server.com 443
```

#### 3.3 Check Firewall Settings

Ensure client can access target server:
- Check outbound firewall rules
- Check network policies
- Check DNS resolution

### 4. Connection Timeout

**Error Description**:
```
curl: (7) Failed to connect to proxy-server port 8080: Connection timed out
```

**Solutions**:

#### 4.1 Check Proxy Server Status

```bash
# Check if proxy process is running
ps aux | grep anyproxy

# Check port listening
netstat -tlnp | grep 8080
```

#### 4.2 Check Network Connectivity

```bash
# Test network connection
ping proxy-server
traceroute proxy-server
```

#### 4.3 Check Firewall

```bash
# Check firewall rules
iptables -L
ufw status

# Open proxy port
ufw allow 8080
```

## Debugging Techniques

### 1. Enable Verbose Logging

Enable debug logging in configuration file:

```yaml
log:
  level: debug
  format: json
```

### 2. Use curl for Testing

```bash
# Test HTTP request
curl -v -x http://proxy:8080 http://httpbin.org/ip

# Test HTTPS request
curl -v -x http://proxy:8080 https://httpbin.org/ip

# Test authenticated request
curl -v -x http://user:pass@proxy:8080 https://httpbin.org/ip
```

### 3. Use openssl for HTTPS Testing

```bash
# Test HTTPS connection through proxy
openssl s_client -connect httpbin.org:443 -proxy proxy:8080
```

### 4. Network Packet Capture

```bash
# Use tcpdump for packet capture analysis
tcpdump -i any -w proxy-debug.pcap port 8080

# Use wireshark to analyze capture file
wireshark proxy-debug.pcap
```

## Performance Optimization

### 1. Adjust Timeout Settings

```yaml
proxy:
  http:
    read_timeout: 30s
    write_timeout: 30s
    idle_timeout: 60s
```

### 2. Adjust Buffer Size

```go
// Adjust buffer size in code
buffer := make([]byte, 64*1024) // 64KB buffer
```

### 3. Connection Pool Optimization

```yaml
client:
  max_concurrent_conns: 200
  keep_alive_timeout: 30s
```

## Monitoring and Alerting

### 1. Key Metrics

- Proxy connection count
- Request success rate
- Response time
- Error rate

### 2. Log Monitoring

```bash
# Monitor error logs
tail -f gateway.log | grep ERROR

# Count connections
grep "Client connected" gateway.log | wc -l
```

### 3. Health Checks

```bash
# Create health check script
#!/bin/bash
curl -f -x http://proxy:8080 http://httpbin.org/status/200
if [ $? -eq 0 ]; then
    echo "Proxy is healthy"
else
    echo "Proxy is unhealthy"
    exit 1
fi
```

## Common Configuration Errors

### 1. Port Conflicts

```bash
# Check port usage
lsof -i :8080
netstat -tlnp | grep 8080
```

### 2. Permission Issues

```bash
# Ensure permission to bind port
# Ports < 1024 require root privileges
sudo ./anyproxy-gateway
```

### 3. Configuration File Format Errors

```bash
# Validate YAML format
yamllint config.yaml

# Check configuration file syntax
./anyproxy-gateway --config config.yaml --check-config
```

## Contact Support

If the problem persists, please provide the following information:

1. Complete error logs
2. Proxy configuration file
3. Network topology diagram
4. Operating system versions of client and server
5. Detailed steps to reproduce the issue

Submit Issue to: https://github.com/buhuipao/anyproxy/issues 