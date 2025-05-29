# AnyProxy Troubleshooting Guide

## Overview

This document provides diagnosis and solutions for common AnyProxy issues, helping users quickly locate and resolve problems.

## Common Issue Categories

### 1. Connection Issues

#### 1.1 WebSocket Connection Failure

**Symptoms**:
- Client cannot connect to gateway
- Connection drops immediately
- Connection timeout

**Possible Causes**:
- Network connectivity issues
- Firewall blocking connections
- TLS certificate problems
- Port already in use

**Diagnostic Steps**:

```bash
# 1. Check network connectivity
ping gateway-host

# 2. Check if port is open
telnet gateway-host 8443

# 3. Check TLS connection
openssl s_client -connect gateway-host:8443

# 4. Check port usage
netstat -an | grep 8443
```

**Solutions**:

```bash
# Check firewall settings
sudo ufw status
sudo firewall-cmd --list-ports

# Open ports
sudo ufw allow 8443/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload

# Check service status
sudo systemctl status anyproxy-gateway

# Restart service
sudo systemctl restart anyproxy-gateway
```

#### 1.2 TLS Handshake Failure

**Symptoms**:
- SSL/TLS handshake errors
- Certificate verification failure
- Connection reset

**Possible Causes**:
- Certificate expired or invalid
- Incorrect certificate path
- TLS version incompatibility
- Time synchronization issues

**Diagnostic Steps**:

```bash
# Check certificate validity
openssl x509 -in certs/server.crt -text -noout

# Check certificate expiration
openssl x509 -in certs/server.crt -enddate -noout

# Check system time
date
ntpdate -q pool.ntp.org
```

**Solutions**:

```bash
# Regenerate certificates
bash generate_certs.sh your-domain.com

# Synchronize system time
sudo ntpdate pool.ntp.org

# Check certificate permissions
ls -la certs/
sudo chown anyproxy:anyproxy certs/*
sudo chmod 600 certs/server.key
sudo chmod 644 certs/server.crt
```

### 2. Authentication Issues

#### 2.1 Authentication Failure

**Symptoms**:
- Client disconnects immediately after connection
- Authentication error messages
- Unable to authenticate through SOCKS5

**Possible Causes**:
- Incorrect username/password
- Configuration file mismatch
- Special character encoding issues

**Diagnostic Steps**:

```bash
# Check configuration file
cat configs/config.yaml | grep -A5 -B5 auth

# Check logs
sudo journalctl -u anyproxy-gateway | grep auth
sudo journalctl -u anyproxy-client | grep auth
```

**Solutions**:

```yaml
# Ensure gateway and client configurations match
gateway:
  auth_username: "same_username"
  auth_password: "same_password"

client:
  auth_username: "same_username"
  auth_password: "same_password"
```

### 3. Performance Issues

#### 3.1 Slow Connections

**Symptoms**:
- Long connection establishment time
- Slow data transfer speed
- High latency

**Possible Causes**:
- Network bandwidth limitations
- Insufficient system resources
- Improper configuration parameters

**Diagnostic Steps**:

```bash
# Check system resources
top
free -h
iostat 1

# Check network status
iftop
netstat -i

# Check connection count
ss -s
```

**Solutions**:

```yaml
# Optimize configuration parameters
client:
  replicas: 3                    # Increase client replica count
  max_concurrent_conns: 1000     # Increase maximum concurrent connections
```

```bash
# System optimization
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

#### 3.2 Memory Leaks

**Symptoms**:
- Continuously growing memory usage
- System slowdown
- Eventually running out of memory

**Diagnostic Steps**:

```bash
# Monitor memory usage
watch -n 1 'ps aux | grep anyproxy'

# Check memory details
pmap -d $(pgrep anyproxy-gateway)

# Use valgrind for checking (if available)
valgrind --tool=memcheck --leak-check=full ./bin/anyproxy-gateway
```

**Solutions**:

```bash
# Restart services to free memory
sudo systemctl restart anyproxy-gateway anyproxy-client

# Set memory limits
sudo systemctl edit anyproxy-gateway
# Add:
# [Service]
# MemoryLimit=1G
```

### 4. Configuration Issues

#### 4.1 Configuration File Errors

**Symptoms**:
- Service startup failure
- Configuration parsing errors
- Abnormal functionality

**Diagnostic Steps**:

```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('configs/config.yaml'))"

# Check configuration file permissions
ls -la configs/config.yaml

# Manually test configuration
./bin/anyproxy-gateway --config configs/config.yaml --dry-run
```

**Solutions**:

```bash
# Backup original configuration
cp configs/config.yaml configs/config.yaml.backup

# Use example configuration
cp configs/config.yaml.example configs/config.yaml

# Gradually modify configuration and test
```

#### 4.2 Port Conflicts

**Symptoms**:
- Service startup failure
- "Address already in use" error
- Port binding failure

**Diagnostic Steps**:

```bash
# Check port usage
sudo netstat -tlnp | grep :8443
sudo lsof -i :8443

# Check processes
ps aux | grep anyproxy
```

**Solutions**:

```bash
# Kill process occupying the port
sudo kill -9 $(lsof -t -i:8443)

# Or modify configuration to use different port
sed -i 's/:8443/:8444/g' configs/config.yaml
```

### 5. Network Issues

#### 5.1 DNS Resolution Failure

**Symptoms**:
- Cannot connect to target host
- DNS query timeout
- Domain name resolution errors

**Diagnostic Steps**:

```bash
# Test DNS resolution
nslookup target-host
dig target-host

# Check DNS configuration
cat /etc/resolv.conf

# Test different DNS servers
nslookup target-host 8.8.8.8
```

**Solutions**:

```bash
# Modify DNS configuration
echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
echo 'nameserver 8.8.4.4' >> /etc/resolv.conf

# Clear DNS cache
sudo systemctl restart systemd-resolved
```

#### 5.2 Firewall Blocking

**Symptoms**:
- Connection refused
- Timeout errors
- Partial functionality unavailable

**Diagnostic Steps**:

```bash
# Check iptables rules
sudo iptables -L -n

# Check ufw status
sudo ufw status verbose

# Check firewalld
sudo firewall-cmd --list-all
```

**Solutions**:

```bash
# UFW configuration
sudo ufw allow from any to any port 8443
sudo ufw allow from any to any port 1080

# firewalld configuration
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=1080/tcp
sudo firewall-cmd --reload

# iptables configuration
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
```

## Log Analysis

### Log Locations

```bash
# systemd logs
sudo journalctl -u anyproxy-gateway
sudo journalctl -u anyproxy-client

# File logs (if configured)
tail -f /var/log/anyproxy/gateway.log
tail -f /var/log/anyproxy/client.log
```

### Common Error Messages

#### "connection refused"

```bash
# Check service status
sudo systemctl status anyproxy-gateway

# Check port listening
sudo netstat -tlnp | grep anyproxy
```

#### "certificate verify failed"

```bash
# Check certificate
openssl verify certs/server.crt

# Regenerate certificate
bash generate_certs.sh
```

#### "authentication failed"

```bash
# Check configuration
grep -r auth configs/

# Check password special characters
echo "password" | od -c
```

### Enable Debug Logging

```yaml
# Add to configuration file
logging:
  level: debug
  output: /var/log/anyproxy/debug.log
```

## Monitoring and Diagnostic Tools

### System Monitoring

```bash
# Real-time monitoring script
#!/bin/bash
while true; do
    echo "=== $(date) ==="
    echo "Gateway Status: $(systemctl is-active anyproxy-gateway)"
    echo "Client Status: $(systemctl is-active anyproxy-client)"
    echo "Memory Usage: $(ps -o pid,ppid,cmd,%mem,%cpu --sort=-%mem -C anyproxy-gateway,anyproxy-client)"
    echo "Network Connections: $(ss -t | grep -E ':(8443|1080)' | wc -l)"
    echo ""
    sleep 30
done
```

### Network Diagnostics

```bash
# Connection test script
#!/bin/bash
HOST="gateway-host"
PORT="8443"

echo "Testing connection to $HOST:$PORT"

# TCP connection test
timeout 5 bash -c "</dev/tcp/$HOST/$PORT" && echo "TCP connection: OK" || echo "TCP connection: FAILED"

# TLS connection test
echo | timeout 5 openssl s_client -connect $HOST:$PORT 2>/dev/null && echo "TLS connection: OK" || echo "TLS connection: FAILED"

# WebSocket test (requires wscat)
if command -v wscat >/dev/null; then
    timeout 5 wscat -c wss://$HOST:$PORT/ws --no-check && echo "WebSocket connection: OK" || echo "WebSocket connection: FAILED"
fi
```

### Performance Testing

```bash
# Simple performance test
#!/bin/bash
PROXY_HOST="127.0.0.1"
PROXY_PORT="1080"
TARGET_URL="http://httpbin.org/ip"

echo "Testing SOCKS5 proxy performance..."

for i in {1..10}; do
    start_time=$(date +%s.%N)
    curl --socks5 $PROXY_HOST:$PROXY_PORT $TARGET_URL >/dev/null 2>&1
    end_time=$(date +%s.%N)
    duration=$(echo "$end_time - $start_time" | bc)
    echo "Request $i: ${duration}s"
done
```

## Recovery Procedures

### Service Recovery

```bash
#!/bin/bash
# Service recovery script

echo "Starting AnyProxy recovery procedure..."

# Stop services
sudo systemctl stop anyproxy-gateway anyproxy-client

# Check processes
if pgrep anyproxy; then
    echo "Killing remaining processes..."
    sudo pkill -f anyproxy
    sleep 5
fi

# Clean temporary files
sudo rm -f /tmp/anyproxy-*

# Check configuration
if ! python3 -c "import yaml; yaml.safe_load(open('configs/config.yaml'))" 2>/dev/null; then
    echo "Configuration file is invalid, restoring backup..."
    sudo cp configs/config.yaml.backup configs/config.yaml
fi

# Check certificates
if ! openssl x509 -in certs/server.crt -noout 2>/dev/null; then
    echo "Certificate is invalid, regenerating..."
    bash generate_certs.sh
fi

# Restart services
sudo systemctl start anyproxy-gateway
sleep 5
sudo systemctl start anyproxy-client

# Verify service status
if systemctl is-active --quiet anyproxy-gateway && systemctl is-active --quiet anyproxy-client; then
    echo "Recovery successful!"
else
    echo "Recovery failed, check logs:"
    sudo journalctl -u anyproxy-gateway --since "5 minutes ago"
    sudo journalctl -u anyproxy-client --since "5 minutes ago"
fi
```

### Configuration Recovery

```bash
#!/bin/bash
# Configuration recovery script

BACKUP_DIR="/backup/anyproxy"
CONFIG_DIR="/etc/anyproxy"

if [ -d "$BACKUP_DIR" ]; then
    echo "Restoring configuration from backup..."
    sudo cp -r $BACKUP_DIR/* $CONFIG_DIR/
    sudo chown -R anyproxy:anyproxy $CONFIG_DIR
    echo "Configuration restored"
else
    echo "No backup found, using default configuration..."
    sudo cp configs/config.yaml.example $CONFIG_DIR/config.yaml
fi
```

## Preventive Measures

### Regular Maintenance

```bash
# Add to crontab
# Daily configuration backup
0 2 * * * /opt/anyproxy/backup.sh

# Weekly service restart
0 3 * * 0 systemctl restart anyproxy-gateway anyproxy-client

# Monthly log cleanup
0 4 1 * * find /var/log/anyproxy -name "*.log" -mtime +30 -delete
```

### Monitoring Alerts

```bash
#!/bin/bash
# Monitoring script, can be configured as cron job

ALERT_EMAIL="admin@example.com"

# Check service status
if ! systemctl is-active --quiet anyproxy-gateway; then
    echo "AnyProxy Gateway is down!" | mail -s "AnyProxy Alert" $ALERT_EMAIL
fi

if ! systemctl is-active --quiet anyproxy-client; then
    echo "AnyProxy Client is down!" | mail -s "AnyProxy Alert" $ALERT_EMAIL
fi

# Check memory usage
MEMORY_USAGE=$(ps -o %mem -C anyproxy-gateway --no-headers | awk '{sum+=$1} END {print sum}')
if (( $(echo "$MEMORY_USAGE > 80" | bc -l) )); then
    echo "High memory usage: ${MEMORY_USAGE}%" | mail -s "AnyProxy Memory Alert" $ALERT_EMAIL
fi
```

## Contact Support

If none of the above solutions resolve the issue, please:

1. Collect relevant logs and configuration files
2. Record detailed error information and reproduction steps
3. Provide system environment information
4. Create an Issue in the GitHub repository or contact technical support

### Information Collection Script

```bash
#!/bin/bash
# Collect diagnostic information

REPORT_FILE="anyproxy-diagnostic-$(date +%Y%m%d-%H%M%S).txt"

echo "AnyProxy Diagnostic Report" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "=========================" >> $REPORT_FILE

echo -e "\n=== System Information ===" >> $REPORT_FILE
uname -a >> $REPORT_FILE
cat /etc/os-release >> $REPORT_FILE

echo -e "\n=== Service Status ===" >> $REPORT_FILE
systemctl status anyproxy-gateway >> $REPORT_FILE 2>&1
systemctl status anyproxy-client >> $REPORT_FILE 2>&1

echo -e "\n=== Configuration ===" >> $REPORT_FILE
cat configs/config.yaml >> $REPORT_FILE 2>&1

echo -e "\n=== Recent Logs ===" >> $REPORT_FILE
journalctl -u anyproxy-gateway --since "1 hour ago" >> $REPORT_FILE 2>&1
journalctl -u anyproxy-client --since "1 hour ago" >> $REPORT_FILE 2>&1

echo -e "\n=== Network Status ===" >> $REPORT_FILE
netstat -tlnp | grep -E ':(8443|1080)' >> $REPORT_FILE 2>&1

echo "Diagnostic report saved to: $REPORT_FILE"
``` 