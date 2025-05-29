# AnyProxy Deployment Guide

## Overview

This document provides a deployment guide for AnyProxy in production environments, including system requirements, installation steps, configuration optimization, and operational recommendations.

## System Requirements

### Hardware Requirements

#### Gateway Server
- **CPU**: 2+ cores
- **Memory**: 2GB+
- **Network**: Public IP, bandwidth determined by expected traffic
- **Storage**: 10GB+ available space

#### Client Server
- **CPU**: 1+ core
- **Memory**: 1GB+
- **Network**: Able to access gateway server
- **Storage**: 5GB+ available space

### Software Requirements

- **Operating System**: Linux (Ubuntu 20.04+, CentOS 7+, RHEL 8+)
- **Go**: 1.21 or higher
- **OpenSSL**: For generating TLS certificates
- **Firewall**: Configure appropriate port openings

## Deployment Architecture

### Single Node Deployment

```
Internet ──→ [Gateway + SOCKS5] ──→ [Client] ──→ Internal Services
```

Suitable for:
- Small-scale deployments
- Test environments
- Personal use

### Distributed Deployment

```
Internet ──→ [Load Balancer] ──→ [Gateway Cluster] ──→ [Client Cluster] ──→ Internal Services
```

Suitable for:
- Production environments
- High availability requirements
- Large-scale deployments

## Installation Steps

### 1. Environment Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install necessary tools
sudo apt install -y git build-essential openssl

# Install Go (if not installed)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. Download and Build

```bash
# Clone project
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# Build project
make build

# Generate certificates
make certs
```

### 3. Configuration Files

#### Production Environment Configuration Example

```yaml
# configs/production.yaml
proxy:
  socks5:
    listen_addr: ":1080"
    auth_username: "proxy_user"
    auth_password: "secure_proxy_password"

gateway:
  listen_addr: ":8443"
  tls_cert: "/etc/anyproxy/certs/server.crt"
  tls_key: "/etc/anyproxy/certs/server.key"
  auth_username: "gateway_user"
  auth_password: "secure_gateway_password"

client:
  gateway_addr: "your-gateway-domain.com:8443"
  gateway_tls_cert: "/etc/anyproxy/certs/server.crt"
  client_id: "production-client"
  replicas: 3
  max_concurrent_conns: 1000
  auth_username: "gateway_user"
  auth_password: "secure_gateway_password"
  forbidden_hosts:
    - "localhost"
    - "127.0.0.1"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
  limit:
    - name: "web-service"
      addr: "internal-web:80"
      protocol: "tcp"
    - name: "api-service"
      addr: "internal-api:8080"
      protocol: "tcp"
```

### 4. Certificate Configuration

#### Using Let's Encrypt Certificates

```bash
# Install certbot
sudo apt install -y certbot

# Obtain certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificate to project directory
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/anyproxy/certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/anyproxy/certs/server.key
sudo chown anyproxy:anyproxy /etc/anyproxy/certs/*
```

#### Using Self-Signed Certificates

```bash
# Generate self-signed certificate
bash generate_certs.sh your-domain.com

# Move certificates to system directory
sudo mkdir -p /etc/anyproxy/certs
sudo cp certs/* /etc/anyproxy/certs/
```

## System Service Configuration

### 1. Create System User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false anyproxy
sudo mkdir -p /opt/anyproxy
sudo mkdir -p /etc/anyproxy
sudo mkdir -p /var/log/anyproxy
sudo chown -R anyproxy:anyproxy /opt/anyproxy /etc/anyproxy /var/log/anyproxy
```

### 2. Install Binary Files

```bash
# Copy binary files
sudo cp bin/anyproxy-gateway /opt/anyproxy/
sudo cp bin/anyproxy-client /opt/anyproxy/
sudo chmod +x /opt/anyproxy/*

# Copy configuration files
sudo cp configs/production.yaml /etc/anyproxy/config.yaml
```

### 3. Create systemd Services

#### Gateway Service

```bash
# Create gateway service file
sudo tee /etc/systemd/system/anyproxy-gateway.service > /dev/null <<EOF
[Unit]
Description=AnyProxy Gateway
After=network.target

[Service]
Type=simple
User=anyproxy
Group=anyproxy
ExecStart=/opt/anyproxy/anyproxy-gateway --config /etc/anyproxy/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=anyproxy-gateway

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy

[Install]
WantedBy=multi-user.target
EOF
```

#### Client Service

```bash
# Create client service file
sudo tee /etc/systemd/system/anyproxy-client.service > /dev/null <<EOF
[Unit]
Description=AnyProxy Client
After=network.target

[Service]
Type=simple
User=anyproxy
Group=anyproxy
ExecStart=/opt/anyproxy/anyproxy-client --config /etc/anyproxy/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=anyproxy-client

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy

[Install]
WantedBy=multi-user.target
EOF
```

### 4. Start Services

```bash
# Reload systemd
sudo systemctl daemon-reload

# Start and enable services
sudo systemctl enable anyproxy-gateway
sudo systemctl start anyproxy-gateway

sudo systemctl enable anyproxy-client
sudo systemctl start anyproxy-client

# Check service status
sudo systemctl status anyproxy-gateway
sudo systemctl status anyproxy-client
```

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Allow gateway ports
sudo ufw allow 8443/tcp comment 'AnyProxy Gateway'
sudo ufw allow 1080/tcp comment 'SOCKS5 Proxy'

# Enable firewall
sudo ufw enable
```

### firewalld (CentOS/RHEL)

```bash
# Allow gateway ports
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=1080/tcp
sudo firewall-cmd --reload
```

## Load Balancer Configuration

### Nginx Load Balancing

```nginx
# /etc/nginx/sites-available/anyproxy
upstream anyproxy_gateway {
    server 10.0.1.10:8443;
    server 10.0.1.11:8443;
    server 10.0.1.12:8443;
}

server {
    listen 443 ssl;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass https://anyproxy_gateway;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Monitoring and Logging

### 1. Log Configuration

```bash
# Configure rsyslog
sudo tee /etc/rsyslog.d/anyproxy.conf > /dev/null <<EOF
if \$programname == 'anyproxy-gateway' then /var/log/anyproxy/gateway.log
if \$programname == 'anyproxy-client' then /var/log/anyproxy/client.log
& stop
EOF

# Restart rsyslog
sudo systemctl restart rsyslog
```

### 2. Log Rotation

```bash
# Configure logrotate
sudo tee /etc/logrotate.d/anyproxy > /dev/null <<EOF
/var/log/anyproxy/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 anyproxy anyproxy
    postrotate
        systemctl reload anyproxy-gateway anyproxy-client
    endscript
}
EOF
```

### 3. Monitoring Script

```bash
#!/bin/bash
# /opt/anyproxy/monitor.sh

# Check service status
check_service() {
    local service=$1
    if ! systemctl is-active --quiet $service; then
        echo "$(date): $service is not running, attempting to restart..."
        systemctl restart $service
        sleep 5
        if systemctl is-active --quiet $service; then
            echo "$(date): $service restarted successfully"
        else
            echo "$(date): Failed to restart $service"
        fi
    fi
}

check_service anyproxy-gateway
check_service anyproxy-client
```

```bash
# Add to crontab
echo "*/5 * * * * /opt/anyproxy/monitor.sh >> /var/log/anyproxy/monitor.log 2>&1" | sudo crontab -u anyproxy -
```

## Performance Optimization

### 1. System Parameter Tuning

```bash
# Increase file descriptor limits
echo "anyproxy soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "anyproxy hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# Network parameter optimization
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# Increase network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 1048576

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1
EOF

sudo sysctl -p
```

### 2. Application Configuration Optimization

```yaml
# High performance configuration example
client:
  replicas: 5
  max_concurrent_conns: 2000
  # Other configurations...
```

## Security Hardening

### 1. System Security

```bash
# Disable unnecessary services
sudo systemctl disable apache2 nginx mysql

# Update system
sudo apt update && sudo apt upgrade -y

# Install security updates
sudo unattended-upgrades
```

### 2. Network Security

```bash
# Restrict SSH access
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### 3. Application Security

- Use strong passwords
- Regularly rotate authentication credentials
- Enable access logging
- Configure appropriate access control lists

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check firewall settings
   - Verify services are running
   - Check if ports are occupied

2. **TLS Handshake Failure**
   - Verify certificate validity
   - Check certificate paths
   - Ensure time synchronization

3. **Authentication Failure**
   - Check username and password
   - Verify configuration files
   - Review authentication logs

### Log Analysis

```bash
# View real-time logs
sudo journalctl -u anyproxy-gateway -f
sudo journalctl -u anyproxy-client -f

# View error logs
sudo journalctl -u anyproxy-gateway --since "1 hour ago" | grep ERROR
```

## Backup and Recovery

### Backup

```bash
#!/bin/bash
# Backup script
BACKUP_DIR="/backup/anyproxy/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configuration files
cp -r /etc/anyproxy $BACKUP_DIR/
cp -r /opt/anyproxy $BACKUP_DIR/

# Backup certificates
cp -r /etc/anyproxy/certs $BACKUP_DIR/

# Create compressed archive
tar -czf $BACKUP_DIR.tar.gz -C /backup/anyproxy $(basename $BACKUP_DIR)
```

### Recovery

```bash
#!/bin/bash
# Recovery script
BACKUP_FILE="/backup/anyproxy/20240115.tar.gz"

# Stop services
sudo systemctl stop anyproxy-gateway anyproxy-client

# Extract backup
tar -xzf $BACKUP_FILE -C /tmp/

# Restore files
sudo cp -r /tmp/anyproxy/* /etc/anyproxy/
sudo cp -r /tmp/anyproxy/* /opt/anyproxy/

# Set permissions
sudo chown -R anyproxy:anyproxy /etc/anyproxy /opt/anyproxy

# Start services
sudo systemctl start anyproxy-gateway anyproxy-client
```

## High Availability Setup

### 1. Database Clustering (if applicable)

```bash
# For future database requirements
# Configure database replication
# Set up failover mechanisms
```

### 2. Gateway Clustering

```yaml
# Multiple gateway instances
gateway_cluster:
  - host: gateway1.example.com:8443
  - host: gateway2.example.com:8443
  - host: gateway3.example.com:8443
```

### 3. Health Checks

```bash
#!/bin/bash
# Health check script
check_health() {
    local endpoint=$1
    local response=$(curl -s -o /dev/null -w "%{http_code}" $endpoint)
    if [ "$response" = "200" ]; then
        echo "OK"
    else
        echo "FAIL"
    fi
}

# Check gateway health
check_health "https://your-domain.com:8443/health"
```

## Maintenance Procedures

### 1. Regular Updates

```bash
#!/bin/bash
# Update script
cd /opt/anyproxy/source
git pull origin main
make build

# Stop services
sudo systemctl stop anyproxy-gateway anyproxy-client

# Update binaries
sudo cp bin/* /opt/anyproxy/

# Start services
sudo systemctl start anyproxy-gateway anyproxy-client
```

### 2. Certificate Renewal

```bash
#!/bin/bash
# Certificate renewal script
sudo certbot renew --quiet

# Copy new certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/anyproxy/certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/anyproxy/certs/server.key

# Restart services
sudo systemctl restart anyproxy-gateway
```

### 3. Log Cleanup

```bash
#!/bin/bash
# Log cleanup script
find /var/log/anyproxy -name "*.log" -mtime +30 -delete
find /var/log/anyproxy -name "*.gz" -mtime +90 -delete
```

## Monitoring Integration

### 1. Prometheus Metrics

```yaml
# Add to configuration
monitoring:
  prometheus:
    enabled: true
    port: 9090
    path: /metrics
```

### 2. Grafana Dashboard

```json
{
  "dashboard": {
    "title": "AnyProxy Monitoring",
    "panels": [
      {
        "title": "Active Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "anyproxy_active_connections"
          }
        ]
      }
    ]
  }
}
```

### 3. Alerting Rules

```yaml
# Prometheus alerting rules
groups:
  - name: anyproxy
    rules:
      - alert: AnyProxyDown
        expr: up{job="anyproxy"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "AnyProxy instance is down"
``` 