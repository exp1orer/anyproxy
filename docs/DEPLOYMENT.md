# AnyProxy 部署指南

## 概述

本文档提供了 AnyProxy 在生产环境中的部署指南，包括系统要求、安装步骤、配置优化和运维建议。

## 系统要求

### 硬件要求

#### 网关服务器
- **CPU**: 2核心以上
- **内存**: 2GB 以上
- **网络**: 公网IP，带宽根据预期流量确定
- **存储**: 10GB 以上可用空间

#### 客户端服务器
- **CPU**: 1核心以上
- **内存**: 1GB 以上
- **网络**: 能够访问网关服务器
- **存储**: 5GB 以上可用空间

### 软件要求

- **操作系统**: Linux (Ubuntu 20.04+, CentOS 7+, RHEL 8+)
- **Go**: 1.21 或更高版本
- **OpenSSL**: 用于生成 TLS 证书
- **防火墙**: 配置相应端口开放

## 部署架构

### 单节点部署

```
Internet ──→ [Gateway + SOCKS5] ──→ [Client] ──→ Internal Services
```

适用于：
- 小规模部署
- 测试环境
- 个人使用

### 分布式部署

```
Internet ──→ [Load Balancer] ──→ [Gateway Cluster] ──→ [Client Cluster] ──→ Internal Services
```

适用于：
- 生产环境
- 高可用需求
- 大规模部署

## 安装步骤

### 1. 准备环境

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装必要工具
sudo apt install -y git build-essential openssl

# 安装 Go (如果未安装)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### 2. 下载和构建

```bash
# 克隆项目
git clone https://github.com/buhuipao/anyproxy.git
cd anyproxy

# 构建项目
make build

# 生成证书
make certs
```

### 3. 配置文件

#### 生产环境配置示例

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

### 4. 证书配置

#### 使用 Let's Encrypt 证书

```bash
# 安装 certbot
sudo apt install -y certbot

# 获取证书
sudo certbot certonly --standalone -d your-domain.com

# 复制证书到项目目录
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /etc/anyproxy/certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /etc/anyproxy/certs/server.key
sudo chown anyproxy:anyproxy /etc/anyproxy/certs/*
```

#### 使用自签名证书

```bash
# 生成自签名证书
bash generate_certs.sh your-domain.com

# 移动证书到系统目录
sudo mkdir -p /etc/anyproxy/certs
sudo cp certs/* /etc/anyproxy/certs/
```

## 系统服务配置

### 1. 创建系统用户

```bash
# 创建专用用户
sudo useradd -r -s /bin/false anyproxy
sudo mkdir -p /opt/anyproxy
sudo mkdir -p /etc/anyproxy
sudo mkdir -p /var/log/anyproxy
sudo chown -R anyproxy:anyproxy /opt/anyproxy /etc/anyproxy /var/log/anyproxy
```

### 2. 安装二进制文件

```bash
# 复制二进制文件
sudo cp bin/anyproxy-gateway /opt/anyproxy/
sudo cp bin/anyproxy-client /opt/anyproxy/
sudo chmod +x /opt/anyproxy/*

# 复制配置文件
sudo cp configs/production.yaml /etc/anyproxy/config.yaml
```

### 3. 创建 systemd 服务

#### 网关服务

```bash
# 创建网关服务文件
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

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy

[Install]
WantedBy=multi-user.target
EOF
```

#### 客户端服务

```bash
# 创建客户端服务文件
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

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy

[Install]
WantedBy=multi-user.target
EOF
```

### 4. 启动服务

```bash
# 重新加载 systemd
sudo systemctl daemon-reload

# 启动并启用服务
sudo systemctl enable anyproxy-gateway
sudo systemctl start anyproxy-gateway

sudo systemctl enable anyproxy-client
sudo systemctl start anyproxy-client

# 检查服务状态
sudo systemctl status anyproxy-gateway
sudo systemctl status anyproxy-client
```

## 防火墙配置

### UFW (Ubuntu)

```bash
# 允许网关端口
sudo ufw allow 8443/tcp comment 'AnyProxy Gateway'
sudo ufw allow 1080/tcp comment 'SOCKS5 Proxy'

# 启用防火墙
sudo ufw enable
```

### firewalld (CentOS/RHEL)

```bash
# 允许网关端口
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=1080/tcp
sudo firewall-cmd --reload
```

## 负载均衡配置

### Nginx 负载均衡

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

## 监控和日志

### 1. 日志配置

```bash
# 配置 rsyslog
sudo tee /etc/rsyslog.d/anyproxy.conf > /dev/null <<EOF
if \$programname == 'anyproxy-gateway' then /var/log/anyproxy/gateway.log
if \$programname == 'anyproxy-client' then /var/log/anyproxy/client.log
& stop
EOF

# 重启 rsyslog
sudo systemctl restart rsyslog
```

### 2. 日志轮转

```bash
# 配置 logrotate
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

### 3. 监控脚本

```bash
#!/bin/bash
# /opt/anyproxy/monitor.sh

# 检查服务状态
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
# 添加到 crontab
echo "*/5 * * * * /opt/anyproxy/monitor.sh >> /var/log/anyproxy/monitor.log 2>&1" | sudo crontab -u anyproxy -
```

## 性能优化

### 1. 系统参数调优

```bash
# 增加文件描述符限制
echo "anyproxy soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "anyproxy hard nofile 65536" | sudo tee -a /etc/security/limits.conf

# 网络参数优化
sudo tee -a /etc/sysctl.conf > /dev/null <<EOF
# 增加网络缓冲区
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# 增加连接跟踪表大小
net.netfilter.nf_conntrack_max = 1048576

# 启用 TCP 窗口缩放
net.ipv4.tcp_window_scaling = 1
EOF

sudo sysctl -p
```

### 2. 应用配置优化

```yaml
# 高性能配置示例
client:
  replicas: 5
  max_concurrent_conns: 2000
  # 其他配置...
```

## 安全加固

### 1. 系统安全

```bash
# 禁用不必要的服务
sudo systemctl disable apache2 nginx mysql

# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装安全更新
sudo unattended-upgrades
```

### 2. 网络安全

```bash
# 限制 SSH 访问
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart ssh
```

### 3. 应用安全

- 使用强密码
- 定期更换认证凭据
- 启用访问日志
- 配置适当的访问控制列表

## 故障排除

### 常见问题

1. **连接被拒绝**
   - 检查防火墙设置
   - 验证服务是否运行
   - 检查端口是否被占用

2. **TLS 握手失败**
   - 验证证书有效性
   - 检查证书路径
   - 确认时间同步

3. **认证失败**
   - 检查用户名密码
   - 验证配置文件
   - 查看认证日志

### 日志分析

```bash
# 查看实时日志
sudo journalctl -u anyproxy-gateway -f
sudo journalctl -u anyproxy-client -f

# 查看错误日志
sudo journalctl -u anyproxy-gateway --since "1 hour ago" | grep ERROR
```

## 备份和恢复

### 备份

```bash
#!/bin/bash
# 备份脚本
BACKUP_DIR="/backup/anyproxy/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# 备份配置文件
cp -r /etc/anyproxy $BACKUP_DIR/
cp -r /opt/anyproxy $BACKUP_DIR/

# 备份证书
cp -r /etc/anyproxy/certs $BACKUP_DIR/

# 创建压缩包
tar -czf $BACKUP_DIR.tar.gz -C /backup/anyproxy $(basename $BACKUP_DIR)
```

### 恢复

```bash
#!/bin/bash
# 恢复脚本
BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file.tar.gz>"
    exit 1
fi

# 停止服务
sudo systemctl stop anyproxy-gateway anyproxy-client

# 恢复文件
sudo tar -xzf $BACKUP_FILE -C /

# 设置权限
sudo chown -R anyproxy:anyproxy /etc/anyproxy /opt/anyproxy

# 启动服务
sudo systemctl start anyproxy-gateway anyproxy-client
``` 