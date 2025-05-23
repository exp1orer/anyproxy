# AnyProxy 故障排除指南

## 概述

本文档提供了 AnyProxy 常见问题的诊断和解决方案，帮助用户快速定位和解决问题。

## 常见问题分类

### 1. 连接问题

#### 1.1 WebSocket 连接失败

**症状**：
- 客户端无法连接到网关
- 连接立即断开
- 连接超时

**可能原因**：
- 网络连通性问题
- 防火墙阻止连接
- TLS 证书问题
- 端口被占用

**诊断步骤**：

```bash
# 1. 检查网络连通性
ping gateway-host

# 2. 检查端口是否开放
telnet gateway-host 8443

# 3. 检查 TLS 连接
openssl s_client -connect gateway-host:8443

# 4. 检查端口占用
netstat -an | grep 8443
```

**解决方案**：

```bash
# 检查防火墙设置
sudo ufw status
sudo firewall-cmd --list-ports

# 开放端口
sudo ufw allow 8443/tcp
sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload

# 检查服务状态
sudo systemctl status anyproxy-gateway

# 重启服务
sudo systemctl restart anyproxy-gateway
```

#### 1.2 TLS 握手失败

**症状**：
- SSL/TLS 握手错误
- 证书验证失败
- 连接被重置

**可能原因**：
- 证书过期或无效
- 证书路径错误
- TLS 版本不兼容
- 时间同步问题

**诊断步骤**：

```bash
# 检查证书有效性
openssl x509 -in certs/server.crt -text -noout

# 检查证书过期时间
openssl x509 -in certs/server.crt -enddate -noout

# 检查系统时间
date
ntpdate -q pool.ntp.org
```

**解决方案**：

```bash
# 重新生成证书
bash generate_certs.sh your-domain.com

# 同步系统时间
sudo ntpdate pool.ntp.org

# 检查证书权限
ls -la certs/
sudo chown anyproxy:anyproxy certs/*
sudo chmod 600 certs/server.key
sudo chmod 644 certs/server.crt
```

### 2. 认证问题

#### 2.1 认证失败

**症状**：
- 客户端连接后立即断开
- 认证错误消息
- 无法通过 SOCKS5 认证

**可能原因**：
- 用户名密码错误
- 配置文件不匹配
- 特殊字符编码问题

**诊断步骤**：

```bash
# 检查配置文件
cat configs/config.yaml | grep -A5 -B5 auth

# 检查日志
sudo journalctl -u anyproxy-gateway | grep auth
sudo journalctl -u anyproxy-client | grep auth
```

**解决方案**：

```yaml
# 确保网关和客户端配置一致
gateway:
  auth_username: "same_username"
  auth_password: "same_password"

client:
  auth_username: "same_username"
  auth_password: "same_password"
```

### 3. 性能问题

#### 3.1 连接缓慢

**症状**：
- 建立连接时间过长
- 数据传输速度慢
- 高延迟

**可能原因**：
- 网络带宽限制
- 系统资源不足
- 配置参数不当

**诊断步骤**：

```bash
# 检查系统资源
top
free -h
iostat 1

# 检查网络状态
iftop
netstat -i

# 检查连接数
ss -s
```

**解决方案**：

```yaml
# 优化配置参数
client:
  replicas: 3                    # 增加客户端副本数
  max_concurrent_conns: 1000     # 增加最大并发连接数
```

```bash
# 系统优化
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p
```

#### 3.2 内存泄漏

**症状**：
- 内存使用持续增长
- 系统变慢
- 最终内存耗尽

**诊断步骤**：

```bash
# 监控内存使用
watch -n 1 'ps aux | grep anyproxy'

# 检查内存详情
pmap -d $(pgrep anyproxy-gateway)

# 使用 valgrind 检查（如果可用）
valgrind --tool=memcheck --leak-check=full ./bin/anyproxy-gateway
```

**解决方案**：

```bash
# 重启服务释放内存
sudo systemctl restart anyproxy-gateway anyproxy-client

# 设置内存限制
sudo systemctl edit anyproxy-gateway
# 添加：
# [Service]
# MemoryLimit=1G
```

### 4. 配置问题

#### 4.1 配置文件错误

**症状**：
- 服务启动失败
- 配置解析错误
- 功能异常

**诊断步骤**：

```bash
# 验证 YAML 语法
python3 -c "import yaml; yaml.safe_load(open('configs/config.yaml'))"

# 检查配置文件权限
ls -la configs/config.yaml

# 手动测试配置
./bin/anyproxy-gateway --config configs/config.yaml --dry-run
```

**解决方案**：

```bash
# 备份原配置
cp configs/config.yaml configs/config.yaml.backup

# 使用示例配置
cp configs/config.yaml.example configs/config.yaml

# 逐步修改配置并测试
```

#### 4.2 端口冲突

**症状**：
- 服务启动失败
- "地址已在使用"错误
- 端口绑定失败

**诊断步骤**：

```bash
# 检查端口占用
sudo netstat -tlnp | grep :8443
sudo lsof -i :8443

# 检查进程
ps aux | grep anyproxy
```

**解决方案**：

```bash
# 杀死占用端口的进程
sudo kill -9 $(lsof -t -i:8443)

# 或者修改配置使用其他端口
sed -i 's/:8443/:8444/g' configs/config.yaml
```

### 5. 网络问题

#### 5.1 DNS 解析失败

**症状**：
- 无法连接到目标主机
- DNS 查询超时
- 域名解析错误

**诊断步骤**：

```bash
# 测试 DNS 解析
nslookup target-host
dig target-host

# 检查 DNS 配置
cat /etc/resolv.conf

# 测试不同 DNS 服务器
nslookup target-host 8.8.8.8
```

**解决方案**：

```bash
# 修改 DNS 配置
echo 'nameserver 8.8.8.8' >> /etc/resolv.conf
echo 'nameserver 8.8.4.4' >> /etc/resolv.conf

# 清除 DNS 缓存
sudo systemctl restart systemd-resolved
```

#### 5.2 防火墙阻止

**症状**：
- 连接被拒绝
- 超时错误
- 部分功能不可用

**诊断步骤**：

```bash
# 检查 iptables 规则
sudo iptables -L -n

# 检查 ufw 状态
sudo ufw status verbose

# 检查 firewalld
sudo firewall-cmd --list-all
```

**解决方案**：

```bash
# UFW 配置
sudo ufw allow from any to any port 8443
sudo ufw allow from any to any port 1080

# firewalld 配置
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --permanent --add-port=1080/tcp
sudo firewall-cmd --reload

# iptables 配置
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 1080 -j ACCEPT
```

## 日志分析

### 日志位置

```bash
# systemd 日志
sudo journalctl -u anyproxy-gateway
sudo journalctl -u anyproxy-client

# 文件日志（如果配置）
tail -f /var/log/anyproxy/gateway.log
tail -f /var/log/anyproxy/client.log
```

### 常见错误消息

#### "connection refused"

```bash
# 检查服务状态
sudo systemctl status anyproxy-gateway

# 检查端口监听
sudo netstat -tlnp | grep anyproxy
```

#### "certificate verify failed"

```bash
# 检查证书
openssl verify certs/server.crt

# 重新生成证书
bash generate_certs.sh
```

#### "authentication failed"

```bash
# 检查配置
grep -r auth configs/

# 检查密码特殊字符
echo "password" | od -c
```

### 启用调试日志

```yaml
# 在配置文件中添加
logging:
  level: debug
  output: /var/log/anyproxy/debug.log
```

## 监控和诊断工具

### 系统监控

```bash
# 实时监控脚本
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

### 网络诊断

```bash
# 连接测试脚本
#!/bin/bash
HOST="gateway-host"
PORT="8443"

echo "Testing connection to $HOST:$PORT"

# TCP 连接测试
timeout 5 bash -c "</dev/tcp/$HOST/$PORT" && echo "TCP connection: OK" || echo "TCP connection: FAILED"

# TLS 连接测试
echo | timeout 5 openssl s_client -connect $HOST:$PORT 2>/dev/null && echo "TLS connection: OK" || echo "TLS connection: FAILED"

# WebSocket 测试（需要 wscat）
if command -v wscat >/dev/null; then
    timeout 5 wscat -c wss://$HOST:$PORT/ws --no-check && echo "WebSocket connection: OK" || echo "WebSocket connection: FAILED"
fi
```

### 性能测试

```bash
# 简单性能测试
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

## 恢复程序

### 服务恢复

```bash
#!/bin/bash
# 服务恢复脚本

echo "Starting AnyProxy recovery procedure..."

# 停止服务
sudo systemctl stop anyproxy-gateway anyproxy-client

# 检查进程
if pgrep anyproxy; then
    echo "Killing remaining processes..."
    sudo pkill -f anyproxy
    sleep 5
fi

# 清理临时文件
sudo rm -f /tmp/anyproxy-*

# 检查配置
if ! python3 -c "import yaml; yaml.safe_load(open('configs/config.yaml'))" 2>/dev/null; then
    echo "Configuration file is invalid, restoring backup..."
    sudo cp configs/config.yaml.backup configs/config.yaml
fi

# 检查证书
if ! openssl x509 -in certs/server.crt -noout 2>/dev/null; then
    echo "Certificate is invalid, regenerating..."
    bash generate_certs.sh
fi

# 重启服务
sudo systemctl start anyproxy-gateway
sleep 5
sudo systemctl start anyproxy-client

# 验证服务状态
if systemctl is-active --quiet anyproxy-gateway && systemctl is-active --quiet anyproxy-client; then
    echo "Recovery successful!"
else
    echo "Recovery failed, check logs:"
    sudo journalctl -u anyproxy-gateway --since "5 minutes ago"
    sudo journalctl -u anyproxy-client --since "5 minutes ago"
fi
```

### 配置恢复

```bash
#!/bin/bash
# 配置恢复脚本

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

## 预防措施

### 定期维护

```bash
# 添加到 crontab
# 每日备份配置
0 2 * * * /opt/anyproxy/backup.sh

# 每周重启服务
0 3 * * 0 systemctl restart anyproxy-gateway anyproxy-client

# 每月清理日志
0 4 1 * * find /var/log/anyproxy -name "*.log" -mtime +30 -delete
```

### 监控告警

```bash
#!/bin/bash
# 监控脚本，可配置为 cron 任务

ALERT_EMAIL="admin@example.com"

# 检查服务状态
if ! systemctl is-active --quiet anyproxy-gateway; then
    echo "AnyProxy Gateway is down!" | mail -s "AnyProxy Alert" $ALERT_EMAIL
fi

if ! systemctl is-active --quiet anyproxy-client; then
    echo "AnyProxy Client is down!" | mail -s "AnyProxy Alert" $ALERT_EMAIL
fi

# 检查内存使用
MEMORY_USAGE=$(ps -o %mem -C anyproxy-gateway --no-headers | awk '{sum+=$1} END {print sum}')
if (( $(echo "$MEMORY_USAGE > 80" | bc -l) )); then
    echo "High memory usage: ${MEMORY_USAGE}%" | mail -s "AnyProxy Memory Alert" $ALERT_EMAIL
fi
```

## 联系支持

如果以上解决方案都无法解决问题，请：

1. 收集相关日志和配置文件
2. 记录详细的错误信息和重现步骤
3. 提供系统环境信息
4. 在 GitHub 仓库创建 Issue 或联系技术支持

### 信息收集脚本

```bash
#!/bin/bash
# 收集诊断信息

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