# HTTP 代理故障排除指南

## 常见错误和解决方案

### 1. ERR_TUNNEL_CONNECTION_FAILED

**错误描述**: 
```
This site can't be reached
The webpage at https://example.com/ might be temporarily down or it may have moved permanently to a new web address.
ERR_TUNNEL_CONNECTION_FAILED
```

**原因分析**:
- HTTPS CONNECT 隧道建立失败
- 代理服务器无法连接到目标服务器
- 代理服务器配置错误

**解决方案**:

#### 1.1 检查代理配置

确保 HTTP 代理正确配置：

```yaml
proxy:
  http:
    listen_addr: "0.0.0.0:8080"  # 确保端口正确
    auth_username: "your_user"   # 可选
    auth_password: "your_pass"   # 可选
```

#### 1.2 检查客户端连接

确保至少有一个客户端连接到网关：

```bash
# 查看网关日志，应该看到类似信息：
# Client connected: client-001
```

#### 1.3 检查网络连通性

测试代理服务器是否可达：

```bash
# 测试代理端口是否开放
telnet your-proxy-server 8080

# 测试简单的 HTTP 请求
curl -v -x http://your-proxy-server:8080 http://httpbin.org/ip
```

#### 1.4 检查目标服务器

确保目标服务器可以从客户端访问：

```bash
# 在客户端机器上测试
curl -v https://www.bilibili.com/
```

### 2. 407 Proxy Authentication Required

**错误描述**:
```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Proxy"
```

**解决方案**:

#### 2.1 提供正确的认证信息

```bash
# 使用用户名密码
curl -x http://username:password@proxy-server:8080 https://example.com

# 或设置环境变量
export http_proxy=http://username:password@proxy-server:8080
export https_proxy=http://username:password@proxy-server:8080
```

#### 2.2 浏览器配置

在浏览器代理设置中：
- 代理类型: HTTP
- 代理地址: your-proxy-server
- 代理端口: 8080
- 用户名: your_username
- 密码: your_password

### 3. 502 Bad Gateway

**错误描述**:
```
HTTP/1.1 502 Bad Gateway
```

**原因分析**:
- 代理无法连接到目标服务器
- 客户端连接断开
- 网络路由问题

**解决方案**:

#### 3.1 检查客户端状态

```bash
# 查看网关日志
tail -f gateway.log

# 应该看到客户端连接信息
# Client connected: client-001
```

#### 3.2 检查目标服务器可达性

```bash
# 在客户端机器上测试
ping target-server.com
telnet target-server.com 443
```

#### 3.3 检查防火墙设置

确保客户端可以访问目标服务器：
- 检查出站防火墙规则
- 检查网络策略
- 检查 DNS 解析

### 4. 连接超时

**错误描述**:
```
curl: (7) Failed to connect to proxy-server port 8080: Connection timed out
```

**解决方案**:

#### 4.1 检查代理服务器状态

```bash
# 检查代理进程是否运行
ps aux | grep anyproxy

# 检查端口监听
netstat -tlnp | grep 8080
```

#### 4.2 检查网络连通性

```bash
# 测试网络连接
ping proxy-server
traceroute proxy-server
```

#### 4.3 检查防火墙

```bash
# 检查防火墙规则
iptables -L
ufw status

# 开放代理端口
ufw allow 8080
```

## 调试技巧

### 1. 启用详细日志

在配置文件中启用调试日志：

```yaml
log:
  level: debug
  format: json
```

### 2. 使用 curl 测试

```bash
# 测试 HTTP 请求
curl -v -x http://proxy:8080 http://httpbin.org/ip

# 测试 HTTPS 请求
curl -v -x http://proxy:8080 https://httpbin.org/ip

# 测试带认证的请求
curl -v -x http://user:pass@proxy:8080 https://httpbin.org/ip
```

### 3. 使用 openssl 测试 HTTPS

```bash
# 通过代理测试 HTTPS 连接
openssl s_client -connect httpbin.org:443 -proxy proxy:8080
```

### 4. 网络抓包

```bash
# 使用 tcpdump 抓包分析
tcpdump -i any -w proxy-debug.pcap port 8080

# 使用 wireshark 分析抓包文件
wireshark proxy-debug.pcap
```

## 性能优化

### 1. 调整超时设置

```yaml
proxy:
  http:
    read_timeout: 30s
    write_timeout: 30s
    idle_timeout: 60s
```

### 2. 调整缓冲区大小

```go
// 在代码中调整缓冲区大小
buffer := make([]byte, 64*1024) // 64KB buffer
```

### 3. 连接池优化

```yaml
client:
  max_concurrent_conns: 200
  keep_alive_timeout: 30s
```

## 监控和告警

### 1. 关键指标

- 代理连接数
- 请求成功率
- 响应时间
- 错误率

### 2. 日志监控

```bash
# 监控错误日志
tail -f gateway.log | grep ERROR

# 统计连接数
grep "Client connected" gateway.log | wc -l
```

### 3. 健康检查

```bash
# 创建健康检查脚本
#!/bin/bash
curl -f -x http://proxy:8080 http://httpbin.org/status/200
if [ $? -eq 0 ]; then
    echo "Proxy is healthy"
else
    echo "Proxy is unhealthy"
    exit 1
fi
```

## 常见配置错误

### 1. 端口冲突

```bash
# 检查端口占用
lsof -i :8080
netstat -tlnp | grep 8080
```

### 2. 权限问题

```bash
# 确保有权限绑定端口
# 对于 < 1024 的端口需要 root 权限
sudo ./anyproxy-gateway
```

### 3. 配置文件格式错误

```bash
# 验证 YAML 格式
yamllint config.yaml

# 检查配置文件语法
./anyproxy-gateway --config config.yaml --check-config
```

## 联系支持

如果问题仍然存在，请提供以下信息：

1. 错误信息的完整日志
2. 代理配置文件
3. 网络拓扑图
4. 客户端和服务器的操作系统版本
5. 重现问题的详细步骤

提交 Issue 到: https://github.com/buhuipao/anyproxy/issues 