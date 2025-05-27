# 双代理支持 (Dual Proxy Support)

AnyProxy 现在支持同时运行 HTTP/HTTPS 和 SOCKS5 代理服务器。

## 功能特性

- **HTTP/HTTPS 代理**: 支持标准的 HTTP 代理协议，包括 CONNECT 方法用于 HTTPS 隧道
- **SOCKS5 代理**: 支持 SOCKS5 协议
- **同时运行**: 可以同时启动两种代理类型
- **独立配置**: 每种代理类型都有独立的监听地址和认证配置
- **统一后端**: 两种代理都使用相同的 WebSocket 客户端连接池

## 配置说明

### 同时启动两种代理

```yaml
proxy:
  # HTTP 代理配置
  http:
    listen_addr: "0.0.0.0:8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  
  # SOCKS5 代理配置
  socks5:
    listen_addr: "0.0.0.0:1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
```

### 仅启动 HTTP 代理

```yaml
proxy:
  http:
    listen_addr: "0.0.0.0:8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  # socks5 部分留空或不配置 listen_addr
```

### 仅启动 SOCKS5 代理

```yaml
proxy:
  socks5:
    listen_addr: "0.0.0.0:1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
  # http 部分留空或不配置 listen_addr
```

## HTTP 代理功能

### 支持的方法

- **GET, POST, PUT, DELETE** 等标准 HTTP 方法
- **CONNECT** 方法用于 HTTPS 隧道

### 认证

HTTP 代理支持基本认证 (Basic Authentication):

```
Proxy-Authorization: Basic <base64(username:password)>
```

### 使用示例

```bash
# 使用 curl 通过 HTTP 代理访问网站
curl -x http://http_user:http_pass@localhost:8080 https://example.com

# 设置环境变量
export http_proxy=http://http_user:http_pass@localhost:8080
export https_proxy=http://http_user:http_pass@localhost:8080
```

## SOCKS5 代理功能

### 认证方法

- 无认证
- 用户名/密码认证

### 使用示例

```bash
# 使用 curl 通过 SOCKS5 代理
curl --socks5 socks_user:socks_pass@localhost:1080 https://example.com

# 设置环境变量
export ALL_PROXY=socks5://socks_user:socks_pass@localhost:1080
```

## 架构说明

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

## 日志输出

启动时会显示已创建的代理类型：

```
2025/05/27 16:05:08 Created HTTP proxy on 0.0.0.0:8080
2025/05/27 16:05:08 Created SOCKS5 proxy on 0.0.0.0:1080
```

## 错误处理

- 如果两种代理都没有配置 `listen_addr`，系统会返回错误
- 如果某个代理启动失败，已启动的代理会被停止
- 每种代理的错误都会独立记录

## 性能考虑

- 两种代理共享相同的客户端连接池
- 连接负载均衡在客户端级别进行
- 每种代理类型都有独立的监听端口，避免端口冲突

## 示例配置文件

完整的配置示例请参考 `examples/dual-proxy-config.yaml`。 