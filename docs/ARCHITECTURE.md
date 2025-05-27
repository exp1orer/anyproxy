# AnyProxy 架构设计

## 概述

AnyProxy 是一个基于 WebSocket + TLS 的反向代理系统，旨在安全地将内网服务暴露给公网用户。系统采用客户端主动连接的方式，避免了传统端口转发的安全风险。支持同时运行 HTTP/HTTPS 和 SOCKS5 代理服务。

## 系统架构

### 整体架构

```
┌─────────────┐  HTTP/SOCKS5  ┌─────────────┐    WebSocket+TLS    ┌─────────────┐    TCP/UDP    ┌─────────────┐
│ 公网用户     │ ──────────────→ │ 网关(Gateway) │ ──────────────────→ │ 客户端(Client) │ ──────────────→ │ 目标服务     │
│ (Internet)  │               │             │                    │             │               │ (LAN/WAN)   │
└─────────────┘               └─────────────┘                    └─────────────┘               └─────────────┘
```

### 双代理架构

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

## 核心组件

### 1. 网关 (Gateway)

网关是系统的核心组件，负责：

- **HTTP/HTTPS 代理服务**: 监听公网用户的 HTTP 代理连接请求
- **SOCKS5 代理服务**: 监听公网用户的 SOCKS5 连接请求
- **WebSocket 服务器**: 接受客户端的 WebSocket 连接
- **请求路由**: 将公网用户的请求路由到合适的客户端
- **负载均衡**: 在多个客户端之间分发请求
- **认证授权**: 验证客户端和用户的身份

#### 主要功能模块

```go
type Gateway struct {
    httpServer      *http.Server        // WebSocket 服务器
    proxies         []GatewayProxy      // 代理服务器列表 (HTTP + SOCKS5)
    clientManager   *ClientManager      // 客户端连接管理器
    config          *config.GatewayConfig
}
```

#### 工作流程

1. 根据配置启动 HTTP 和/或 SOCKS5 代理服务，监听公网用户连接
2. 启动 WebSocket 服务器，等待客户端连接
3. 当客户端连接时，进行 TLS 握手和身份验证
4. 当公网用户发起代理请求时，选择一个可用客户端
5. 通过 WebSocket 将请求转发给客户端
6. 将客户端的响应返回给公网用户

#### 双代理支持

网关现在支持同时运行多种代理类型：

**HTTP/HTTPS 代理**:
- 支持标准 HTTP 代理协议
- 支持 CONNECT 方法用于 HTTPS 隧道
- 支持基本认证 (Basic Authentication)
- 处理 HTTP 请求头和响应头

**SOCKS5 代理**:
- 支持 SOCKS5 协议标准
- 支持用户名/密码认证
- 支持 TCP 和 UDP 连接
- 兼容各种 SOCKS5 客户端

**配置灵活性**:
- 可以同时启动两种代理
- 可以只启动其中一种代理
- 每种代理有独立的监听端口和认证配置
- 共享相同的客户端连接池

### 2. 客户端 (Client)

客户端运行在内网环境中，负责：

- **主动连接**: 主动连接到网关的 WebSocket 服务器
- **请求处理**: 接收网关转发的请求并处理
- **服务访问**: 访问内网或公网的目标服务
- **访问控制**: 根据配置限制可访问的服务

#### 主要功能模块

```go
type ProxyClient struct {
    wsConn          *websocket.Conn     // WebSocket 连接
    connManager     *ConnectionManager  // 连接管理器
    config          *config.ClientConfig
}
```

#### 工作流程

1. 建立到网关的 WebSocket + TLS 连接
2. 进行身份验证
3. 监听网关发送的代理请求
4. 对每个请求建立到目标服务的连接
5. 在网关和目标服务之间转发数据
6. 处理连接关闭和错误情况

### 3. 连接管理

#### 连接包装器 (ConnectionWrapper)

```go
type ConnectionWrapper struct {
    ID          string
    Conn        net.Conn
    CreatedAt   time.Time
    LastActive  time.Time
}
```

负责：
- 连接生命周期管理
- 连接状态跟踪
- 超时处理

#### WebSocket 写入器 (WebSocketWriter)

```go
type WebSocketWriter struct {
    conn   *websocket.Conn
    connID string
    mu     sync.Mutex
}
```

负责：
- WebSocket 消息的安全写入
- 并发写入控制
- 错误处理

## 数据流

### 1. 客户端注册流程

```
Client                    Gateway
  │                         │
  │──── WebSocket Connect ──→│
  │                         │
  │←──── TLS Handshake ─────│
  │                         │
  │──── Auth Request ───────→│
  │                         │
  │←──── Auth Response ─────│
  │                         │
  │──── Keep Alive ─────────→│
```

### 2. 代理请求流程

#### HTTP 代理请求流程

```
User          Gateway         Client          Target
  │              │              │              │
  │─ HTTP ───────→│              │              │
  │              │─ WebSocket ──→│              │
  │              │              │─ HTTP/HTTPS ─→│
  │              │              │←─ Response ──│
  │              │←─ WebSocket ──│              │
  │←─ HTTP ──────│              │              │
```

#### SOCKS5 代理请求流程

```
User          Gateway         Client          Target
  │              │              │              │
  │─ SOCKS5 ─────→│              │              │
  │              │─ WebSocket ──→│              │
  │              │              │─ TCP/UDP ────→│
  │              │              │←─ Response ──│
  │              │←─ WebSocket ──│              │
  │←─ SOCKS5 ────│              │              │
```

## 安全机制

### 1. 传输安全

- **TLS 加密**: 所有 WebSocket 连接使用 TLS 1.2+ 加密
- **证书验证**: 客户端验证网关的 TLS 证书
- **双向认证**: 支持客户端证书认证（可选）

### 2. 身份认证

- **用户名密码**: 基于用户名密码的认证机制
- **HTTP 代理认证**: 支持 HTTP 代理的基本认证 (Basic Authentication)
- **SOCKS5 认证**: 支持 SOCKS5 协议的用户认证
- **客户端认证**: 客户端连接网关时的身份验证
- **独立认证**: 每种代理类型可配置独立的认证信息

### 3. 访问控制

- **黑名单**: 禁止访问特定主机或IP段
- **白名单**: 仅允许访问配置的服务列表
- **协议限制**: 限制可使用的协议类型（TCP/UDP）

## 配置管理

### 配置结构

```go
type Config struct {
    Proxy   ProxyConfig   `yaml:"proxy"`
    Gateway GatewayConfig `yaml:"gateway"`
    Client  ClientConfig  `yaml:"client"`
}

type ProxyConfig struct {
    HTTP   HTTPConfig   `yaml:"http"`
    SOCKS5 SOCKS5Config `yaml:"socks5"`
}

type HTTPConfig struct {
    ListenAddr   string `yaml:"listen_addr"`
    AuthUsername string `yaml:"auth_username"`
    AuthPassword string `yaml:"auth_password"`
}

type SOCKS5Config struct {
    ListenAddr   string `yaml:"listen_addr"`
    AuthUsername string `yaml:"auth_username"`
    AuthPassword string `yaml:"auth_password"`
}
```

### 配置热重载

- 支持配置文件的热重载
- 无需重启服务即可应用新配置
- 配置变更的平滑过渡

## 性能优化

### 1. 连接池

- 复用 WebSocket 连接
- 连接池大小可配置
- 自动清理空闲连接

### 2. 并发控制

- 限制最大并发连接数
- 请求队列管理
- 背压控制机制

### 3. 内存管理

- 缓冲区复用
- 及时释放资源
- 内存使用监控

## 监控和日志

### 1. 日志记录

- 结构化日志输出
- 不同级别的日志记录
- 敏感信息脱敏

### 2. 指标监控

- 连接数统计
- 请求响应时间
- 错误率监控
- 流量统计

## 扩展性

### 1. 水平扩展

- 支持多个网关实例
- 客户端自动重连
- 负载均衡策略

### 2. 协议扩展

- 插件化的协议支持
- 自定义协议处理器
- 协议转换能力

## 故障处理

### 1. 连接恢复

- 自动重连机制
- 指数退避策略
- 连接健康检查

### 2. 错误处理

- 优雅的错误处理
- 错误信息传播
- 故障隔离机制 