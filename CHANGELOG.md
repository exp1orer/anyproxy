# 更新日志 (Changelog)

## [v1.1.0] - 2025-05-27

### 🚀 新功能 (New Features)

- **双代理支持**: 新增同时支持 HTTP/HTTPS 和 SOCKS5 代理服务
- **HTTP/HTTPS 代理**: 实现完整的 HTTP 代理协议支持
  - 支持标准 HTTP 方法 (GET, POST, PUT, DELETE 等)
  - 支持 CONNECT 方法用于 HTTPS 隧道
  - 支持基本认证 (Basic Authentication)
  - 支持 HTTP 请求头和响应头处理
- **灵活配置**: 支持同时启动或单独启动任一代理类型
- **独立认证**: 每种代理类型可配置独立的认证信息
- **统一后端**: 两种代理共享相同的 WebSocket 客户端连接池

### 🔧 改进 (Improvements)

- **Gateway 架构重构**: 支持多代理实例管理
- **配置系统增强**: 新增 HTTP 代理配置选项
- **错误处理优化**: 改进代理启动失败时的错误处理
- **日志系统完善**: 添加代理类型识别和状态日志

### 📚 文档更新 (Documentation)

- 更新 README.md 包含双代理功能说明
- 新增 `docs/DUAL_PROXY.md` 详细功能文档
- 更新 `docs/ARCHITECTURE.md` 架构设计文档
- 更新 `docs/API.md` API 使用文档
- 新增示例配置文件 `examples/dual-proxy-config.yaml`
- **新增 `docs/HTTP_PROXY_TROUBLESHOOTING.md` HTTP 代理故障排除指南**

### 🧪 测试 (Testing)

- 新增 HTTP 代理功能测试
- **新增 HTTP CONNECT 方法专项测试**
- **新增 HTTP 代理认证测试**
- 新增 Gateway 多代理管理测试
- 新增配置验证测试
- 所有现有功能回归测试通过

### 📋 配置变更 (Configuration Changes)

#### 新增配置项

```yaml
proxy:
  # HTTP 代理配置 (新增)
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  
  # SOCKS5 代理配置 (保持兼容)
  socks5:
    listen_addr: ":1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
```

#### 配置兼容性

- ✅ 现有 SOCKS5 配置完全兼容
- ✅ 可选择性启用 HTTP 代理
- ✅ 支持同时启用两种代理

### 🔄 迁移指南 (Migration Guide)

#### 从 v1.0.x 升级

1. **无需修改现有配置**: 现有的 SOCKS5 配置将继续正常工作
2. **可选添加 HTTP 代理**: 在配置文件中添加 `proxy.http` 部分即可启用 HTTP 代理
3. **重启服务**: 重启 Gateway 服务以应用新配置

#### 示例迁移

**旧配置 (v1.0.x)**:
```yaml
proxy:
  socks5:
    listen_addr: ":1080"
    auth_username: "user"
    auth_password: "pass"
```

**新配置 (v1.1.0)** - 保持兼容:
```yaml
proxy:
  socks5:
    listen_addr: ":1080"
    auth_username: "user"
    auth_password: "pass"
```

**新配置 (v1.1.0)** - 启用双代理:
```yaml
proxy:
  http:
    listen_addr: ":8080"
    auth_username: "http_user"
    auth_password: "http_pass"
  socks5:
    listen_addr: ":1080"
    auth_username: "socks_user"
    auth_password: "socks_pass"
```

### 🐛 修复 (Bug Fixes)

- **修复 HTTP CONNECT 隧道问题**: 解决 `ERR_TUNNEL_CONNECTION_FAILED` 错误
  - 修复 CONNECT 方法的响应处理顺序
  - 改进连接劫持和隧道建立流程
  - 添加缓冲数据处理逻辑
- 修复 Gateway 停止时的资源清理问题
- 改进 WebSocket 连接的错误处理
- 优化内存使用和连接管理

### ⚠️ 破坏性变更 (Breaking Changes)

无破坏性变更。此版本完全向后兼容。

---

## [v1.0.0] - 2025-05-20

### 🚀 初始版本 (Initial Release)

- **SOCKS5 代理**: 基础 SOCKS5 代理功能
- **WebSocket 通信**: 基于 WebSocket + TLS 的客户端-网关通信
- **安全连接**: TLS 加密和身份认证
- **负载均衡**: 多客户端连接支持
- **访问控制**: 黑白名单机制
- **配置管理**: YAML 配置文件支持 