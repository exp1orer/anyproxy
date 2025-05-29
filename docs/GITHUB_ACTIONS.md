# GitHub Actions 自动化构建指南

本文档介绍如何使用 AnyProxy 项目的 GitHub Actions 自动化构建和发布流程。

## 🚀 功能概述

我们为 AnyProxy 项目配置了两个主要的 GitHub Actions 工作流：

### 1. CI 工作流 (`.github/workflows/ci.yml`)
- **触发条件**: 推送到 `main`/`develop` 分支或创建 PR
- **功能**: 代码质量检查、测试、基础构建
- **运行时间**: 约 3-5 分钟

### 2. 构建和发布工作流 (`.github/workflows/build-and-release.yml`)
- **触发条件**: 推送到 `main`/`develop` 分支或创建标签
- **功能**: 多平台构建、Docker 镜像、自动发布
- **运行时间**: 约 10-15 分钟

## 📋 工作流详情

### CI 工作流包含的任务

1. **代码检查**
   - Go 代码格式化检查
   - golangci-lint 静态分析
   - go vet 代码检查

2. **测试**
   - 单元测试 (Go 1.21 和 1.22)
   - 代码覆盖率报告
   - 测试结果上传

3. **构建验证**
   - Linux AMD64 平台构建
   - 二进制文件验证
   - Docker 镜像构建测试

### 构建和发布工作流包含的任务

1. **多平台构建**
   - Linux (AMD64, ARM64)
   - Windows (AMD64)
   - macOS (AMD64, ARM64)

2. **Docker 镜像**
   - 多架构镜像构建 (AMD64, ARM64)
   - 自动推送到 Docker Hub (需配置密钥)

3. **自动发布**
   - 创建 GitHub Release
   - 上传构建产物
   - 生成校验和文件

4. **安全扫描**
   - Gosec 安全扫描
   - SARIF 报告上传

## 🛠️ 使用方法

### 日常开发

1. **创建 Pull Request**
   ```bash
   git checkout -b feature/your-feature
   git commit -m "Add your feature"
   git push origin feature/your-feature
   ```
   - 自动触发 CI 工作流
   - 检查代码质量和测试

2. **合并到主分支**
   ```bash
   git checkout main
   git merge feature/your-feature
   git push origin main
   ```
   - 触发完整的构建和测试流程

### 发布新版本

1. **创建版本标签**
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

2. **自动发布流程**
   - 自动构建所有平台的二进制文件
   - 创建 GitHub Release
   - 上传构建产物和校验和

### Docker 镜像发布

如需自动推送 Docker 镜像到 Docker Hub，需要配置以下密钥：

1. 在 GitHub 仓库设置中添加 Secrets：
   - `DOCKER_USERNAME`: Docker Hub 用户名
   - `DOCKER_PASSWORD`: Docker Hub 密码或访问令牌

2. 推送到 `main` 分支或创建标签时自动构建和推送镜像

## 📁 构建产物

### 二进制文件
- `anyproxy-linux-amd64.tar.gz`
- `anyproxy-linux-arm64.tar.gz`
- `anyproxy-windows-amd64.zip`
- `anyproxy-darwin-amd64.tar.gz`
- `anyproxy-darwin-arm64.tar.gz`

### Docker 镜像
- `your-dockerhub-username/anyproxy:latest`
- `your-dockerhub-username/anyproxy:v1.0.1`

### 包含内容
每个构建包都包含：
- `anyproxy-gateway` 和 `anyproxy-client` 二进制文件
- `configs/` 配置文件目录
- `certs/` 证书文件目录
- `README.md` 和 `CHANGELOG.md` 文档

## 🔧 本地测试

在推送代码前，可以使用我们提供的测试脚本验证构建：

```bash
# 运行完整的 GitHub Actions 测试
./scripts/test-github-actions.sh

# 或者分步测试
make test          # 运行测试
make lint          # 代码检查
make build-all     # 多平台构建
make docker-build  # Docker 构建
```

## 📊 状态徽章

可以在 README.md 中添加以下徽章来显示构建状态：

```markdown
[![CI](https://github.com/your-username/anyproxy/workflows/CI/badge.svg)](https://github.com/your-username/anyproxy/actions)
[![Build and Release](https://github.com/your-username/anyproxy/workflows/Build%20and%20Release/badge.svg)](https://github.com/your-username/anyproxy/actions)
```

## 🐛 故障排除

### 常见问题

1. **构建失败**
   - 检查 Go 版本兼容性
   - 确保所有测试通过
   - 查看具体的错误日志

2. **Docker 推送失败**
   - 验证 Docker Hub 密钥配置
   - 检查仓库权限

3. **发布失败**
   - 确保标签格式正确 (v1.0.0)
   - 检查 CHANGELOG.md 格式

### 查看日志

1. 访问 GitHub 仓库的 Actions 页面
2. 点击具体的工作流运行
3. 查看详细的步骤日志

## 🔄 工作流配置

### 修改触发条件

编辑 `.github/workflows/ci.yml` 或 `.github/workflows/build-and-release.yml`：

```yaml
on:
  push:
    branches: [ main, develop, staging ]  # 添加更多分支
  pull_request:
    branches: [ main ]
```

### 添加新的构建平台

在 `build-and-release.yml` 中修改 matrix：

```yaml
strategy:
  matrix:
    goos: [linux, windows, darwin, freebsd]  # 添加 freebsd
    goarch: [amd64, arm64, 386]              # 添加 386
```

## 📚 相关文档

- [GitHub Actions 官方文档](https://docs.github.com/en/actions)
- [Go 构建最佳实践](https://golang.org/doc/install/source)
- [Docker 多架构构建](https://docs.docker.com/buildx/working-with-buildx/)

---

**提示**: 首次使用时建议先在测试分支上验证工作流，确保一切正常后再应用到主分支。 