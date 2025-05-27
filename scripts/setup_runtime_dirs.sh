#!/bin/bash

# AnyProxy 运行目录设置脚本
# 用于配置生产环境的目录结构和权限

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查是否以 root 权限运行
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "此脚本需要 root 权限运行"
        echo "请使用: sudo $0"
        exit 1
    fi
}

# 创建系统用户
create_user() {
    log_info "创建 anyproxy 系统用户..."
    
    if id "anyproxy" &>/dev/null; then
        log_warn "用户 anyproxy 已存在，跳过创建"
    else
        useradd -r -s /bin/false -d /opt/anyproxy anyproxy
        log_info "用户 anyproxy 创建成功"
    fi
}

# 创建目录结构
create_directories() {
    log_info "创建运行目录结构..."
    
    # 主要目录
    local dirs=(
        "/opt/anyproxy"              # 程序安装目录
        "/opt/anyproxy/bin"          # 二进制文件目录
        "/opt/anyproxy/scripts"      # 脚本目录
        "/etc/anyproxy"              # 配置文件目录
        "/etc/anyproxy/certs"        # 证书目录
        "/var/lib/anyproxy"          # 数据目录
        "/var/log/anyproxy"          # 日志目录
        "/var/run/anyproxy"          # PID 文件目录
        "/tmp/anyproxy"              # 临时文件目录
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "创建目录: $dir"
        else
            log_warn "目录已存在: $dir"
        fi
    done
}

# 设置目录权限
set_permissions() {
    log_info "设置目录权限..."
    
    # 设置所有者
    chown -R anyproxy:anyproxy /opt/anyproxy
    chown -R anyproxy:anyproxy /etc/anyproxy
    chown -R anyproxy:anyproxy /var/lib/anyproxy
    chown -R anyproxy:anyproxy /var/log/anyproxy
    chown -R anyproxy:anyproxy /var/run/anyproxy
    chown -R anyproxy:anyproxy /tmp/anyproxy
    
    # 设置权限
    chmod 755 /opt/anyproxy
    chmod 755 /opt/anyproxy/bin
    chmod 755 /opt/anyproxy/scripts
    chmod 750 /etc/anyproxy
    chmod 700 /etc/anyproxy/certs
    chmod 755 /var/lib/anyproxy
    chmod 755 /var/log/anyproxy
    chmod 755 /var/run/anyproxy
    chmod 755 /tmp/anyproxy
    
    log_info "权限设置完成"
}

# 复制二进制文件
install_binaries() {
    log_info "安装二进制文件..."
    
    local current_dir=$(dirname "$(readlink -f "$0")")
    local project_root=$(dirname "$current_dir")
    
    if [[ -f "$project_root/bin/anyproxy-gateway" ]]; then
        cp "$project_root/bin/anyproxy-gateway" /opt/anyproxy/bin/
        chmod +x /opt/anyproxy/bin/anyproxy-gateway
        log_info "安装 anyproxy-gateway"
    else
        log_error "未找到 anyproxy-gateway 二进制文件"
        log_error "请先运行 'make build' 编译项目"
        exit 1
    fi
    
    if [[ -f "$project_root/bin/anyproxy-client" ]]; then
        cp "$project_root/bin/anyproxy-client" /opt/anyproxy/bin/
        chmod +x /opt/anyproxy/bin/anyproxy-client
        log_info "安装 anyproxy-client"
    else
        log_error "未找到 anyproxy-client 二进制文件"
        log_error "请先运行 'make build' 编译项目"
        exit 1
    fi
}

# 复制配置文件
install_config() {
    log_info "安装配置文件..."
    
    local current_dir=$(dirname "$(readlink -f "$0")")
    local project_root=$(dirname "$current_dir")
    
    if [[ -f "$project_root/configs/config.yaml" ]]; then
        cp "$project_root/configs/config.yaml" /etc/anyproxy/
        log_info "安装配置文件"
    else
        log_error "未找到配置文件"
        exit 1
    fi
    
    # 复制证书文件（如果存在）
    if [[ -d "$project_root/certs" ]]; then
        cp -r "$project_root/certs"/* /etc/anyproxy/certs/ 2>/dev/null || true
        log_info "复制证书文件"
    fi
}

# 创建 systemd 服务文件
create_systemd_services() {
    log_info "创建 systemd 服务文件..."
    
    # Gateway 服务
    cat > /etc/systemd/system/anyproxy-gateway.service << 'EOF'
[Unit]
Description=AnyProxy Gateway
Documentation=https://github.com/buhuipao/anyproxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anyproxy
Group=anyproxy
WorkingDirectory=/opt/anyproxy
ExecStart=/opt/anyproxy/bin/anyproxy-gateway --config /etc/anyproxy/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=anyproxy-gateway

# 运行时目录
RuntimeDirectory=anyproxy
RuntimeDirectoryMode=0755

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy /var/lib/anyproxy /var/run/anyproxy /tmp/anyproxy

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Client 服务
    cat > /etc/systemd/system/anyproxy-client.service << 'EOF'
[Unit]
Description=AnyProxy Client
Documentation=https://github.com/buhuipao/anyproxy
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=anyproxy
Group=anyproxy
WorkingDirectory=/opt/anyproxy
ExecStart=/opt/anyproxy/bin/anyproxy-client --config /etc/anyproxy/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=anyproxy-client

# 运行时目录
RuntimeDirectory=anyproxy
RuntimeDirectoryMode=0755

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy /var/lib/anyproxy /var/run/anyproxy /tmp/anyproxy

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    log_info "systemd 服务文件创建完成"
}

# 配置日志轮转
setup_logrotate() {
    log_info "配置日志轮转..."
    
    cat > /etc/logrotate.d/anyproxy << 'EOF'
/var/log/anyproxy/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 anyproxy anyproxy
    postrotate
        systemctl reload anyproxy-gateway anyproxy-client 2>/dev/null || true
    endscript
}
EOF

    log_info "日志轮转配置完成"
}

# 创建监控脚本
create_monitor_script() {
    log_info "创建监控脚本..."
    
    cat > /opt/anyproxy/scripts/monitor.sh << 'EOF'
#!/bin/bash

# AnyProxy 服务监控脚本

LOG_FILE="/var/log/anyproxy/monitor.log"

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

check_service() {
    local service=$1
    if ! systemctl is-active --quiet "$service"; then
        log_message "WARNING: $service is not running, attempting to restart..."
        if systemctl restart "$service"; then
            log_message "INFO: $service restarted successfully"
        else
            log_message "ERROR: Failed to restart $service"
        fi
    fi
}

# 检查服务状态
check_service "anyproxy-gateway"
check_service "anyproxy-client"

# 检查磁盘空间
DISK_USAGE=$(df /var/log/anyproxy | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    log_message "WARNING: Disk usage is ${DISK_USAGE}%"
fi
EOF

    chmod +x /opt/anyproxy/scripts/monitor.sh
    chown anyproxy:anyproxy /opt/anyproxy/scripts/monitor.sh
    
    log_info "监控脚本创建完成"
}

# 主函数
main() {
    log_info "开始设置 AnyProxy 运行目录..."
    
    check_root
    create_user
    create_directories
    set_permissions
    install_binaries
    install_config
    create_systemd_services
    setup_logrotate
    create_monitor_script
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    log_info "运行目录设置完成！"
    echo
    log_info "下一步操作："
    echo "1. 编辑配置文件: /etc/anyproxy/config.yaml"
    echo "2. 启动服务: sudo systemctl start anyproxy-gateway anyproxy-client"
    echo "3. 启用开机自启: sudo systemctl enable anyproxy-gateway anyproxy-client"
    echo "4. 查看服务状态: sudo systemctl status anyproxy-gateway anyproxy-client"
    echo "5. 查看日志: sudo journalctl -u anyproxy-gateway -f"
}

# 运行主函数
main "$@" 