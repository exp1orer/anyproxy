#!/bin/bash

# AnyProxy 服务管理脚本

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 服务名称
GATEWAY_SERVICE="anyproxy-gateway"
CLIENT_SERVICE="anyproxy-client"

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

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# 显示帮助信息
show_help() {
    echo "AnyProxy 服务管理脚本"
    echo
    echo "用法: $0 <命令> [服务名]"
    echo
    echo "命令:"
    echo "  start     启动服务"
    echo "  stop      停止服务"
    echo "  restart   重启服务"
    echo "  status    查看服务状态"
    echo "  enable    启用开机自启"
    echo "  disable   禁用开机自启"
    echo "  logs      查看服务日志"
    echo "  install   安装并配置服务"
    echo "  uninstall 卸载服务"
    echo
    echo "服务名 (可选):"
    echo "  gateway   网关服务"
    echo "  client    客户端服务"
    echo "  all       所有服务 (默认)"
    echo
    echo "示例:"
    echo "  $0 start           # 启动所有服务"
    echo "  $0 start gateway   # 只启动网关服务"
    echo "  $0 status          # 查看所有服务状态"
    echo "  $0 logs client     # 查看客户端日志"
}

# 检查服务是否存在
check_service_exists() {
    local service=$1
    if ! systemctl list-unit-files | grep -q "^$service.service"; then
        log_error "服务 $service 不存在"
        log_info "请先运行: $0 install"
        return 1
    fi
    return 0
}

# 获取服务列表
get_services() {
    local target=$1
    case $target in
        "gateway")
            echo "$GATEWAY_SERVICE"
            ;;
        "client")
            echo "$CLIENT_SERVICE"
            ;;
        "all"|"")
            echo "$GATEWAY_SERVICE $CLIENT_SERVICE"
            ;;
        *)
            log_error "未知的服务名: $target"
            log_info "支持的服务名: gateway, client, all"
            exit 1
            ;;
    esac
}

# 启动服务
start_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "启动服务: $service"
            if sudo systemctl start "$service"; then
                log_info "服务 $service 启动成功"
            else
                log_error "服务 $service 启动失败"
            fi
        fi
    done
}

# 停止服务
stop_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "停止服务: $service"
            if sudo systemctl stop "$service"; then
                log_info "服务 $service 停止成功"
            else
                log_error "服务 $service 停止失败"
            fi
        fi
    done
}

# 重启服务
restart_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "重启服务: $service"
            if sudo systemctl restart "$service"; then
                log_info "服务 $service 重启成功"
            else
                log_error "服务 $service 重启失败"
            fi
        fi
    done
}

# 查看服务状态
show_status() {
    local target=$1
    local services=$(get_services "$target")
    
    echo
    echo "=== AnyProxy 服务状态 ==="
    echo
    
    for service in $services; do
        if check_service_exists "$service"; then
            echo "服务: $service"
            sudo systemctl status "$service" --no-pager -l
            echo
        fi
    done
}

# 启用开机自启
enable_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "启用服务开机自启: $service"
            if sudo systemctl enable "$service"; then
                log_info "服务 $service 开机自启启用成功"
            else
                log_error "服务 $service 开机自启启用失败"
            fi
        fi
    done
}

# 禁用开机自启
disable_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "禁用服务开机自启: $service"
            if sudo systemctl disable "$service"; then
                log_info "服务 $service 开机自启禁用成功"
            else
                log_error "服务 $service 开机自启禁用失败"
            fi
        fi
    done
}

# 查看服务日志
show_logs() {
    local target=$1
    local services=$(get_services "$target")
    
    if [ $(echo "$services" | wc -w) -eq 1 ]; then
        # 单个服务，显示实时日志
        local service=$services
        if check_service_exists "$service"; then
            log_info "显示服务日志: $service (按 Ctrl+C 退出)"
            sudo journalctl -u "$service" -f
        fi
    else
        # 多个服务，显示最近的日志
        for service in $services; do
            if check_service_exists "$service"; then
                echo
                echo "=== $service 最近日志 ==="
                sudo journalctl -u "$service" --since "1 hour ago" --no-pager
            fi
        done
    fi
}

# 安装服务
install_services() {
    log_info "开始安装 AnyProxy 服务..."
    
    local script_dir=$(dirname "$(readlink -f "$0")")
    local setup_script="$script_dir/setup_runtime_dirs.sh"
    
    if [[ -f "$setup_script" ]]; then
        log_info "运行安装脚本..."
        sudo bash "$setup_script"
    else
        log_error "未找到安装脚本: $setup_script"
        exit 1
    fi
}

# 卸载服务
uninstall_services() {
    log_warn "这将完全卸载 AnyProxy 服务和相关文件"
    read -p "确定要继续吗? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "取消卸载"
        return
    fi
    
    log_info "开始卸载 AnyProxy 服务..."
    
    # 停止并禁用服务
    for service in $GATEWAY_SERVICE $CLIENT_SERVICE; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            log_info "停止并禁用服务: $service"
            sudo systemctl stop "$service" 2>/dev/null || true
            sudo systemctl disable "$service" 2>/dev/null || true
        fi
    done
    
    # 删除服务文件
    sudo rm -f "/etc/systemd/system/$GATEWAY_SERVICE.service"
    sudo rm -f "/etc/systemd/system/$CLIENT_SERVICE.service"
    
    # 重新加载 systemd
    sudo systemctl daemon-reload
    
    # 删除目录和文件
    sudo rm -rf /opt/anyproxy
    sudo rm -rf /etc/anyproxy
    sudo rm -rf /var/lib/anyproxy
    sudo rm -rf /var/log/anyproxy
    sudo rm -rf /var/run/anyproxy
    sudo rm -f /etc/logrotate.d/anyproxy
    
    # 删除用户
    if id "anyproxy" &>/dev/null; then
        sudo userdel anyproxy
        log_info "删除用户: anyproxy"
    fi
    
    log_info "AnyProxy 服务卸载完成"
}

# 主函数
main() {
    local command=$1
    local target=$2
    
    case $command in
        "start")
            start_services "$target"
            ;;
        "stop")
            stop_services "$target"
            ;;
        "restart")
            restart_services "$target"
            ;;
        "status")
            show_status "$target"
            ;;
        "enable")
            enable_services "$target"
            ;;
        "disable")
            disable_services "$target"
            ;;
        "logs")
            show_logs "$target"
            ;;
        "install")
            install_services
            ;;
        "uninstall")
            uninstall_services
            ;;
        "help"|"-h"|"--help"|"")
            show_help
            ;;
        *)
            log_error "未知命令: $command"
            echo
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@" 