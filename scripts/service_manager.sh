#!/bin/bash

# AnyProxy Service Management Script

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service names
GATEWAY_SERVICE="anyproxy-gateway"
CLIENT_SERVICE="anyproxy-client"

# Log functions
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

# Show help information
show_help() {
    echo "AnyProxy Service Management Script"
    echo
    echo "Usage: $0 <command> [service_name]"
    echo
    echo "Commands:"
    echo "  start     Start service"
    echo "  stop      Stop service"
    echo "  restart   Restart service"
    echo "  status    Show service status"
    echo "  enable    Enable auto-start on boot"
    echo "  disable   Disable auto-start on boot"
    echo "  logs      Show service logs"
    echo "  install   Install and configure services"
    echo "  uninstall Uninstall services"
    echo
    echo "Service names (optional):"
    echo "  gateway   Gateway service"
    echo "  client    Client service"
    echo "  all       All services (default)"
    echo
    echo "Examples:"
    echo "  $0 start           # Start all services"
    echo "  $0 start gateway   # Start only gateway service"
    echo "  $0 status          # Show all service status"
    echo "  $0 logs client     # Show client logs"
}

# Check if service exists
check_service_exists() {
    local service=$1
    if ! systemctl list-unit-files | grep -q "^$service.service"; then
        log_error "Service $service does not exist"
        log_info "Please run first: $0 install"
        return 1
    fi
    return 0
}

# Get service list
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
            log_error "Unknown service name: $target"
            log_info "Supported service names: gateway, client, all"
            exit 1
            ;;
    esac
}

# Start services
start_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "Starting service: $service"
            if sudo systemctl start "$service"; then
                log_info "Service $service started successfully"
            else
                log_error "Failed to start service $service"
            fi
        fi
    done
}

# Stop services
stop_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "Stopping service: $service"
            if sudo systemctl stop "$service"; then
                log_info "Service $service stopped successfully"
            else
                log_error "Failed to stop service $service"
            fi
        fi
    done
}

# Restart services
restart_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "Restarting service: $service"
            if sudo systemctl restart "$service"; then
                log_info "Service $service restarted successfully"
            else
                log_error "Failed to restart service $service"
            fi
        fi
    done
}

# Show service status
show_status() {
    local target=$1
    local services=$(get_services "$target")
    
    echo
    echo "=== AnyProxy Service Status ==="
    echo
    
    for service in $services; do
        if check_service_exists "$service"; then
            echo "Service: $service"
            sudo systemctl status "$service" --no-pager -l
            echo
        fi
    done
}

# Enable auto-start on boot
enable_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "Enabling auto-start for service: $service"
            if sudo systemctl enable "$service"; then
                log_info "Auto-start enabled successfully for service $service"
            else
                log_error "Failed to enable auto-start for service $service"
            fi
        fi
    done
}

# Disable auto-start on boot
disable_services() {
    local target=$1
    local services=$(get_services "$target")
    
    for service in $services; do
        if check_service_exists "$service"; then
            log_info "Disabling auto-start for service: $service"
            if sudo systemctl disable "$service"; then
                log_info "Auto-start disabled successfully for service $service"
            else
                log_error "Failed to disable auto-start for service $service"
            fi
        fi
    done
}

# Show service logs
show_logs() {
    local target=$1
    local services=$(get_services "$target")
    
    if [ $(echo "$services" | wc -w) -eq 1 ]; then
        # Single service, show real-time logs
        local service=$services
        if check_service_exists "$service"; then
            log_info "Showing service logs: $service (Press Ctrl+C to exit)"
            sudo journalctl -u "$service" -f
        fi
    else
        # Multiple services, show recent logs
        for service in $services; do
            if check_service_exists "$service"; then
                echo
                echo "=== $service Recent Logs ==="
                sudo journalctl -u "$service" --since "1 hour ago" --no-pager
            fi
        done
    fi
}

# Install services
install_services() {
    log_info "Starting AnyProxy service installation..."
    
    local script_dir=$(dirname "$(readlink -f "$0")")
    local setup_script="$script_dir/setup_runtime_dirs.sh"
    
    if [[ -f "$setup_script" ]]; then
        log_info "Running installation script..."
        sudo bash "$setup_script"
    else
        log_error "Installation script not found: $setup_script"
        exit 1
    fi
}

# Uninstall services
uninstall_services() {
    log_warn "This will completely uninstall AnyProxy services and related files"
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        return
    fi
    
    log_info "Starting AnyProxy service uninstallation..."
    
    # Stop and disable services
    for service in $GATEWAY_SERVICE $CLIENT_SERVICE; do
        if systemctl list-unit-files | grep -q "^$service.service"; then
            log_info "Stopping and disabling service: $service"
            sudo systemctl stop "$service" 2>/dev/null || true
            sudo systemctl disable "$service" 2>/dev/null || true
        fi
    done
    
    # Remove service files
    sudo rm -f "/etc/systemd/system/$GATEWAY_SERVICE.service"
    sudo rm -f "/etc/systemd/system/$CLIENT_SERVICE.service"
    
    # Reload systemd
    sudo systemctl daemon-reload
    
    # Remove directories and files
    sudo rm -rf /opt/anyproxy
    sudo rm -rf /etc/anyproxy
    sudo rm -rf /var/lib/anyproxy
    sudo rm -rf /var/log/anyproxy
    sudo rm -rf /var/run/anyproxy
    sudo rm -f /etc/logrotate.d/anyproxy
    
    # Remove user
    if id "anyproxy" &>/dev/null; then
        sudo userdel anyproxy
        log_info "Removed user: anyproxy"
    fi
    
    log_info "AnyProxy service uninstallation completed"
}

# Main function
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
            log_error "Unknown command: $command"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@" 