#!/bin/bash

# AnyProxy Runtime Directory Setup Script
# Used to configure directory structure and permissions for production environment

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

# Check if running with root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script requires root privileges to run"
        echo "Please use: sudo $0"
        exit 1
    fi
}

# Create system user
create_user() {
    log_info "Creating anyproxy system user..."
    
    if id "anyproxy" &>/dev/null; then
        log_warn "User anyproxy already exists, skipping creation"
    else
        useradd -r -s /bin/false -d /opt/anyproxy anyproxy
        log_info "User anyproxy created successfully"
    fi
}

# Create directory structure
create_directories() {
    log_info "Creating runtime directory structure..."
    
    # Main directories
    local dirs=(
        "/opt/anyproxy"              # Program installation directory
        "/opt/anyproxy/bin"          # Binary files directory
        "/opt/anyproxy/scripts"      # Scripts directory
        "/etc/anyproxy"              # Configuration files directory
        "/etc/anyproxy/certs"        # Certificates directory
        "/var/lib/anyproxy"          # Data directory
        "/var/log/anyproxy"          # Log directory
        "/var/run/anyproxy"          # PID files directory
        "/tmp/anyproxy"              # Temporary files directory
    )
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
        else
            log_warn "Directory already exists: $dir"
        fi
    done
}

# Set directory permissions
set_permissions() {
    log_info "Setting directory permissions..."
    
    # Set ownership
    chown -R anyproxy:anyproxy /opt/anyproxy
    chown -R anyproxy:anyproxy /etc/anyproxy
    chown -R anyproxy:anyproxy /var/lib/anyproxy
    chown -R anyproxy:anyproxy /var/log/anyproxy
    chown -R anyproxy:anyproxy /var/run/anyproxy
    chown -R anyproxy:anyproxy /tmp/anyproxy
    
    # Set permissions
    chmod 755 /opt/anyproxy
    chmod 755 /opt/anyproxy/bin
    chmod 755 /opt/anyproxy/scripts
    chmod 750 /etc/anyproxy
    chmod 700 /etc/anyproxy/certs
    chmod 755 /var/lib/anyproxy
    chmod 755 /var/log/anyproxy
    chmod 755 /var/run/anyproxy
    chmod 755 /tmp/anyproxy
    
    log_info "Permissions set successfully"
}

# Copy binary files
install_binaries() {
    log_info "Installing binary files..."
    
    local current_dir=$(dirname "$(readlink -f "$0")")
    local project_root=$(dirname "$current_dir")
    
    if [[ -f "$project_root/bin/anyproxy-gateway" ]]; then
        cp "$project_root/bin/anyproxy-gateway" /opt/anyproxy/bin/
        chmod +x /opt/anyproxy/bin/anyproxy-gateway
        log_info "Installed anyproxy-gateway"
    else
        log_error "anyproxy-gateway binary file not found"
        log_error "Please run 'make build' to compile the project first"
        exit 1
    fi
    
    if [[ -f "$project_root/bin/anyproxy-client" ]]; then
        cp "$project_root/bin/anyproxy-client" /opt/anyproxy/bin/
        chmod +x /opt/anyproxy/bin/anyproxy-client
        log_info "Installed anyproxy-client"
    else
        log_error "anyproxy-client binary file not found"
        log_error "Please run 'make build' to compile the project first"
        exit 1
    fi
}

# Copy configuration files
install_config() {
    log_info "Installing configuration files..."
    
    local current_dir=$(dirname "$(readlink -f "$0")")
    local project_root=$(dirname "$current_dir")
    
    if [[ -f "$project_root/configs/config.yaml" ]]; then
        cp "$project_root/configs/config.yaml" /etc/anyproxy/
        log_info "Installed configuration file"
    else
        log_error "Configuration file not found"
        exit 1
    fi
    
    # Copy certificate files (if they exist)
    if [[ -d "$project_root/certs" ]]; then
        cp -r "$project_root/certs"/* /etc/anyproxy/certs/ 2>/dev/null || true
        log_info "Copied certificate files"
    fi
}

# Create systemd service files
create_systemd_services() {
    log_info "Creating systemd service files..."
    
    # Gateway service
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

# Runtime directory
RuntimeDirectory=anyproxy
RuntimeDirectoryMode=0755

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy /var/lib/anyproxy /var/run/anyproxy /tmp/anyproxy

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Client service
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

# Runtime directory
RuntimeDirectory=anyproxy
RuntimeDirectoryMode=0755

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anyproxy /var/lib/anyproxy /var/run/anyproxy /tmp/anyproxy

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    log_info "systemd service files created successfully"
}

# Configure log rotation
setup_logrotate() {
    log_info "Configuring log rotation..."
    
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

    log_info "Log rotation configuration completed"
}

# Create monitoring script
create_monitor_script() {
    log_info "Creating monitoring script..."
    
    cat > /opt/anyproxy/scripts/monitor.sh << 'EOF'
#!/bin/bash

# AnyProxy Service Monitoring Script

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

# Check service status
check_service "anyproxy-gateway"
check_service "anyproxy-client"

# Check disk space
DISK_USAGE=$(df /var/log/anyproxy | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 80 ]; then
    log_message "WARNING: Disk usage is ${DISK_USAGE}%"
fi
EOF

    chmod +x /opt/anyproxy/scripts/monitor.sh
    chown anyproxy:anyproxy /opt/anyproxy/scripts/monitor.sh
    
    log_info "Monitoring script created successfully"
}

# Main function
main() {
    log_info "Starting AnyProxy runtime directory setup..."
    
    check_root
    create_user
    create_directories
    set_permissions
    install_binaries
    install_config
    create_systemd_services
    setup_logrotate
    create_monitor_script
    
    # Reload systemd
    systemctl daemon-reload
    
    log_info "Runtime directory setup completed!"
    echo
    log_info "Next steps:"
    echo "1. Edit configuration file: /etc/anyproxy/config.yaml"
    echo "2. Start services: sudo systemctl start anyproxy-gateway anyproxy-client"
    echo "3. Enable auto-start: sudo systemctl enable anyproxy-gateway anyproxy-client"
    echo "4. Check service status: sudo systemctl status anyproxy-gateway anyproxy-client"
    echo "5. View logs: sudo journalctl -u anyproxy-gateway -f"
}

# Run main function
main "$@" 