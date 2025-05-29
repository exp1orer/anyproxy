# Clash for Android Configuration Usage Guide

## Configuration File Description

Two Clash configuration files have been generated for the AnyProxy server:

1. **clash-android.yaml** - Full-featured configuration file
   - Contains complete traffic routing rules
   - Supports specialized groups for app purification, Telegram, YouTube, etc.
   - Suitable for advanced users

2. **clash-android-simple.yaml** - Simplified configuration file
   - Basic traffic routing rules
   - Simple configuration, easy to understand
   - Recommended for beginners

## Usage Steps

### 1. Modify Configuration File

Before using the configuration file, you need to modify the following content:

```yaml
# Replace 127.0.0.1 with your actual server IP address
proxies:
  - name: "AnyProxy-HTTP"
    type: http
    server: YOUR_SERVER_IP  # Modify this
    port: 8080
    username: user
    password: password

  - name: "AnyProxy-SOCKS5"
    type: socks5
    server: YOUR_SERVER_IP  # Modify this
    port: 1080
```

### 2. Ensure AnyProxy Service is Running

Before using the Clash configuration, ensure your AnyProxy service is running:

```bash
# Start gateway
./bin/anyproxy-gateway --config configs/config.yaml

# Start client
./bin/anyproxy-client --config configs/config.yaml
```

### 3. Import Clash Configuration

1. Open Clash for Android app
2. Click the "Profiles" tab
3. Click the "+" button to add a new configuration
4. Select "Import from file"
5. Choose the generated configuration file (simplified version recommended)

### 4. Start Proxy

1. Select the imported configuration in Clash
2. Toggle the switch to start proxy service
3. Choose proxy mode as needed:
   - **Rule Mode**: Automatic traffic routing based on rules (recommended)
   - **Global Mode**: All traffic goes through proxy
   - **Direct Mode**: All traffic goes direct

## Proxy Configuration Details

### HTTP Proxy Configuration
- **Address**: Your server IP
- **Port**: 8080
- **Username**: user
- **Password**: password

### SOCKS5 Proxy Configuration
- **Address**: Your server IP
- **Port**: 1080
- **Authentication**: None (according to your configuration)

## Traffic Routing Rules Description

### Direct Connection (DIRECT)
- Local networks (127.0.0.1, 192.168.x.x, etc.)
- Mainland China websites and IPs
- Common domestic services (Baidu, Tencent, Alibaba, etc.)

### Proxy Connection
- Foreign websites (Google, YouTube, Facebook, etc.)
- Other unmatched traffic

## Troubleshooting

### 1. Connection Failed
- Check if server IP address is correct
- Confirm AnyProxy service is running
- Check firewall settings

### 2. Authentication Failed
- Confirm HTTP proxy username and password are correct
- SOCKS5 proxy is currently configured without authentication

### 3. Incorrect Traffic Routing
- Check if rule configuration is correct
- View connection logs in Clash
- Try switching to global mode for testing

## Advanced Configuration

If you need to customize traffic routing rules, you can modify the `rules` section in the configuration file:

```yaml
rules:
  # Add custom rules
  - DOMAIN-SUFFIX,example.com,Proxy Selection
  - IP-CIDR,1.2.3.0/24,DIRECT
  # ... other rules
```

## Important Notes

1. Server address in configuration file needs to be modified according to actual situation
2. Ensure AnyProxy service is running normally before using Clash
3. Recommend testing connection with simplified configuration file first
4. If there are issues, check Clash connection logs for debugging 