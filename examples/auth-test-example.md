# Authentication with Group-Based Usernames - Test Example

This document demonstrates how the authentication fix allows group-based usernames to work correctly with both HTTP and SOCKS5 proxies.

## Configuration

### Gateway Configuration
```yaml
proxy:
  http:
    listen_addr: ":8080"
    auth_username: "proxyuser"  # Base username for authentication
    auth_password: "proxypass"
  socks5:
    listen_addr: ":1080"
    auth_username: "proxyuser"  # Base username for authentication
    auth_password: "proxypass"
```

### Client Configuration
```yaml
client:
  client_id: "prod-client-001"
  group_id: "production"  # This client belongs to production group
  # ... other config
```

## Authentication Test Cases

### HTTP Proxy Authentication

#### ✅ Valid Cases (All should work)

```bash
# 1. Username with production group
curl -x http://proxyuser@production:proxypass@localhost:8080 https://httpbin.org/ip

# 2. Username with testing group  
curl -x http://proxyuser@testing:proxypass@localhost:8080 https://httpbin.org/ip

# 3. Plain username (backward compatibility)
curl -x http://proxyuser:proxypass@localhost:8080 https://httpbin.org/ip

# 4. Username with multiple @ symbols
curl -x http://proxyuser@prod@env:proxypass@localhost:8080 https://httpbin.org/ip
```

#### ❌ Invalid Cases (Should fail authentication)

```bash
# 1. Wrong base username
curl -x http://wronguser@production:proxypass@localhost:8080 https://httpbin.org/ip
# Expected: 407 Proxy Authentication Required

# 2. Wrong password
curl -x http://proxyuser@production:wrongpass@localhost:8080 https://httpbin.org/ip
# Expected: 407 Proxy Authentication Required

# 3. Wrong base username without group
curl -x http://wronguser:proxypass@localhost:8080 https://httpbin.org/ip
# Expected: 407 Proxy Authentication Required
```

### SOCKS5 Proxy Authentication

#### ✅ Valid Cases (All should work)

```bash
# 1. Username with production group
curl --socks5 proxyuser@production:proxypass@localhost:1080 https://httpbin.org/ip

# 2. Username with testing group
curl --socks5 proxyuser@testing:proxypass@localhost:1080 https://httpbin.org/ip

# 3. Plain username (backward compatibility)
curl --socks5 proxyuser:proxypass@localhost:1080 https://httpbin.org/ip

# 4. Username with multiple @ symbols
curl --socks5 proxyuser@prod@env:proxypass@localhost:1080 https://httpbin.org/ip
```

#### ❌ Invalid Cases (Should fail authentication)

```bash
# 1. Wrong base username
curl --socks5 wronguser@production:proxypass@localhost:1080 https://httpbin.org/ip
# Expected: SOCKS5 authentication failure

# 2. Wrong password
curl --socks5 proxyuser@production:wrongpass@localhost:1080 https://httpbin.org/ip
# Expected: SOCKS5 authentication failure

# 3. Wrong base username without group
curl --socks5 wronguser:proxypass@localhost:1080 https://httpbin.org/ip
# Expected: SOCKS5 authentication failure
```

## Expected Behavior

### Authentication Process

1. **Username Parsing**: The system extracts the base username from `username@group-id`
   - `proxyuser@production` → base username: `proxyuser`, group: `production`
   - `proxyuser` → base username: `proxyuser`, group: `` (default)

2. **Authentication**: Validates base username and password against configuration
   - Base username must match `auth_username` in config
   - Password must match `auth_password` in config

3. **Group Extraction**: After successful authentication, extracts group for routing
   - Full username is passed to group extractor
   - Group information is used for client selection

### Logging Output

#### Successful Authentication
```
INFO HTTP request url=https://httpbin.org/ip user="&{Username:proxyuser@production GroupID:production}"
INFO SOCKS5 extracted user info username=proxyuser@production group_id=production
INFO Selected client from group group=production client_id=prod-client-001
```

#### Failed Authentication
```
WARN Authentication failed for HTTP proxy user=wronguser@production
ERROR SOCKS5 authentication failed for user: wronguser
```

## Testing Script

Create a test script to verify all scenarios:

```bash
#!/bin/bash

echo "Testing HTTP Proxy Authentication..."

# Valid cases
echo "✅ Testing valid HTTP authentication cases..."
curl -s -x http://proxyuser@production:proxypass@localhost:8080 https://httpbin.org/ip > /dev/null && echo "✅ HTTP with production group: PASS" || echo "❌ HTTP with production group: FAIL"
curl -s -x http://proxyuser:proxypass@localhost:8080 https://httpbin.org/ip > /dev/null && echo "✅ HTTP without group: PASS" || echo "❌ HTTP without group: FAIL"

# Invalid cases
echo "❌ Testing invalid HTTP authentication cases..."
curl -s -x http://wronguser@production:proxypass@localhost:8080 https://httpbin.org/ip > /dev/null && echo "❌ HTTP wrong username: FAIL (should have failed)" || echo "✅ HTTP wrong username: PASS (correctly failed)"
curl -s -x http://proxyuser@production:wrongpass@localhost:8080 https://httpbin.org/ip > /dev/null && echo "❌ HTTP wrong password: FAIL (should have failed)" || echo "✅ HTTP wrong password: PASS (correctly failed)"

echo ""
echo "Testing SOCKS5 Proxy Authentication..."

# Valid cases
echo "✅ Testing valid SOCKS5 authentication cases..."
curl -s --socks5 proxyuser@production:proxypass@localhost:1080 https://httpbin.org/ip > /dev/null && echo "✅ SOCKS5 with production group: PASS" || echo "❌ SOCKS5 with production group: FAIL"
curl -s --socks5 proxyuser:proxypass@localhost:1080 https://httpbin.org/ip > /dev/null && echo "✅ SOCKS5 without group: PASS" || echo "❌ SOCKS5 without group: FAIL"

# Invalid cases
echo "❌ Testing invalid SOCKS5 authentication cases..."
curl -s --socks5 wronguser@production:proxypass@localhost:1080 https://httpbin.org/ip > /dev/null && echo "❌ SOCKS5 wrong username: FAIL (should have failed)" || echo "✅ SOCKS5 wrong username: PASS (correctly failed)"
curl -s --socks5 proxyuser@production:wrongpass@localhost:1080 https://httpbin.org/ip > /dev/null && echo "❌ SOCKS5 wrong password: FAIL (should have failed)" || echo "✅ SOCKS5 wrong password: PASS (correctly failed)"
```

## Summary

The authentication fix ensures that:

1. **Group-based usernames work correctly**: `username@group-id` format is properly handled
2. **Backward compatibility is maintained**: Plain usernames continue to work
3. **Security is preserved**: Authentication still validates against configured credentials
4. **Both protocols are supported**: HTTP and SOCKS5 proxies both handle group-based authentication
5. **Group routing functions properly**: After authentication, group information is correctly extracted and used for client selection 