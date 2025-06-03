# Port Forwarding Feature

## Overview

The port forwarding feature allows clients to request the gateway to expose ports on the gateway server, forwarding traffic to specified local addresses through the client's WebSocket connection.

## Key Features

- ✅ **TCP and UDP Support**: Handle both TCP and UDP protocols
- ✅ **Automatic Cleanup**: Ports are automatically closed when clients disconnect
- ✅ **Port Conflict Detection**: Prevent multiple clients from using the same port
- ✅ **Performance Optimized**: Uses direct listener closure for immediate shutdown
- ✅ **Thread Safe**: Concurrent access protection with proper synchronization

## Configuration

Add port forwarding configuration to your client config:

```yaml
client:
  open_ports:
    - remote_port: 9000     # Port to open on gateway
      protocol: "tcp"       # Protocol: tcp or udp
      local_port: 9000      # Target port on client side
      local_host: "10.0.0.1" # Target host on client side
    - remote_port: 8022
      protocol: "udp"
      local_port: 22
      local_host: "10.0.0.2"
```

## Implementation Details

Our implementation uses **direct listener closure** for optimal performance and immediate shutdown response.

```go
// TCP: Direct listener closure
listener.Close() // Immediately interrupts Accept() calls

// UDP: Direct connection closure  
packetConn.Close() // Immediately interrupts ReadFrom() calls

// Error detection
if strings.Contains(err.Error(), "use of closed network connection") {
    return // Normal shutdown
}
```

### Why Direct Closure?

1. **Performance**: Immediate shutdown response
2. **Simplicity**: Minimal code complexity, easy to understand and maintain
3. **Resource Efficiency**: Low memory allocation and CPU usage
4. **Immediate Response**: Shutdown signals take effect instantly
5. **Reliability**: Proven approach used throughout the Go ecosystem

## Usage Example

1. **Client Configuration**: Add `open_ports` to client config
2. **Automatic Request**: Client sends port forwarding request on startup
3. **Gateway Processing**: Gateway opens requested ports and starts listening
4. **Traffic Forwarding**: Incoming connections are forwarded to client via WebSocket
5. **Automatic Cleanup**: Ports are closed when client disconnects

## Traffic Flow

```
External Client → Gateway:Port → WebSocket → AnyProxy Client → Target Service
                     ↓
              [Port Forwarding]
                     ↓
            Uses existing dialNetwork logic
```

## Error Handling

- **Port Conflicts**: Detected and reported, preventing multiple clients from using same port
- **Connection Failures**: Logged with detailed error information
- **Client Disconnection**: All client ports automatically closed
- **Graceful Shutdown**: All ports closed simultaneously during gateway shutdown

## Testing

Comprehensive test coverage includes:

- ✅ Basic port forwarding functionality
- ✅ Port conflict detection
- ✅ Client disconnection cleanup
- ✅ TCP and UDP protocol support

Run tests:
```bash
go test ./pkg/proxy -run TestPortForward -v
```

## Security Considerations

- Port forwarding requires valid client authentication
- Forbidden/allowed host filtering still applies to target addresses
- Each client can only close ports they opened
- Gateway admin can see all active port forwards

## Monitoring

Key metrics logged:
- Port opening/closing events
- Connection counts and data transfer volumes
- Error rates and types
- Client connection/disconnection events 