# Logging Configuration Guide

AnyProxy uses Go's structured logging library `slog` to provide powerful logging capabilities, supporting multiple output formats, log levels, and file rotation.

## Configuration Options

Configure logging in the `log` section of the `config.yaml` file:

```yaml
log:
  level: "info"           # Log level
  format: "text"          # Log format
  output: "stdout"        # Output target
  file: "logs/anyproxy.log"  # File path (when output is file)
  max_size: 100           # Maximum file size (MB)
  max_backups: 5          # Number of old files to retain
  max_age: 30             # Days to retain files
  compress: true          # Whether to compress old files
```

### Log Levels

Supports the following log levels (in increasing order of severity):

- `debug`: Debug information, including detailed program execution information
- `info`: General information, normal program operation status
- `warn`: Warning information, potential issues that don't affect program operation
- `error`: Error information, errors encountered by the program but can continue running

### Log Format

Supports two output formats:

- `text`: Human-readable text format (default)
- `json`: JSON format, convenient for log analysis tools

#### Text Format Example
```
time=2024-01-15T10:30:45.123Z level=INFO msg="Gateway started" listen_addr=:8443
time=2024-01-15T10:30:45.124Z level=INFO msg="Client connected" client_id=client-abc123
```

#### JSON Format Example
```json
{"time":"2024-01-15T10:30:45.123Z","level":"INFO","msg":"Gateway started","listen_addr":":8443"}
{"time":"2024-01-15T10:30:45.124Z","level":"INFO","msg":"Client connected","client_id":"client-abc123"}
```

### Output Targets

Supports the following output targets:

- `stdout`: Standard output (default)
- `stderr`: Standard error output
- `file`: Output to file
- Or directly specify a file path

### File Rotation Configuration

When using file output, supports automatic file rotation:

- `file`: Log file path
- `max_size`: Maximum size of a single log file (MB), automatically rotates when exceeded
- `max_backups`: Number of old log files to retain
- `max_age`: Maximum days to retain log files
- `compress`: Whether to compress rotated log files

## Configuration Examples

### Basic Configuration (Console Output)
```yaml
log:
  level: "info"
  format: "text"
  output: "stdout"
```

### File Logging Configuration
```yaml
log:
  level: "debug"
  format: "json"
  output: "file"
  file: "logs/anyproxy.log"
  max_size: 50
  max_backups: 10
  max_age: 7
  compress: true
```

### Production Environment Configuration
```yaml
log:
  level: "warn"
  format: "json"
  output: "file"
  file: "/var/log/anyproxy/anyproxy.log"
  max_size: 100
  max_backups: 5
  max_age: 30
  compress: true
```

## Log Content

AnyProxy records the following types of log information:

### System Events
- Service startup and shutdown
- Configuration loading
- Component initialization

### Connection Events
- Client connections and disconnections
- Proxy connection establishment and closure
- WebSocket connection status

### Request Processing
- HTTP/HTTPS requests
- SOCKS5 connections
- Data transfer statistics

### Errors and Warnings
- Connection failures
- Authentication failures
- Configuration errors
- Network errors

## Performance Considerations

### Log Level Selection
- **Production Environment**: Recommend using `warn` or `error` level
- **Development Environment**: Can use `debug` or `info` level
- **Debugging Issues**: Temporarily set to `debug` level

### File Rotation Settings
- Adjust `max_size` based on disk space and log volume
- Set reasonable `max_backups` to avoid excessive disk usage
- Enable `compress` to save storage space

### JSON vs Text Format
- **JSON Format**: Convenient for log analysis tools, but slightly larger files
- **Text Format**: Good human readability, slightly smaller files

## Troubleshooting

### Log File Cannot Be Created
Ensure the log directory exists and has write permissions:
```bash
mkdir -p logs
chmod 755 logs
```

### Log Rotation Not Working
Check the following configuration:
- Whether `max_size` is set reasonably
- Whether disk space is sufficient
- Whether file permissions are correct

### Log Level Not Taking Effect
Ensure the configuration file format is correct, restart the service for configuration to take effect.

## Integration with Monitoring Systems

### ELK Stack
Use JSON format for easy Elasticsearch indexing:
```yaml
log:
  format: "json"
  output: "file"
  file: "/var/log/anyproxy/anyproxy.log"
```

### Prometheus + Grafana
Can create metrics based on log content to monitor:
- Connection count changes
- Error rates
- Response times

### Log Aggregation
Use tools like Fluentd, Filebeat to collect and forward logs to central logging systems. 