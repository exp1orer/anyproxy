package monitoring

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Metrics global performance metrics
type Metrics struct {
	// Connection related
	ActiveConnections int64 // Current active connections
	TotalConnections  int64 // Total connections

	// Data transfer
	BytesSent     int64 // Bytes sent
	BytesReceived int64 // Bytes received

	// Error statistics
	ErrorCount int64 // Error count

	// Start time
	StartTime time.Time
}

// Uptime gets uptime duration
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.StartTime)
}

// SuccessRate calculates success rate
func (m *Metrics) SuccessRate() float64 {
	total := atomic.LoadInt64(&m.TotalConnections)
	if total == 0 {
		return 100.0
	}
	errors := atomic.LoadInt64(&m.ErrorCount)
	return float64(total-errors) / float64(total) * 100
}

// Global metrics instance
var globalMetrics = &Metrics{
	StartTime: time.Now(),
}

// GetMetrics gets global metrics
func GetMetrics() *Metrics {
	return globalMetrics
}

// IncrementActiveConnections increments active connections count
func IncrementActiveConnections() {
	atomic.AddInt64(&globalMetrics.ActiveConnections, 1)
	atomic.AddInt64(&globalMetrics.TotalConnections, 1)
}

// DecrementActiveConnections decrements active connections count
func DecrementActiveConnections() {
	atomic.AddInt64(&globalMetrics.ActiveConnections, -1)
}

// AddBytesSent adds bytes sent count
func AddBytesSent(bytes int64) {
	atomic.AddInt64(&globalMetrics.BytesSent, bytes)
}

// AddBytesReceived adds bytes received count
func AddBytesReceived(bytes int64) {
	atomic.AddInt64(&globalMetrics.BytesReceived, bytes)
}

// IncrementErrors increments error count
func IncrementErrors() {
	atomic.AddInt64(&globalMetrics.ErrorCount, 1)
}

// humanizeBytes converts bytes to human-readable format
func humanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
