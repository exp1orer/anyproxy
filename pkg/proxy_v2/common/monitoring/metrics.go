package monitoring

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Metrics 全局性能指标
type Metrics struct {
	// 连接相关
	ActiveConnections int64 // 当前活跃连接数
	TotalConnections  int64 // 总连接数

	// 数据传输
	BytesSent     int64 // 发送字节数
	BytesReceived int64 // 接收字节数

	// 错误统计
	ErrorCount int64 // 错误次数

	// 启动时间
	StartTime time.Time
}

// Uptime 获取运行时长
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.StartTime)
}

// SuccessRate 计算成功率
func (m *Metrics) SuccessRate() float64 {
	total := atomic.LoadInt64(&m.TotalConnections)
	if total == 0 {
		return 100.0
	}
	errors := atomic.LoadInt64(&m.ErrorCount)
	return float64(total-errors) / float64(total) * 100
}

// 全局指标实例
var globalMetrics = &Metrics{
	StartTime: time.Now(),
}

// GetMetrics 获取全局指标
func GetMetrics() *Metrics {
	return globalMetrics
}

// IncrementActiveConnections 增加活跃连接数
func IncrementActiveConnections() {
	atomic.AddInt64(&globalMetrics.ActiveConnections, 1)
	atomic.AddInt64(&globalMetrics.TotalConnections, 1)
}

// DecrementActiveConnections 减少活跃连接数
func DecrementActiveConnections() {
	atomic.AddInt64(&globalMetrics.ActiveConnections, -1)
}

// AddBytesSent 添加发送字节数
func AddBytesSent(bytes int64) {
	atomic.AddInt64(&globalMetrics.BytesSent, bytes)
}

// AddBytesReceived 添加接收字节数
func AddBytesReceived(bytes int64) {
	atomic.AddInt64(&globalMetrics.BytesReceived, bytes)
}

// IncrementErrors 增加错误计数
func IncrementErrors() {
	atomic.AddInt64(&globalMetrics.ErrorCount, 1)
}

// humanizeBytes 转换字节数为人类可读格式
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
