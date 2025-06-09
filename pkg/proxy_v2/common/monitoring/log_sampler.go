package monitoring

import (
	"sync/atomic"
	"time"
)

// LogSampler 日志采样器，用于减少高频日志
type LogSampler struct {
	counter  uint64
	interval uint64 // 每隔多少次记录一次
}

// NewLogSampler 创建日志采样器
func NewLogSampler(interval uint64) *LogSampler {
	if interval == 0 {
		interval = 1000 // 默认每1000次记录一次
	}
	return &LogSampler{
		interval: interval,
	}
}

// ShouldLog 判断是否应该记录日志
func (s *LogSampler) ShouldLog() bool {
	count := atomic.AddUint64(&s.counter, 1)
	return count%s.interval == 0
}

// Count 获取当前计数
func (s *LogSampler) Count() uint64 {
	return atomic.LoadUint64(&s.counter)
}

// RateLimiter 基于时间的限流器
type RateLimiter struct {
	lastLog    int64 // 上次记录时间（纳秒）
	intervalNs int64 // 间隔（纳秒）
}

// NewRateLimiter 创建限流器
func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		intervalNs: interval.Nanoseconds(),
	}
}

// ShouldLog 判断是否应该记录日志
func (r *RateLimiter) ShouldLog() bool {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&r.lastLog)

	if now-last < r.intervalNs {
		return false
	}

	// 尝试更新时间戳
	return atomic.CompareAndSwapInt64(&r.lastLog, last, now)
}

// 预定义的全局采样器
var (
	dataSampler  = NewLogSampler(1000)         // 数据传输日志：每1000次记录一次
	connSampler  = NewLogSampler(100)          // 连接日志：每100次记录一次
	msgSampler   = NewLogSampler(100)          // 消息日志：每100次记录一次
	errorLimiter = NewRateLimiter(time.Second) // 错误日志：每秒最多一次
)

// ShouldLogData 判断是否应该记录数据传输日志
func ShouldLogData() bool {
	return dataSampler.ShouldLog()
}

// ShouldLogConnection 判断是否应该记录连接日志
func ShouldLogConnection() bool {
	return connSampler.ShouldLog()
}

// ShouldLogMessage 判断是否应该记录消息日志
func ShouldLogMessage() bool {
	return msgSampler.ShouldLog()
}

// ShouldLogError 判断是否应该记录错误日志（限流）
func ShouldLogError() bool {
	return errorLimiter.ShouldLog()
}
