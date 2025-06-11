// Package monitoring provides logging, metrics, and monitoring utilities for the anyproxy system.
// It includes log sampling, performance monitoring, and other observability features.
package monitoring

import (
	"sync/atomic"
	"time"
)

// LogSampler log sampler for reducing high-frequency logs
type LogSampler struct {
	counter  uint64
	interval uint64 // How often to record logs
}

// NewLogSampler creates a log sampler
func NewLogSampler(interval uint64) *LogSampler {
	if interval == 0 {
		interval = 1000 // Default: record once every 1000 times
	}
	return &LogSampler{
		interval: interval,
	}
}

// ShouldLog determines whether to record logs
func (s *LogSampler) ShouldLog() bool {
	count := atomic.AddUint64(&s.counter, 1)
	return count%s.interval == 0
}

// Count gets the current count
func (s *LogSampler) Count() uint64 {
	return atomic.LoadUint64(&s.counter)
}

// RateLimiter time-based rate limiter
type RateLimiter struct {
	lastLog    int64 // Last log time (nanoseconds)
	intervalNs int64 // Interval (nanoseconds)
}

// NewRateLimiter creates a rate limiter
func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		intervalNs: interval.Nanoseconds(),
	}
}

// ShouldLog determines whether to record logs
func (r *RateLimiter) ShouldLog() bool {
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&r.lastLog)

	if now-last < r.intervalNs {
		return false
	}

	// Try to update timestamp
	return atomic.CompareAndSwapInt64(&r.lastLog, last, now)
}

// Predefined global samplers
var (
	dataSampler  = NewLogSampler(1000)         // Data transfer logs: record once every 1000 times
	connSampler  = NewLogSampler(100)          // Connection logs: record once every 100 times
	msgSampler   = NewLogSampler(100)          // Message logs: record once every 100 times
	errorLimiter = NewRateLimiter(time.Second) // Error logs: maximum once per second
)

// ShouldLogData determines whether to record data transfer logs
func ShouldLogData() bool {
	return dataSampler.ShouldLog()
}

// ShouldLogConnection determines whether to record connection logs
func ShouldLogConnection() bool {
	return connSampler.ShouldLog()
}

// ShouldLogMessage determines whether to record message logs
func ShouldLogMessage() bool {
	return msgSampler.ShouldLog()
}

// ShouldLogError determines whether to record error logs (rate limited)
func ShouldLogError() bool {
	return errorLimiter.ShouldLog()
}
