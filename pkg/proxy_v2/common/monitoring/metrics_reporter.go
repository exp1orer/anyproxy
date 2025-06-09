package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/buhuipao/anyproxy/pkg/logger"
)

// MetricsReporter 指标报告器
type MetricsReporter struct {
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewMetricsReporter 创建指标报告器
func NewMetricsReporter(interval time.Duration) *MetricsReporter {
	if interval <= 0 {
		interval = 30 * time.Second // 默认30秒
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &MetricsReporter{
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start 启动定期报告
func (r *MetricsReporter) Start() {
	go r.run()
}

// Stop 停止报告
func (r *MetricsReporter) Stop() {
	r.cancel()
}

// run 运行报告循环
func (r *MetricsReporter) run() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.report()
		}
	}
}

// report 生成并输出报告
func (r *MetricsReporter) report() {
	metrics := GetMetrics()

	// 只在有活动时输出
	if metrics.TotalConnections == 0 && metrics.BytesSent == 0 && metrics.BytesReceived == 0 {
		return
	}

	// 简洁的一行输出
	logger.Info("Performance",
		"uptime", fmt.Sprintf("%dm", int(metrics.Uptime().Minutes())),
		"conns", fmt.Sprintf("%d/%d", metrics.ActiveConnections, metrics.TotalConnections),
		"success", fmt.Sprintf("%.0f%%", metrics.SuccessRate()),
		"sent", humanizeBytes(metrics.BytesSent),
		"recv", humanizeBytes(metrics.BytesReceived),
		"errors", metrics.ErrorCount,
	)
}

// 全局报告器实例
var globalReporter *MetricsReporter

// StartMetricsReporter 启动全局指标报告器
func StartMetricsReporter(interval time.Duration) {
	if globalReporter != nil {
		globalReporter.Stop()
	}
	globalReporter = NewMetricsReporter(interval)
	globalReporter.Start()
}

// StopMetricsReporter 停止全局指标报告器
func StopMetricsReporter() {
	if globalReporter != nil {
		globalReporter.Stop()
		globalReporter = nil
	}
}
