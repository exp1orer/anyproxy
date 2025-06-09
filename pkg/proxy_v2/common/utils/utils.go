package utils

import (
	"github.com/rs/xid"
)

// UserContext user context (same as v1)
type UserContext struct {
	Username string
	GroupID  string
}

// GatewayProxy proxy interface (simplified version - only keeps truly used methods)
type GatewayProxy interface {
	// Start starts the proxy server
	Start() error
	// Stop stops the proxy server
	Stop() error
}

// GenerateConnID generate a unique connection ID
func GenerateConnID() string {
	// use xid to generate a unique connection ID
	// Length: 20 characters
	return xid.New().String()
}

// GetMessageFields 获取消息的所有字段名（用于调试）
func GetMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}
