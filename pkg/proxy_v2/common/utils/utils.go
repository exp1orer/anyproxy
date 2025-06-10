// Package utils provides common utility functions and helpers for the anyproxy v2 system.
// It includes string manipulation, data conversion, and other general-purpose utilities.
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

// GetMessageFields gets all field names from a message (for debugging)
func GetMessageFields(msg map[string]interface{}) []string {
	fields := make([]string, 0, len(msg))
	for key := range msg {
		fields = append(fields, key)
	}
	return fields
}
