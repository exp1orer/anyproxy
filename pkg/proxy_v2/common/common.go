// Package common provides shared utilities for AnyProxy v2.
package common

// The following type definitions need to be migrated or redefined from elsewhere
// These are all types that already exist in v1

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
