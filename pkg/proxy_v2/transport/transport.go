// Package transport defines transport layer abstractions.
package transport

import (
	"sync"

	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/common/protocol"
)

var (
	transportCreatorMap = map[string]Creator{}
	transportMutex      sync.RWMutex // Fix: Add read-write lock to protect concurrent access
)

// Creator is a function that creates a Transport instance
type Creator func(authConfig *AuthConfig) Transport

// RegisterTransportCreator registers a Creator for a given transport name
func RegisterTransportCreator(name string, transportCreator Creator) {
	// Fix: Use write lock to protect registration operation
	transportMutex.Lock()
	defer transportMutex.Unlock()

	transportCreatorMap[name] = transportCreator
	logger.Debug("Registered transport creator", "transport_name", name)
}

// CreateTransport creates a Transport instance for a given transport name
func CreateTransport(name string, authConfig *AuthConfig) Transport {
	// Fix: If empty string is passed, use default transport type
	if name == "" {
		name = protocol.TransportTypeDefault
		logger.Debug("Using default transport type", "transport_type", name)
	}

	// Fix: Use read lock to protect read operation
	transportMutex.RLock()
	creator, ok := transportCreatorMap[name]
	transportMutex.RUnlock()

	if !ok {
		logger.Error("Transport creator not found", "transport_name", name, "available_transports", getRegisteredTransports())
		return nil
	}

	return creator(authConfig)
}

// getRegisteredTransports returns a list of registered transport names for debugging
func getRegisteredTransports() []string {
	transportMutex.RLock()
	defer transportMutex.RUnlock()

	names := make([]string, 0, len(transportCreatorMap))
	for name := range transportCreatorMap {
		names = append(names, name)
	}
	return names
}
