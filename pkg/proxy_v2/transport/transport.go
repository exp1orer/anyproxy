package transport

import "github.com/buhuipao/anyproxy/pkg/logger"

var transportCreatorMap = map[string]Creator{}

// Creator is a function that creates a Transport instance
type Creator func(authConfig *AuthConfig) Transport

// RegisterTransportCreator registers a Creator for a given transport name
func RegisterTransportCreator(name string, transportCreator Creator) {
	transportCreatorMap[name] = transportCreator
}

// CreateTransport creates a Transport instance for a given transport name
func CreateTransport(name string, authConfig *AuthConfig) Transport {
	if _, ok := transportCreatorMap[name]; !ok {
		logger.Error("Transport creator not found", "transport_name", name)
		return nil
	}

	return transportCreatorMap[name](authConfig)
}
