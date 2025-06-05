package transport

import "log/slog"

var transportCreatorMap = map[string]TransportCreator{}

// TransportCreator is a function that creates a Transport instance
type TransportCreator func(authConfig *AuthConfig) Transport

// RegisterTransportCreator registers a TransportCreator for a given transport name
func RegisterTransportCreator(name string, transportCreator TransportCreator) {
	transportCreatorMap[name] = transportCreator
}

// CreateTransport creates a Transport instance for a given transport name
func CreateTransport(name string, authConfig *AuthConfig) Transport {
	if _, ok := transportCreatorMap[name]; !ok {
		slog.Error("Transport creator not found", "transport_name", name)
		return nil
	}

	return transportCreatorMap[name](authConfig)
}
