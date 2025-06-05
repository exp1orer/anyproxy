// Package main implements the AnyProxy client application.
// This is the v1 client that connects to the gateway and handles proxy requests.
package main

import (
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy"
)

func main() {
	// Parse command-line flags
	configFile := flag.String("config", "configs/config.yaml", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		logger.Error("Failed to load configuration", "err", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(&cfg.Log); err != nil {
		logger.Error("Failed to initialize logger", "err", err)
		os.Exit(1)
	}

	var clients []*proxy.Client
	for i := 0; i < cfg.Client.Replicas; i++ {
		// Create and start client
		client, err := proxy.NewClient(&cfg.Client)
		if err != nil {
			logger.Error("Failed to create client", "err", err)
			os.Exit(1)
		}

		// Start client (non-blocking)
		if err := client.Start(); err != nil {
			logger.Error("Failed to start client", "err", err)
			os.Exit(1)
		}

		clients = append(clients, client)
	}
	logger.Info("Started clients", "count", cfg.Client.Replicas, "gateway_addr", cfg.Client.GatewayAddr)

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	<-sigCh
	logger.Info("Shutting down...")

	// Stop all clients concurrently
	var stopWg sync.WaitGroup
	for _, client := range clients {
		stopWg.Add(1)
		go func(c *proxy.Client) {
			defer stopWg.Done()
			if err := c.Stop(); err != nil {
				logger.Error("Error shutting down client", "err", err)
			}
		}(client)
	}

	// Wait for all clients to stop
	stopWg.Wait()
	logger.Info("All clients stopped")
}
