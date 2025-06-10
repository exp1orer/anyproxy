// Package main implements the AnyProxy v2 client application.
// This is the v2 client with multi-transport support (WebSocket, gRPC, QUIC).
package main

import (
	"flag"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/client"
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

	var clients []*client.Client
	for i := 0; i < cfg.Client.Replicas; i++ {
		// Create and start client (using WebSocket transport layer)
		// Fix: Pass replica index i to ensure each client has unique ID
		proxyClient, err := client.NewClient(&cfg.Client, cfg.Transport.Type, i)
		if err != nil {
			logger.Error("Failed to create client", "replica_idx", i, "err", err)
			os.Exit(1)
		}

		// Start client (non-blocking)
		if err := proxyClient.Start(); err != nil {
			logger.Error("Failed to start client", "err", err)
			os.Exit(1)
		}

		clients = append(clients, proxyClient)
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
	for _, proxyClient := range clients {
		stopWg.Add(1)
		go func(c *client.Client) {
			defer stopWg.Done()
			if err := c.Stop(); err != nil {
				logger.Error("Error shutting down client", "err", err)
			}
		}(proxyClient)
	}

	// Wait for all clients to stop
	stopWg.Wait()
	logger.Info("All clients stopped")
}
