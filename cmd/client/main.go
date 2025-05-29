package main

import (
	"flag"
	"log/slog"
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
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(&cfg.Log); err != nil {
		slog.Error("Failed to initialize logger", "error", err)
		os.Exit(1)
	}

	var clients []*proxy.ProxyClient
	for i := 0; i < cfg.Client.Replicas; i++ {
		// Create and start client
		client, err := proxy.NewClient(&cfg.Client)
		if err != nil {
			slog.Error("Failed to create client", "error", err)
			os.Exit(1)
		}

		// Start client (non-blocking)
		if err := client.Start(); err != nil {
			slog.Error("Failed to start client", "error", err)
			os.Exit(1)
		}

		clients = append(clients, client)
	}
	slog.Info("Started clients", "count", cfg.Client.Replicas, "gateway_addr", cfg.Client.GatewayAddr)

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	<-sigCh
	slog.Info("Shutting down...")

	// Stop all clients concurrently
	var stopWg sync.WaitGroup
	for _, client := range clients {
		stopWg.Add(1)
		go func(c *proxy.ProxyClient) {
			defer stopWg.Done()
			if err := c.Stop(); err != nil {
				slog.Error("Error shutting down client", "error", err)
			}
		}(client)
	}

	// Wait for all clients to stop
	stopWg.Wait()
	slog.Info("All clients stopped")
}
