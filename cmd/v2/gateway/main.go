// Package main implements the AnyProxy v2 gateway server application.
// This is the v2 gateway with multi-transport support (WebSocket, gRPC, QUIC).
package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/logger"
	"github.com/buhuipao/anyproxy/pkg/proxy_v2/gateway"
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

	// Create and start gateway (using WebSocket transport layer)
	gw, err := gateway.NewGateway(cfg, cfg.Transport.Type)
	if err != nil {
		logger.Error("Failed to create gateway", "err", err)
		os.Exit(1)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start gateway in a separate goroutine
	go func() {
		if err := gw.Start(); err != nil {
			logger.Error("Gateway failed", "err", err)
			os.Exit(1)
		}
	}()

	logger.Info("Gateway started", "listen_addr", cfg.Gateway.ListenAddr)

	// Wait for termination signal
	<-sigCh
	logger.Info("Shutting down...")

	// Stop gateway
	if err := gw.Stop(); err != nil {
		logger.Error("Error shutting down gateway", "err", err)
	}

	logger.Info("Gateway stopped")
}
