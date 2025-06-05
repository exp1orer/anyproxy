// Package main implements the AnyProxy gateway server application.
// This is the v1 gateway that accepts client connections and handles proxy traffic.
package main

import (
	"flag"
	"os"
	"os/signal"
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

	// Create and start gateway
	gateway, err := proxy.NewGateway(cfg)
	if err != nil {
		logger.Error("Failed to create gateway", "err", err)
		os.Exit(1)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start gateway in a separate goroutine
	go func() {
		if err := gateway.Start(); err != nil {
			logger.Error("Gateway failed", "err", err)
			os.Exit(1)
		}
	}()

	logger.Info("Gateway started", "listen_addr", cfg.Gateway.ListenAddr)

	// Wait for termination signal
	<-sigCh
	logger.Info("Shutting down...")

	// Stop gateway
	if err := gateway.Stop(); err != nil {
		logger.Error("Error shutting down gateway", "err", err)
	}

	logger.Info("Gateway stopped")
}
