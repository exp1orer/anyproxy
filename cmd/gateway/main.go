package main

import (
	"flag"
	"log/slog"
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
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Initialize logger
	if err := logger.Init(&cfg.Log); err != nil {
		slog.Error("Failed to initialize logger", "error", err)
		os.Exit(1)
	}

	// Create and start gateway
	gateway, err := proxy.NewGateway(cfg)
	if err != nil {
		slog.Error("Failed to create gateway", "error", err)
		os.Exit(1)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start gateway in a separate goroutine
	go func() {
		if err := gateway.Start(); err != nil {
			slog.Error("Gateway failed", "error", err)
			os.Exit(1)
		}
	}()

	slog.Info("Gateway started", "listen_addr", cfg.Gateway.ListenAddr)

	// Wait for termination signal
	<-sigCh
	slog.Info("Shutting down...")

	// Stop gateway
	if err := gateway.Stop(); err != nil {
		slog.Error("Error shutting down gateway", "error", err)
	}

	slog.Info("Gateway stopped")
}
