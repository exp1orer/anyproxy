package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/buhuipao/anyproxy/pkg/config"
	"github.com/buhuipao/anyproxy/pkg/proxy"
)

func main() {
	// Parse command-line flags
	configFile := flag.String("config", "configs/config.yaml", "Path to the configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create and start gateway
	gateway, err := proxy.NewGateway(cfg)
	if err != nil {
		log.Fatalf("Failed to create gateway: %v", err)
	}

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start gateway in a separate goroutine
	go func() {
		if err := gateway.Start(); err != nil {
			log.Fatalf("Gateway failed: %v", err)
		}
	}()

	log.Printf("Gateway started on %s", cfg.Gateway.ListenAddr)

	// Wait for termination signal
	<-sigCh
	log.Println("Shutting down...")

	// Stop gateway
	if err := gateway.Stop(); err != nil {
		log.Printf("Error shutting down gateway: %v", err)
	}

	log.Println("Gateway stopped")
}
