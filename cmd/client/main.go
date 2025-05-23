package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"sync"
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

	var clients []*proxy.ProxyClient
	for i := 0; i < cfg.Client.Replicas; i++ {
		// Create and start client
		client, err := proxy.NewClient(&cfg.Client)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}

		// Start client (non-blocking)
		if err := client.Start(); err != nil {
			log.Fatalf("Failed to start client: %v", err)
		}

		clients = append(clients, client)
	}
	log.Printf("Started %d client(s), connecting to gateway at %s", cfg.Client.Replicas, cfg.Client.GatewayAddr)

	// Handle signals for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for termination signal
	<-sigCh
	log.Println("Shutting down...")

	// Stop all clients concurrently
	var stopWg sync.WaitGroup
	for _, client := range clients {
		stopWg.Add(1)
		go func(c *proxy.ProxyClient) {
			defer stopWg.Done()
			if err := c.Stop(); err != nil {
				log.Printf("Error shutting down client: %v", err)
			}
		}(client)
	}

	// Wait for all clients to stop
	stopWg.Wait()
	log.Println("All clients stopped")
}
