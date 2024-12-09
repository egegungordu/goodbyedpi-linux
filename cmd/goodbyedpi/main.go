package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/egegungordu/goodbyedpi-linux/internal/proxy"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create signal channel for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize the proxy server
	proxyServer, err := proxy.NewServer(true, false, false)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Start the proxy server in a goroutine
	go func() {
		if err := proxyServer.Start(ctx); err != nil {
			log.Printf("Proxy server error: %v", err)
			cancel()
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	log.Println("Shutting down...")
	cancel()
} 