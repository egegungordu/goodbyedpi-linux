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
	// --dns-addr 77.88.8.8 --dns-port 1253 --dnsv6-addr 2a02:6b8::feed:0ff --dnsv6-port 1253
	proxyServer, err := proxy.NewServer(true, false, false, &proxy.DNSConfig{
		IPv4Addr: "77.88.8.8",
		IPv4Port: 1253,
		IPv6Addr: "2a02:6b8::feed:0ff",
		IPv6Port: 1253,
	})
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