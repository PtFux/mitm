package main

import (
	"log"
	"net/http"
	"proxy/proxy"
)

func main() {
	// Create proxy server
	proxyServer := proxy.NewProxyServer()

	// Create API server
	apiServer := proxy.NewAPIServer(proxyServer)

	// Start proxy server on port 8080
	go func() {
		log.Printf("Starting proxy server on :8080")
		if err := http.ListenAndServe(":8080", proxyServer); err != nil {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Start API server on port 8000
	log.Printf("Starting API server on :8000")
	if err := http.ListenAndServe(":8000", apiServer); err != nil {
		log.Fatalf("API server error: %v", err)
	}
}
