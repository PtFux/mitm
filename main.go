package main

import (
	"log"
	"net/http"
	"proxy/proxy"
	"time"
)

func main() {

	// Create proxy server
	proxyServer, err := proxy.NewProxyServer(
		"ca.crt", // Путь к корневому сертификату
		"ca.key", // Путь к приватному ключу CA
		"certs",  // Директория для сертификатов хостов
	)

	if err != nil {
		log.Fatalf("Failed to create proxy: %v", err)
	}

	// Create API server
	//apiServer := proxy.NewAPIServer(proxyServer)

	// Start proxy server on port 8080
	//go func() {
	//	log.Printf("Starting proxy server on :8080")
	//	if err := http.ListenAndServe(":8080", proxyServer); err != nil {
	//		log.Fatalf("Proxy server error: %v", err)
	//	}
	//}()

	//// Start API server on port 8000
	//log.Printf("Starting API server on :8000")
	//if err := http.ListenAndServe(":8000", apiServer); err != nil {
	//	log.Fatalf("API server error: %v", err)
	//}

	// Настраиваем HTTP-сервер с таймаутами
	server := &http.Server{
		Addr:         ":8080",
		Handler:      proxyServer,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Запускаем сервер
	log.Printf("Starting proxy server on :8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Proxy server error: %v", err)
	}
}
