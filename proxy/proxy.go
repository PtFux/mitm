package proxy

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
)

type ProxyServer struct {
	requests     map[string]*http.Request
	requestsLock sync.RWMutex
}

func NewProxyServer() *ProxyServer {
	return &ProxyServer{
		requests: make(map[string]*http.Request),
	}
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Store request for later retrieval
	p.requestsLock.Lock()
	p.requests[r.URL.String()] = r
	p.requestsLock.Unlock()

	// Create new request with correct URL (including scheme)
	targetURL := r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http" // или "https" если нужно
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}

	//// Create new request
	//proxyURL, err := url.Parse(r.URL.String())
	//if err != nil {
	//	http.Error(w, "Invalid URL", http.StatusBadRequest)
	//	return
	//}

	proxyReq, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		http.Error(w, "Error creating request", http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		if key != "Proxy-Connection" {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
	}

	// Send request to target
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Не следовать редиректам
		},
	}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Error forwarding request"+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		if key != "Proxy-Connection" && key != "Connection" {
			for _, value := range values {
				proxyReq.Header.Add(key, value)
			}
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	io.Copy(w, resp.Body)
	log.Printf("Response headers: %v", resp.Header)
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Connect to target
	targetConn, err := net.Dial("tcp", host)
	if err != nil {
		http.Error(w, "Error connecting to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	// Send 200 Connection established
	w.WriteHeader(http.StatusOK)

	// Hijack connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Error hijacking connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Start bidirectional copy
	go io.Copy(targetConn, clientConn)
	io.Copy(clientConn, targetConn)
}

// GetRequest retrieves a stored request by ID
func (p *ProxyServer) GetRequest(id string) *http.Request {
	p.requestsLock.RLock()
	defer p.requestsLock.RUnlock()
	return p.requests[id]
}

// GetAllRequests returns all stored requests
func (p *ProxyServer) GetAllRequests() []*http.Request {
	p.requestsLock.RLock()
	defer p.requestsLock.RUnlock()
	requests := make([]*http.Request, 0, len(p.requests))
	for _, req := range p.requests {
		requests = append(requests, req)
	}
	return requests
}
