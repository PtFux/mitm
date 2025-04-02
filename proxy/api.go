package proxy

import (
	"encoding/json"
	"net/http"
	"strings"
)

type APIServer struct {
	proxyServer *ProxyServer
}

func NewAPIServer(proxyServer *ProxyServer) *APIServer {
	return &APIServer{
		proxyServer: proxyServer,
	}
}

func (a *APIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/requests":
		if r.Method == http.MethodGet {
			a.handleListRequests(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	case "/scan":
		if r.Method == http.MethodPost {
			a.handleScanRequest(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (a *APIServer) handleListRequests(w http.ResponseWriter, r *http.Request) {
	requests := a.proxyServer.GetAllRequests()
	json.NewEncoder(w).Encode(requests)
}

func (a *APIServer) handleScanRequest(w http.ResponseWriter, r *http.Request) {
	// Parse request ID from query parameters
	requestID := r.URL.Query().Get("id")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	// Get the request
	req := a.proxyServer.GetRequest(requestID)
	if req == nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	// Perform basic vulnerability scanning
	scanResults := a.scanRequest(req)
	json.NewEncoder(w).Encode(scanResults)
}

type ScanResult struct {
	Vulnerabilities []string `json:"vulnerabilities"`
}

func (a *APIServer) scanRequest(req *http.Request) ScanResult {
	result := ScanResult{
		Vulnerabilities: make([]string, 0),
	}

	// Check for common vulnerabilities
	// 1. SQL Injection in query parameters
	for _, values := range req.URL.Query() {
		for _, value := range values {
			if containsSQLInjection(value) {
				result.Vulnerabilities = append(result.Vulnerabilities, "Potential SQL Injection in query parameters")
			}
		}
	}

	// 2. XSS in query parameters
	for _, values := range req.URL.Query() {
		for _, value := range values {
			if containsXSS(value) {
				result.Vulnerabilities = append(result.Vulnerabilities, "Potential XSS in query parameters")
			}
		}
	}

	// 3. Check for sensitive headers
	if req.Header.Get("Authorization") != "" {
		result.Vulnerabilities = append(result.Vulnerabilities, "Authorization header present - potential sensitive data")
	}

	return result
}

func containsSQLInjection(input string) bool {
	sqlKeywords := []string{"'", "1' OR '1'='1", "1; DROP TABLE", "UNION SELECT", "--"}
	for _, keyword := range sqlKeywords {
		if strings.Contains(strings.ToLower(input), strings.ToLower(keyword)) {
			return true
		}
	}
	return false
}

func containsXSS(input string) bool {
	xssPatterns := []string{"<script>", "javascript:", "onerror=", "onload="}
	for _, pattern := range xssPatterns {
		if strings.Contains(strings.ToLower(input), strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
