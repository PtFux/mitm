package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"proxy/proxy/certs"
	"strings"
	"sync"
)

type ProxyServer struct {
	// requests хранит историю запросов для последующего анализа
	requests map[string]*http.Request

	// requestsLock обеспечивает безопасный доступ к requests
	requestsLock sync.RWMutex

	// certManager управляет SSL/TLS сертификатами
	certManager *certs.CertManager

	// transport используется для HTTP-запросов
	transport *http.Transport

	// httpsHandler обрабатывает HTTPS соединения
	httpsHandler http.HandlerFunc
}

// NewProxyServer создает новый экземпляр прокси-сервера с поддержкой HTTPS
// caCertPath - путь к файлу корневого сертификата CA
// caKeyPath - путь к файлу приватного ключа CA
// certDir - директория для хранения сертификатов хостов
func NewProxyServer(caCertPath, caKeyPath, certDir string) (*ProxyServer, error) {
	// Инициализируем менеджер сертификатов
	certManager, err := certs.NewCertManager(caCertPath, caKeyPath, certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate manager: %w", err)
	}

	// Создаем транспорт с настройками по умолчанию
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Мы сами проверяем сертификаты
		},
	}

	return &ProxyServer{
		requests:     make(map[string]*http.Request),
		certManager:  certManager,
		transport:    transport,
		httpsHandler: makeHTTPSHandler(certManager, transport),
	}, nil
}

// makeHTTPSHandler создает обработчик HTTPS соединений
func makeHTTPSHandler(certManager *certs.CertManager, transport *http.Transport) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Host
		if !strings.Contains(host, ":") {
			host = host + ":443"
		}
		hostname := strings.Split(host, ":")[0]

		// Получаем сертификат для хоста
		cert, err := certManager.GetCert(hostname)
		if err != nil {
			http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
			return
		}

		// Хайджекаем соединение
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}

		clientConn, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
			return
		}

		// Отправляем 200 Connection established
		_, _ = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

		// Настраиваем TLS соединение
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*cert},
			ServerName:   hostname,
		}

		tlsConn := tls.Server(clientConn, tlsConfig)
		defer tlsConn.Close()

		// Устанавливаем соединение с целевым сервером
		targetConn, err := tls.Dial("tcp", host, &tls.Config{
			ServerName: hostname,
		})
		if err != nil {
			log.Printf("Failed to connect to target: %v", err)
			return
		}
		defer targetConn.Close()

		// Туннелируем данные
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			io.Copy(targetConn, tlsConn)
		}()

		go func() {
			defer wg.Done()
			io.Copy(tlsConn, targetConn)
		}()

		wg.Wait()
	}
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.httpsHandler(w, r)
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

	// Устанавливаем Host header
	proxyReq.Host = targetURL.Hostname()

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
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Printf("Error copying response body: %v", err)
	}
	log.Printf("Response headers: %v", resp.Header)
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	hostname := strings.Split(host, ":")[0]

	// Получаем или генерируем сертификат
	cert, err := p.certManager.GetCert(hostname)
	if err != nil {
		http.Error(w, "Failed to get certificate", http.StatusInternalServerError)
		return
	}

	// Хайджекаем соединение
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}

	// Отправляем 200 Connection established
	_, _ = clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

	// Настраиваем TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ServerName:   hostname,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	defer tlsConn.Close()

	// Устанавливаем соединение с целевым сервером
	targetConn, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		log.Printf("Failed to connect to target: %v", err)
		return
	}
	defer targetConn.Close()

	// Туннелируем данные
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, tlsConn)
	}()

	go func() {
		defer wg.Done()
		io.Copy(tlsConn, targetConn)
	}()

	wg.Wait()
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
