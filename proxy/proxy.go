package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"proxy/proxy/certs"
	"strings"
	"sync"
	"time"
)

type ProxyServer struct {
	// requests хранит историю запросов для последующего анализа
	requests map[int]*RequestRecord // Изменено на int ключ

	// requestsLock обеспечивает безопасный доступ к requests
	requestsLock sync.RWMutex

	// certManager управляет SSL/TLS сертификатами
	certManager *certs.CertManager

	// transport используется для HTTP-запросов
	transport *http.Transport

	// httpsHandler обрабатывает HTTPS соединения
	//httpsHandler  http.HandlerFunc
	nextRequestID int
}

type ResponseRecord struct {
	Status     string
	StatusCode int
	Headers    http.Header
	Body       []byte
}

type RequestRecord struct {
	ID        int
	Method    string
	URL       *url.URL // Используем *url.URL вместо string
	Headers   http.Header
	Body      []byte
	Timestamp time.Time
	Response  *ResponseRecord
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
		requests:      make(map[int]*RequestRecord), // Используем int как ключ
		certManager:   certManager,
		transport:     transport,
		nextRequestID: 1, // Начинаем с ID = 1
	}, nil
}

func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleHTTPS(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}
func (p *ProxyServer) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Записываем запрос в историю
	reqRecord := p.recordRequest(r)

	// Подготавливаем запрос для пересылки
	outReq := p.prepareOutgoingRequest(r)
	if outReq == nil {
		http.Error(w, "Error creating outgoing request", http.StatusInternalServerError)
		return
	}

	// Отправляем запрос к целевому серверу
	client := &http.Client{
		Transport: p.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, "Error forwarding request: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Записываем ответ в историю
	p.recordResponse(reqRecord, resp)

	// Копируем заголовки ответа
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Копируем тело ответа
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Error copying response body: %v", err)
	}
}

func (p *ProxyServer) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}
	hostname := strings.Split(host, ":")[0]

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Failed to hijack connection: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		log.Printf("Failed to write 200 OK: %v", err)
		return
	}

	cert, err := p.certManager.GetCert(hostname)
	if err != nil {
		log.Printf("Failed to get certificate for %s: %v", hostname, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ServerName:   hostname,
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		tlsConn.Close()
		return
	}
	defer tlsConn.Close()

	targetConn, err := tls.Dial("tcp", host, &tls.Config{
		ServerName: hostname,
	})
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	// Чтение запроса с таймаутом
	tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	clientReader := bufio.NewReader(tlsConn)
	req, err := http.ReadRequest(clientReader)
	if err != nil {
		log.Printf("Error reading request: %v", err)
		return
	}
	tlsConn.SetReadDeadline(time.Time{})

	req.URL.Scheme = "https"
	req.URL.Host = host
	if reqRecord := p.recordRequest(req); reqRecord != nil {
		if err := req.Write(targetConn); err != nil {
			log.Printf("Error forwarding request: %v", err)
			return
		}

		// Чтение ответа с таймаутом
		targetConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(targetConn), req)
		targetConn.SetReadDeadline(time.Time{})
		if err != nil {
			log.Printf("Error reading response: %v", err)
			return
		}
		defer resp.Body.Close()

		p.recordResponse(reqRecord, resp)
		if err := resp.Write(tlsConn); err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}
}

func (p *ProxyServer) prepareOutgoingRequest(r *http.Request) *http.Request {
	targetURL := r.URL
	if targetURL.Scheme == "" {
		targetURL.Scheme = "http"
	}
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		return nil
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	outReq, err := http.NewRequest(r.Method, targetURL.String(), bytes.NewBuffer(bodyBytes))
	if err != nil {
		log.Printf("Error creating new request: %v", err)
		return nil
	}

	// Полное копирование заголовков
	outReq.Header = r.Header.Clone()
	outReq.Host = targetURL.Host

	// Копирование специальных полей
	outReq.Close = r.Close
	outReq.Trailer = r.Trailer
	outReq.TransferEncoding = r.TransferEncoding

	return outReq
}

func (p *ProxyServer) recordRequest(r *http.Request) *RequestRecord {
	p.requestsLock.Lock()
	defer p.requestsLock.Unlock()

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		return nil
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	record := &RequestRecord{
		ID:        p.nextRequestID,
		Method:    r.Method,
		URL:       r.URL,
		Headers:   r.Header.Clone(),
		Body:      bodyBytes,
		Timestamp: time.Now(),
	}

	p.requests[record.ID] = record
	p.nextRequestID++

	return record
}

func (p *ProxyServer) findRequest(r *http.Request) *RequestRecord {
	p.requestsLock.RLock()
	defer p.requestsLock.RUnlock()

	for _, req := range p.requests {
		if req.Method != r.Method {
			continue
		}

		// Сравниваем компоненты URL вместо String()
		if req.URL.Scheme == r.URL.Scheme &&
			req.URL.Host == r.URL.Host &&
			req.URL.Path == r.URL.Path &&
			req.URL.RawQuery == r.URL.RawQuery {
			return req
		}
	}
	return nil
}

// GetRequest возвращает запрос по ID
func (p *ProxyServer) GetRequest(id int) *RequestRecord {
	p.requestsLock.RLock()
	defer p.requestsLock.RUnlock()
	return p.requests[id]
}

// GetAllRequests возвращает все запросы
func (p *ProxyServer) GetAllRequests() []*RequestRecord {
	p.requestsLock.RLock()
	defer p.requestsLock.RUnlock()

	requests := make([]*RequestRecord, 0, len(p.requests))
	for _, req := range p.requests {
		requests = append(requests, req)
	}
	return requests
}

func (p *ProxyServer) recordResponse(reqRecord *RequestRecord, resp *http.Response) {
	if reqRecord == nil {
		log.Println("Attempt to record response for nil request")
		return
	}

	p.requestsLock.Lock()
	defer p.requestsLock.Unlock()

	// Ограничиваем максимальный размер тела 10MB
	maxBodySize := 10 * 1024 * 1024
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxBodySize)+1))
	if err != nil {
		log.Printf("Error reading response body: %v", err)
		return
	}

	if len(bodyBytes) > maxBodySize {
		bodyBytes = bodyBytes[:maxBodySize]
		log.Printf("Response body truncated to %d bytes", maxBodySize)
	}

	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	responseRecord := &ResponseRecord{
		Status:     resp.Status,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header.Clone(),
		Body:       bodyBytes,
	}

	if req, exists := p.requests[reqRecord.ID]; exists {
		req.Response = responseRecord
	} else {
		log.Printf("Request ID %d not found", reqRecord.ID)
	}
}
