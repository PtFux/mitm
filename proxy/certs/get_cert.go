package certs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func (cm *CertManager) GetCert(hostname string) (*tls.Certificate, error) {
	// Проверяем кеш
	if cert, ok := cm.certCache.Load(hostname); ok {
		return cert.(*tls.Certificate), nil
	}

	// Проверяем существование файлов сертификатов
	certPath := filepath.Join(cm.certDir, hostname+".crt")
	keyPath := filepath.Join(cm.certDir, hostname+".key")

	// Если сертификат существует - загружаем его
	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load existing cert: %w", err)
		}
		cm.certCache.Store(hostname, &cert)
		return &cert, nil
	}

	// Если сертификата нет - генерируем новый
	return cm.generateAndSaveCert(hostname)
}

func (cm *CertManager) generateAndSaveCert(hostname string) (*tls.Certificate, error) {
	// Генерируем приватный ключ
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Создаем шаблон сертификата
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	// Подписываем сертификат
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, cm.caCert, &privKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Сохраняем сертификат и ключ в файлы
	certOut, err := os.Create(filepath.Join(cm.certDir, hostname+".crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to open cert file: %w", err)
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyOut, err := os.OpenFile(filepath.Join(cm.certDir, hostname+".key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open key file: %w", err)
	}
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	// Создаем tls.Certificate
	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	cm.certCache.Store(hostname, &cert)
	return &cert, nil
}
