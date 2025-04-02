package certs

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sync"
)

type CertManager struct {
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	certCache sync.Map // Кеш сертификатов [hostname]*tls.Certificate
	certDir   string   // Директория с сертификатами
}

func NewCertManager(caCertPath, caKeyPath, certDir string) (*CertManager, error) {
	// Загрузка CA сертификата
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, errors.New("failed to parse CA cert PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}

	// Загрузка CA ключа (поддержка PKCS#1 и PKCS#8)
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key: %w", err)
	}

	block, _ = pem.Decode(caKeyPEM)
	if block == nil {
		return nil, errors.New("failed to parse CA key PEM")
	}

	var caKey *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		// PKCS#1 формат
		caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		// PKCS#8 формат
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 key: %w", err)
		}
		var ok bool
		caKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
	} else {
		return nil, fmt.Errorf("unsupported private key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse CA key: %w", err)
	}

	return &CertManager{
		caCert:  caCert,
		caKey:   caKey,
		certDir: certDir,
	}, nil
}
