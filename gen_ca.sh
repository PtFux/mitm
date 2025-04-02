# !/bin/bash

# Generate root CA private key
openssl genrsa -out ca.key 2048

# Generate root CA certificate
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -subj "/CN=Proxy Root CA"

# Create directory for certificates
mkdir -p certs 