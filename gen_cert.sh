# !/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <hostname>"
    exit 1
fi

HOSTNAME=$1

# Generate private key for the host
openssl genrsa -out certs/$HOSTNAME.key 2048

# Generate CSR
openssl req -new -key certs/$HOSTNAME.key -out certs/$HOSTNAME.csr -subj "/CN=$HOSTNAME"

# Sign the certificate with our CA
openssl x509 -req -in certs/$HOSTNAME.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out certs/$HOSTNAME.crt -days 365 -sha256

# Clean up CSR
rm certs/$HOSTNAME.csr 