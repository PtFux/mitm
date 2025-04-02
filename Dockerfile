FROM golang:1.21-alpine

WORKDIR /app

# Install OpenSSL for certificate generation
RUN apk add --no-cache openssl

# Copy source code
COPY . .


# First copy only the scripts needed for certificate generation
COPY gen_ca.sh gen_cert.sh ./

# Make certificate generation scripts executable
RUN chmod +x ./gen_ca.sh ./gen_cert.sh

# Generate root certificate
RUN ./gen_ca.sh

# Copy Go module files
COPY go.mod ./

# Download dependencies
RUN go mod tidy


# Build the application
RUN go build -o proxy-server

# Expose ports
EXPOSE 8080 8000

# Run the proxy server
CMD ["./proxy-server"] 