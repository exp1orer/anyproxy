#!/bin/bash


# Get the domain from the first argument
DOMAIN=$1
if [ -z "$DOMAIN" ]; then
    DOMAIN="localhost"
fi

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=$DOMAIN" -addext "subjectAltName = DNS:$DOMAIN,IP:127.0.0.1"

echo "Certificate generated successfully!"
echo "Certificate location: certs/server.crt"
echo "Key location: certs/server.key" 