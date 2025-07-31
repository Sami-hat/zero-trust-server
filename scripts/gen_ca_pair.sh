#!/bin/bash

CA="CertAuth"

echo "Generating CA key and certificate"

# Generate the root CA key and certificate
openssl req -x509 -newkey rsa:4096 -keyout "rootca/CA-key.pem" \
 -out "rootca/CA-cert.pem" \
 -sha256 -days 365 -subj "/CN=CertAuth Root CA/C=GB/ST=Fife/L=STA/O=CertAuth" \
 -nodes 

# Verify the root CA certificate
openssl x509 -in rootca/CA-cert.pem -text -noout