#!/bin/bash

path="resources/server"
password="123456"

echo "Generating server key and certificate"

openssl req -newkey rsa:4096 -keyout $path/server-key.pem \
 -out $path/server.csr \
 -subj "/CN=Server/O=YourOrg" \
 -passout pass:$password 

echo "Signing the server certificate with the root CA"

openssl x509 -req -in resources/server/server.csr -CA rootca/CA-cert.pem -CAkey rootca/CA-key.pem \
 -CAcreateserial -out resources/server/server-cert.pem \
 -sha256 -days 365 
