#!/bin/bash

path="resources/server"
password="123456"

echo "Generating server keystore"

openssl pkcs12 -export -in $path/server-cert.pem \
 -inkey $path/server-key.pem \
 -out $path/server-keystore.p12 -name server \
 -CAfile rootca/CA-cert.pem -caname rootCA \
 -passin pass:$password \
 -passout pass:$password