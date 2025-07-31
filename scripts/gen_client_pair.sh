#!/bin/bash

username=$1
password=$2

echo "Creating client directory for $username"

mkdir -p resources/clients/$username

path="resources/clients/$username"

echo "Generating client key and certificate for $username"

openssl req -newkey rsa:2048 -keyout $path/$username-key.pem \
 -out $path/$username.csr \
 -subj "/O=YourOrg/C=GB/ST=Fife/L=STA/CN=$username" \
 -passout pass:$password \
 -passin pass:$password

echo "Signing the client certificate with the root CA"

openssl x509 -req -in $path/$username.csr -CA rootca/CA-cert.pem -CAkey rootca/CA-key.pem \
 -CAcreateserial -out $path/$username-cert.pem \
 -sha256 -days 365 
