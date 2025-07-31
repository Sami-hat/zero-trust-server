#!/bin/bash

username=$1
password=$2

path="resources/clients/$username"

echo "Generating client keystore"

openssl pkcs12 -export -in $path/$username-cert.pem \
 -out $path/$username-keystore.p12 -name $username \
 -inkey $path/$username-key.pem \
 -name $username -noiter -nomaciter \
 -passin pass:$password \
 -passout pass:$password
