#!/bin/bash

# Extract username from certificate

username=$1
path="resources/clients/$username/$username-cert.pem"

echo "Extracting username from client1-cert.pem"

openssl x509 -noout -subject -in $path | sed -n 's/ *CN *= //p'