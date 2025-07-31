#!/bin/bash

# Get client private key from key file

username=$1
password=$2

key_path="resources/clients/$username/$username-key.pem"
private_key_path="resources/clients/$username/$username-private-key.pem"

# Debugging
echo "Input file path: $key_path"
echo "Output file path: $private_key_path"

openssl pkcs8 -topk8 -in $key_path -inform pem -out $private_key_path -outform pem -nocrypt -passin pass:$password
