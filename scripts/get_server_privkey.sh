#!/bin/bash

# Get client private key from key file

password="123456"

key_path="resources/server/server-key.pem"
private_key_path="resources/server/server-private-key.pem"

# Debugging
echo "Input file path: $key_path"
echo "Output file path: $private_key_path"

openssl pkcs8 -topk8 -in $key_path -inform pem -out $private_key_path -outform pem -nocrypt -passin pass:$password
