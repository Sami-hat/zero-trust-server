#!/bin/bash

# Get server public key from certificate

cert_path="resources/server/server-cert.pem"
pubkey_path="resources/pubkeys/server-public-key.pem"

echo "Getting server public key"

openssl x509 -pubkey -noout -in $cert_path > $pubkey_path