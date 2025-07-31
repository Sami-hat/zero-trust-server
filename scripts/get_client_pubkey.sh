#!/bin/bash

# Get client public key from certificate

username=$1

cert_path="resources/clients/$username/$username-cert.pem"
pubkey_path="resources/pubkeys/$username-public-key.pem"

echo "Getting $username public key"

openssl x509 -pubkey -noout -in $cert_path > $pubkey_path