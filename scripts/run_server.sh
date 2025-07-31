#!/bin/bash

# Run server scripts

echo "Running server scripts"

sh ./scripts/gen_server_pair.sh
sh ./scripts/gen_server_keystore.sh
sh ./scripts/gen_server_truststore.sh 
sh ./scripts/get_server_pubkey.sh 
sh ./scripts/get_server_privkey.sh 