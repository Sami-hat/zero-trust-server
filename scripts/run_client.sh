#!/bin/bash

username=$1
password=$2

path="resources/clients"

echo "Running client scripts with username $username and password $password"

sh ./scripts/gen_client_pair.sh "$username" "$password"
sh ./scripts/gen_client_keystore.sh "$username" "$password"
sh ./scripts/gen_client_truststore.sh "$username" "$password"
sh ./scripts/get_client_pubkey.sh "$username"
sh ./scripts/get_client_privkey.sh "$username" "$password"