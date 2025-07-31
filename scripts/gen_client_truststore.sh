#!/bin/bash

username=$1
password=$2

path="resources/clients/$username"

echo "Generating $username truststore"

keytool -import -file rootca/CA-cert.pem -alias rootCA \
 -keystore $path/$username-truststore.p12 \
 -storepass $password \
 -noprompt
