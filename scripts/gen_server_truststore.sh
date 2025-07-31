#!/bin/bash

path="resources/server"
password="123456"

echo "Generating server truststore"

keytool -import -file rootca/CA-cert.pem -alias rootCA \
 -keystore $path/server-truststore.p12 \
 -storepass $password \
 -noprompt
