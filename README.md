# zero-trust-server
A cryptographically secure file-server, following zero-trust and zero-knowledge architecture principles

The file server will have NO access to any unencrypted files, filekeys, or filenames.

This places the majority of focus on client side managment for handling access permissions and who has access to what keys

As this is a simulation of cloud-based storage, we will need our own CA, as well as sets of private/public key pairs for the clients and server

1. Generate root CA key and certificate, run:
    $ gen_ca_pair.sh

2. Run server (will create the keys, keystores/truststores):
    $ run_server.sh

3. Run client (will create the keys, keystores/truststores):
    $ run_client.sh

All sensitive data has been cleared from the repo, should you wish to experiment, fill out these folders with your own data 