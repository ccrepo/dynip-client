#!/bin/sh

# NOTE: all keys used in this program are 4096 long so limits the encode buffer to RSA (length % 8) = (11 padding bits)) = 501
\mkdir client

# commands to generate keys
\openssl genpkey -out client/server-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
\openssl rsa -pubout -outform pem -in client/server-private.key -out client/server-public.key
\openssl genpkey -out client/client-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
\openssl rsa -pubout -outform pem -in client/client-private.key -out client/client-public.key 
