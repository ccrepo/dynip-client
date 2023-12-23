#!/bin/bash

# NOTE: all keys used in this program are 4096 long so limits the encode buffer to RSA (length % 8) = (11 padding bits)) = 501

if [[ ! -d client ]]
then
  mkdir client 2>/dev/null
fi

if [[ ! -d server ]]
then
  mkdir server 2>/dev/null
fi

# commands to generate keys

pwd

openssl genpkey -out server/server-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -outform pem -in server/server-private.key -out server/server-public.key

openssl genpkey -out client/client-private.key -algorithm RSA -pkeyopt rsa_keygen_bits:4096
openssl rsa -pubout -outform pem -in client/client-private.key -out client/client-public.key 

