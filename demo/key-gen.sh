#!/bin/bash

if [ "$1" = "rsa" ]; then
	echo "Generating the private key"
	openssl genrsa -out private.pem 2048
	echo "Generating the public key"
	openssl rsa -in private.pem -pubout -out public.pem
elif [ "$1" = "ed25519" ]; then
	echo "Generating the private key"
	openssl genpkey -algorithm ed25519 -out private.pem
	echo "Generating the public key"
	openssl pkey -in private.pem -pubout -out public.pem
elif [ "$1" = "ecdsa" ]; then
	echo "Generating the private key"
	openssl ecparam -name secp384r1 -genkey -noout -out private.pem
	echo "Generating the public key"
	openssl ec -in private.pem -pubout -out public.pem
else
	echo "Unknown algorithm"
fi
