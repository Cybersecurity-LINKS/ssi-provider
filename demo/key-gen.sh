#!/bin/bash

if [ "$1" = "rsa" ]; then
	echo "Generating RSA private key"
	echo ".."
	openssl genrsa -out private.pem 2048
	echo "Done generating RSA private key"
	echo "Generating RSA public key"
	echo ".."
	openssl rsa -in private.pem -pubout -out public.pem
	echo "Done generating RSA public key"
elif [ "$1" = "ed25519" ]; then
	echo "Generating ED25519 private key"
	echo ".."
	openssl genpkey -algorithm ed25519 -out private.pem
	echo "Done generating ED25519 private key"
	echo "Generating ED25519 public key"
	echo ".."
	openssl pkey -in private.pem -pubout -out public.pem
	echo "Done generating ED25519 public key"
elif [ "$1" = "ecdsa" ]; then
	echo "Generating ECDSA private key"
	echo ".."
	openssl ecparam -name prime256v1 -genkey -noout -out private.pem
	echo "Done generating ECDSA private key"
	echo "Generating ECDSA public key"
	echo ".."
	openssl ec -in private.pem -pubout -out public.pem
	echo "Done generating ECDSA public key"
else
	echo "Unknown algorithm"
	echo "usage: $0 [ALGORITHM]"
	echo ""
	echo "Algorithms:"
	echo "rsa"
	echo "ed25519"
	echo "ecdsa"
fi
