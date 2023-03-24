#!/bin/bash

ALGORITHM=$1
ACTOR=$2

if [ $# -ne 2 ]; then
	echo "usage: $0 [ALGORITHM] [ACTOR]"
		echo ""
		echo "Algorithms:"
		echo "- rsa"
		echo "- ed25519"
		echo "- ecdsa"
		echo ""
		echo "Actors:"
		echo "- client"
		echo "- server"
		echo ""
		exit 0
fi

make clean
make
echo ""

for i in {1..4}
do	
	echo "Iteration #$i"
	echo ""
	if [ "$ALGORITHM" = "rsa" ]; then
		echo "Generating RSA private key"
		echo ".."
		openssl genrsa -out private.pem 2048
		echo "Done generating RSA private key"
		echo "-------------------------------"
		echo "Generating RSA public key"
		echo ".."
		openssl rsa -in private.pem -pubout -out public.pem
		echo "Done generating RSA public key"
	elif [ "$ALGORITHM" = "ed25519" ]; then
		echo "Generating ED25519 private key"
		echo ".."
		openssl genpkey -algorithm ed25519 -out private.pem
		echo "Done generating ED25519 private key"
		echo "-----------------------------------"
		echo "Generating ED25519 public key"
		echo ".."
		openssl pkey -in private.pem -pubout -out public.pem
		echo "Done generating ED25519 public key"
	elif [ "$ALGORITHM" = "ecdsa" ]; then
		echo "Generating ECDSA private key"
		echo ".."
		openssl ecparam -name prime256v1 -genkey -noout -out private.pem
		echo "Done generating ECDSA private key"
		echo "---------------------------------"
		echo "Generating ECDSA public key"
		echo ".."
		openssl ec -in private.pem -pubout -out public.pem
		echo "Done generating ECDSA public key"
	else
		echo "Unknown algorithm"
		echo ""
		echo "Known algorithms:"
		echo "- rsa"
		echo "- ed25519"
		echo "- ecdsa"
		exit 0
	fi
	
	echo "----------------------------"
	echo "Performing DID CREATE .."
	echo ""
	./demo
	echo ""
	echo "DID CREATE Completed"
	echo "----------------------------"
	
	if [ ! -d $ACTOR ]; then
		mkdir $ACTOR
	fi 
	
	echo "Moving DID and cryptographic material in $ACTOR folder" 
	mkdir $i
	mv public.pem private.pem did.txt $i/
	mv $i $ACTOR/
	rm *.txt
	
	echo "Done"
	echo "-------------------------------"
	echo -e "\n\n"
done



