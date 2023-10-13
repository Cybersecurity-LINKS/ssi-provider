## Build

`did-create-demo.c` lets you create a DID document given a public key that will be used as authentication key and assertion key.

    nano Makefile

Edit the first two lines: `OPENSSL_DIR=/path/to/openssl`. `OPENSSL_LIB` is either equal to `lib` for 32-bit OS or `lib64` for 64-bit OS. Then run

    make

## Usage

First generate a public key and name it `did-public.pem`, like in the following way:

    openssl genrsa -out did-private.pem 2048
    openssl rsa -in did-private.pem -pubout -out did-public.pem

Then run the executable with no additional parameters
