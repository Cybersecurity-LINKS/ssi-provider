`did-create-demo.c` lets you create a DID document given a public key.

## Build

Before building, edit the first two lines of the `Makefile` where `OPENSSL_DIR=/path/to/openssl` and `OPENSSL_LIB` is either equal to `lib` for a 32-bit OS or `lib64` for a 64-bit OS. Then run

    make

## Usage

First generate a public key and name it `did-public.pem`. The following is an example:

    openssl genrsa -out did-private.pem 2048
    openssl rsa -in did-private.pem -pubout -out did-public.pem

Then run the executable with no additional parameters from the command line.
