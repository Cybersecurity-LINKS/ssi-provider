## Build

`vc-create-demo.c` lets you create a VC given the private key of the issuer and the DID of the subject.

    nano Makefile

Edit the first two lines: `OPENSSL_DIR=/path/to/openssl`. `OPENSSL_LIB` is either equal to `lib` for 32-bit OS or `lib64` for 64-bit OS. Then run

    make

## Usage

- Run `did-create-demo` executable to generate a valid DID document
- Generate VC issuer key pair and name them `vc-issuer-private.pem` and `vc-issuer-public.pem`, like in the following way

    openssl genrsa -out did-private.pem 2048
    openssl rsa -in did-private.pem -pubout -out did-public.pem

- `./vc-create-demo [DID]`. The generated VC will be saved in `vc.txt` file. 