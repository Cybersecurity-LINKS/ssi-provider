# demo

`vc-create-demo.c` lets you create a VC given the private key of the issuer and the DID of the subject.

    nano Makefile

Edit the first two lines: `OPENSSL_DIR=/path/to/openssl`. `OPENSSL_LIB` is either equal to `lib` for 32-bit OS or `lib64` for 64-bit OS. Then run

    make
