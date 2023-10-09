# demo

`did-resolve-demo.c` lets you resolve a DID document from the IOTA Tangle given its DID.

    nano Makefile

Edit the first two lines: `OPENSSL_DIR=/path/to/openssl`. `OPENSSL_LIB` is either equal to `lib` for 32-bit OS or `lib64` for 64-bit OS. Then run

    make
