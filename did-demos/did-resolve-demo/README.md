`did-resolve-demo.c` lets you resolve a DID document from the IOTA Tangle given its DID.

## Build

Edit the first two lines of the `Makefile` where `OPENSLL_INSTALL_DIR=/path/to/openssl` and `OPENSSL_LIB` is either equal to `lib` for a 32-bit OS or `lib64` for a 64-bit OS. Then run

    make

## Usage

First, run `did-create-demo` executable to generate a valid DID document, then

    ./did-resolve-demo [DID] 