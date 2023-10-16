# Build and Install on Unix/Linux/macOS

## Prerequisites

### ssi-openssl

Download and install locally the SSI-version of OpenSSL

    git clone git@github.com:Cybersecurity-LINKS/ssi-openssl.git

### iota.c

Download the iota.c client library from the official github repository and install it locally. 

    git clone -b dev https://github.com/iotaledger/iota.c.git
    cd iota.c
    nano cmake/sodium.cmake

At line 19 replace `--disable-shared` with `cxxflags=-fPIC`, and then  

    mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCryptoUse=libsodium -DIOTA_WALLET_ENABLE:BOOL=TRUE -DCMAKE_INSTALL_PREFIX=$PWD -DWITH_IOTA_CLIENT:BOOL=TRUE -DWITH_IOTA_CORE:BOOL=TRUE ..
    make all
    make install

## Build & Install

    cd path/to/ssiprovider
    nano Makefile

Edit the first two lines specifying the right paths `OPENSSL_DIR=path/to/openssl` , `IOTA_DIR=path/to/iota.c` and `OPENSSL_LIB=<lib/lib64>`, and then

    make
    make install

`ssi.so` will be installed in `path/to/openssl/lib64/ossl-modules` 