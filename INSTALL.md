# Build and Install on Unix/Linux/macOS

## Prerequisites

### ssi-openssl

Download and install locally the SSI-version of OpenSSL which is a fork of the original OpenSSL repo

    https://github.com/Cybersecurity-LINKS/openssl.git -b openssl-3.0-ssi-dev

### iota.c

Download the iota.c client library from the official github repository and install it locally. 

    git clone -b dev https://github.com/iotaledger/iota.c.git
    cd iota.c

Open `cmake/sodium.cmake` in write mode and at line 19 replace `--disable-shared` with `cxxflags=-fPIC`. Then  

    mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCryptoUse=libsodium -DIOTA_WALLET_ENABLE:BOOL=TRUE -DCMAKE_INSTALL_PREFIX=$PWD -DWITH_IOTA_CLIENT:BOOL=TRUE -DWITH_IOTA_CORE:BOOL=TRUE ..
    make all
    make install

## Build & Install

    cd path/to/ssiprovider

Edit the `Makefile` by specifying the right paths for `OPENSSL_INSTALL_DIR`, `IOTA_DIR`. `OPENSSL_LIB` must be set to `lib` in a 32-bit OS or `lib64` in a 64-bit OS. Then

    make
    make install

`ssi.so` will be installed in `$OPENSSL_INSTALL_DIR/$OPENSSL_LIB/ossl-modules` 