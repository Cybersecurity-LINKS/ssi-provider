# didprovider

# Build and Installation guide

## Requirements

### SSI-OpenSSL

Download and install locally the SSI-version of OpenSSL.

### iota.c

Download the iota.c client library from the official github repository and install it locally. 

    git clone -b dev https://github.com/iotaledger/iota.c.git
    cd iota.c
    nano cmake/sodium.cmake

At line 19 replace `--disable-shared` with `cxxflags=-fPIC`  

    mkdir build && cd build
    cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ -DCryptoUse=libsodium -DIOTA_WALLET_ENABLE:BOOL=TRUE -DCMAKE_INSTALL_PREFIX=$PWD -DWITH_IOTA_CLIENT:BOOL=TRUE -DWITH_IOTA_CORE:BOOL=TRUE ..
    make all
    make install

## Build & Install

    cd didprovider
    nano Makefile

Edit the first two lines specifying the right paths `OPENSSL_DIR=/path/to/openssl` and `IOTA_DIR=/path/to/iota.c`

    make
    make install



