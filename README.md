# ssi-provider

# Build and Installation guide

## Requirements

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

Edit the first two lines specifying the right paths `OPENSSL_DIR=/path/to/openssl` , `IOTA_DIR=/path/to/iota.c` and `OPENSSL_DIR=/path/to/lib`, and then

    make
    make install


## Usage

The address of the gateway node of the IOTA ledger can be changed in the file `did-internal.c` : `MAINNET_PUBLIC` is the address of the public gateway node, `MAINNET` is the address of the private gateway node. They are both synched with the mainnet.
