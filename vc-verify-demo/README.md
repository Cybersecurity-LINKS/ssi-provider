## Build

`vc-verify-demo.c` lets you verify a VC given the public key of the issuer.

    nano Makefile

Edit the first two lines: `OPENSSL_DIR=/path/to/openssl`. `OPENSSL_LIB` is either equal to `lib` for 32-bit OS or `lib64` for 64-bit OS. Then run

    make

## Usage

- Run `./vc-create-demo` to generate a valid VC.
- copy `vc.txt` and `vc-issuer-public.pem` previously generated into this directory
- `./vc-verify-demo vc.txt vc-issuer-public.pem` 