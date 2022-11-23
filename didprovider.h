#include <openssl/core_dispatch.h>
#include <openssl/types.h>

typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *core;
    //OSSL_LIB_CTX *libctx;         /* For all provider modules */
    //BIO_METHOD *corebiometh;
} PROV_CTX;