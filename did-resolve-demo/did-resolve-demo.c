#include "openssl/provider.h"
#include "openssl/params.h"
#include "openssl/core.h"
#include "openssl/crypto.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/evp_ssi.h"
#include <openssl/bio.h>

int main(int argc, char *argv[]){

    BIO *bio_err = NULL;

    OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;

    EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

    if(argc != 2){
        BIO_printf(bio_err, "Wrong number of parameters\n");
        return 0;
    }

    // load the did provider for SSI operations
    provider = OSSL_PROVIDER_load(NULL, "ssi");
    if (provider == NULL) {
        BIO_printf(bio_err, "Error loading provider\n");
        goto err;
    }

    // load the default provider for key operations
    provider_base = OSSL_PROVIDER_load(NULL, "default");
    if (provider_base == NULL) {
        BIO_printf(bio_err, "Error loading provider\n");
        goto err;
    }

    evp_did = EVP_DID_fetch(NULL, "OTT", NULL);
	if (evp_did == NULL) {
		BIO_printf(bio_err, "Error fetching DID\n");
        goto err;
	}

    ctx_did = EVP_DID_CTX_new(evp_did);
	if (ctx_did == NULL){
		BIO_printf(bio_err, "Error creating DID CTX\n");
        goto err;
	}

    if(!EVP_DID_resolve(ctx_did, argv[1], NULL)){
		BIO_printf(bio_err, "Error resolving DID\n");
        goto err;
	}

err:
    EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);

    return 0;
}