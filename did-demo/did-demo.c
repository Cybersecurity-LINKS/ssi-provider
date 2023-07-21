#include "openssl/provider.h"
#include "openssl/params.h"
#include "openssl/core.h"
#include "openssl/crypto.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/evp_ssi.h"
#include <openssl/bio.h>

BIO *bio_err = NULL;

int main(void) {
    
    OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;
    FILE *fp_did = NULL;
    long f_size;
    char *authentication_pem = NULL;
    char *assertion_pem = NULL;
    char c;
    FILE *authn_meth_fp;
    FILE *assrtn_meth_fp;

    EVP_DID_CTX *ctx_did = NULL;
	EVP_DID *evp_did = NULL;

    OSSL_PARAM params[3];
	size_t params_n = 0, n = 0; 

    authn_meth_fp = fopen("did-public.pem", "r");
	if (authn_meth_fp == NULL){
		printf("Error opening did-public.pem file\n");
        return -1;
    }

    fseek(authn_meth_fp, 0, SEEK_END);
	f_size = ftell(authn_meth_fp);
	fseek(authn_meth_fp, 0, SEEK_SET);
	authentication_pem = malloc(f_size);

	while ((c = fgetc(authn_meth_fp)) != EOF) {
		authentication_pem[n++] = c;
	}

    fclose(authn_meth_fp); 

    assrtn_meth_fp = fopen("did-public.pem", "r");
	if (assrtn_meth_fp == NULL){
        printf("Error opening did-public.pem file\n");
		return -1;
    }

    fseek(assrtn_meth_fp, 0, SEEK_END);
	f_size = ftell(assrtn_meth_fp);
	fseek(assrtn_meth_fp, 0, SEEK_SET);
	assertion_pem = malloc(f_size);

    n = 0;
	while ((c = fgetc(assrtn_meth_fp)) != EOF) {
		assertion_pem[n++] = c;
	}

    fclose(authn_meth_fp); 

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

    params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_DID_PARAM_AUTHN_METH_PKEY, authentication_pem, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_DID_PARAM_ASSRTN_METH_PKEY, assertion_pem, 0);
	params[params_n] = OSSL_PARAM_construct_end();

    char *did = EVP_DID_create(ctx_did, params);
    if(did == NULL) {
        BIO_printf(bio_err, "Error creating a DID DOCUMENT\n");
        goto err;
    }

    printf("DID %s\n", did);

    if ((fp_did = fopen("did.txt", "w")) == NULL) {
        goto err;
    }

    fprintf(fp_did, "%s\n", did);

	if(!EVP_DID_resolve(ctx_did, did, NULL)){
		BIO_printf(bio_err, "Error loading provider\n");
        goto err;
	}

err:
    fclose(fp_did);
    EVP_DID_free(evp_did);
	EVP_DID_CTX_free(ctx_did);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);

    return 0;
}