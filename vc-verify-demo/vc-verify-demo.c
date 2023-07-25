#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp_ssi.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <sys/time.h>

typedef struct vc {
	char *atContext;
	char *id;
	char *type;
	char *issuer;
	char *issuanceDate;
	char *expirationDate;
	char *credentialSubject;
	char *proofType;
	char *proofCreated;
	char *proofPurpose;
	char *verificationMethod;
	char *proofValue;
} vc;


int main(int argc, char *argv[]){

    vc vc;
    unsigned char *key = NULL;
    EVP_PKEY *pubkey = NULL;
    BIO *biokey = NULL;
	OSSL_PARAM params[13];
    size_t params_n = 0;
    long f_size;
    FILE *vc_issuers_fp = NULL;
    FILE *vc_fp = NULL;
	unsigned char *vc_stream = NULL;
	size_t n;
	OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;

	EVP_VC_CTX *ctx_vc = NULL;
	EVP_VC *evp_vc = NULL;

	struct timeval tv1, tv2;

    if(argc != 3){
        fprintf(stderr, "Wrong number of parameters\n");
        return 0;
    }

	vc_fp = fopen(argv[1], "r");
	if (vc_fp == NULL){
        fprintf(stderr, "Error opening %s file\n", argv[1]);
		return 0;
    }

	fseek(vc_fp, 0, SEEK_END);
	f_size = ftell(vc_fp);
	fseek(vc_fp, 0, SEEK_SET);
	vc_stream = malloc(f_size + 1);
    if (vc_stream == NULL){
    	fprintf(stderr, "Error allocating memory\n");
		return 0;
    }

	for (n = 0; n < f_size; n++) {
		vc_stream[n] = fgetc(vc_fp);
	}
	vc_stream[n] = '\0';

	printf("%s\n", vc_stream);

	// load the default provider for key operations
	provider_base = OSSL_PROVIDER_load(NULL, "default");
	if (provider_base == NULL) {
		fprintf(stderr, "Error loading provider\n");
		goto err;
	}

	// load the SSI provider for SSI operations
    provider = OSSL_PROVIDER_load(NULL, "ssi");
    if (provider == NULL) {
    	fprintf(stderr, "Error loading provider\n");
        goto err;
    }

    evp_vc = EVP_VC_fetch(NULL, "vc", NULL);
	if (evp_vc == NULL) {
        fprintf(stderr, "Error fetching VC\n");
        goto err;
    }

	/* Create a context for the vc operation */
	ctx_vc = EVP_VC_CTX_new(evp_vc);
	if (ctx_vc == NULL) {
		fprintf(stderr, "Error creating VC CTX\n");
        goto err;
    }

	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_CONTEXT, &vc.atContext, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ID, &vc.id, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_TYPE, &vc.type, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUER, &vc.issuer, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_ISSUANCE_DATE, &vc.issuanceDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_EXPIRATION_DATE, &vc.expirationDate, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_SUBJECT, &vc.credentialSubject, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_TYPE, &vc.proofType, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_CREATED, &vc.proofCreated, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_PURPOSE, &vc.proofPurpose, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_VERIFICATION_METHOD, &vc.verificationMethod, 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_ptr(OSSL_VC_PARAM_PROOF_VALUE, &vc.proofValue, 0);
	params[params_n] = OSSL_PARAM_construct_end();

	if(!EVP_VC_deserialize(ctx_vc, vc_stream, params)) {
        fprintf(stderr, "Error verifying the VC\n");
        goto err;
    }

	gettimeofday(&tv1, NULL); 

	params_n = 0;

	if (vc.atContext != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_CONTEXT, OPENSSL_strdup(vc.atContext), 0);
	if (vc.id != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, OPENSSL_strdup(vc.id), 0);
	if (vc.type != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_TYPE, OPENSSL_strdup(vc.type), 0);
	if (vc.issuer != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, OPENSSL_strdup(vc.issuer), 0);
	if (vc.issuanceDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUANCE_DATE, OPENSSL_strdup(vc.issuanceDate), 0);
	if (vc.expirationDate != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, OPENSSL_strdup(vc.expirationDate), 0);
	if (vc.credentialSubject != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, OPENSSL_strdup(vc.credentialSubject), 0);
	if (vc.proofType != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_TYPE, OPENSSL_strdup(vc.proofType), 0);
	if (vc.proofCreated != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_CREATED, OPENSSL_strdup(vc.proofCreated), 0);
	if (vc.proofPurpose != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_PURPOSE, OPENSSL_strdup(vc.proofPurpose), 0);
	if (vc.verificationMethod != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, OPENSSL_strdup(vc.verificationMethod), 0);
	if (vc.proofValue != NULL)
		params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_PROOF_VALUE, OPENSSL_strdup(vc.proofValue), 0);
	params[params_n] = OSSL_PARAM_construct_end();

	EVP_VC_CTX_free(ctx_vc);

	vc_issuers_fp = fopen(argv[2], "r");
	if (vc_issuers_fp == NULL){
		fprintf(stderr, "Error opening %s file\n", argv[2]);
		goto err;
    }

    fseek(vc_issuers_fp, 0, SEEK_END);
	f_size = ftell(vc_issuers_fp);
	fseek(vc_issuers_fp, 0, SEEK_SET);
	key = malloc(f_size + 1);
    if (key == NULL){
        fprintf(stderr, "Error allocating memory\n");
		goto err;
    }

	for (n = 0; n < f_size; n++) {
		key[n] = fgetc(vc_issuers_fp);
	}
	key[f_size] = '\0';

	printf("%s\n", key);

    if ((biokey = BIO_new_mem_buf(key, -1)) == NULL) {
		fprintf(stderr, "BIO error\n");
		goto err;
	}

	if ((pubkey = PEM_read_bio_PUBKEY(biokey, NULL, NULL,
			NULL)) == NULL) {
		fprintf(stderr, "PEM error\n");
		goto err;
	} 

	
	/* Create a context for the vc operation */
	ctx_vc = EVP_VC_CTX_new(evp_vc);
	if (ctx_vc == NULL) {
		fprintf(stderr, "Error creating VC CTX\n");
        goto err;
    }

    if(!EVP_VC_verify(ctx_vc, pubkey, params)){
		fprintf(stderr, "Error verifying the VC\n");
        goto err;
	}

    printf("VC verification succeded!\n");

	gettimeofday(&tv2, NULL);
    printf("Total time = %f seconds\n\n",
           (double)(tv2.tv_usec - tv1.tv_usec) / 1000000 +
            (double)(tv2.tv_sec - tv1.tv_sec));

err:
    EVP_VC_free(evp_vc);
	EVP_VC_CTX_free(ctx_vc);
    free(key);
    free(vc_stream);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);
    fclose(vc_issuers_fp);
    fclose(vc_fp);
    return 0;
}
