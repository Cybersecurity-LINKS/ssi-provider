#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp_ssi.h>
#include <openssl/err.h>

static int get_key_type(EVP_PKEY *key)
{
    int ret = 0;
    ret = EVP_PKEY_get_id(key);
    // printf("key type %d\n", ret);
    // const char * name1 = EVP_PKEY_get0_type_name(key2);
    switch (ret)
    {
    case EVP_PKEY_RSA:
        ret = 0;
        break;
    case EVP_PKEY_EC:
        ret = 1;
        break;
    case EVP_PKEY_ED25519:
        ret = 2;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

int main()
{
    const char *file = "private.pem";
    EVP_PKEY *pkey = NULL;
    FILE *fp_pkey, *fp_vc;
    char *vc = NULL;

    OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;

    EVP_VC *evp_vc;
    EVP_VC_CTX *vc_ctx;

    OSSL_PARAM params[6];
	size_t params_n = 0;

    int i;

    if ((fp_pkey = fopen(file, "r")) == NULL)
    {
        printf("Error opening a file\n");
        goto err;
    }

	/* load the SSI provider for VC operations */
	provider = OSSL_PROVIDER_load(NULL, "ssi");
	if (provider == NULL) {
		ERR_print_errors_fp(stderr);
		printf("SSI provider load failed\n");
		goto err;
	}

    /* load the default provider for key operations */
    provider_base = OSSL_PROVIDER_load(NULL, "default");
    if (provider_base == NULL)
    {
        printf("default provider load failed\n");
        goto err;
    }

    if (!PEM_read_PrivateKey(fp_pkey, &pkey, NULL, NULL))
    {
        printf("Could not translate PEM into EVP_PKEY\n");
        goto err;
    }
    fclose(fp_pkey);

    if (get_key_type(pkey) == -1)
    {
        printf("Invalid key type\n");
        goto err;
    }

    evp_vc = EVP_VC_fetch(NULL, "VC", "provider=ssi");
    if (evp_vc == NULL) {
    	ERR_print_errors_fp(stderr);
    	goto err;
    }

    vc_ctx = EVP_VC_CTX_new(evp_vc);
    if (vc_ctx == NULL)
    	goto err;

    /* riempi i params */
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ID, "http://example.com/credentials/1", 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_ISSUER, "http://example.com/issuer/1", 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_EXPIRATION_DATE, "2025-01-01T12:00:00Z", 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_SUBJECT, "did:ott:0726D1CC750C612C1E91608261BC374510949569E7A0B9CC8FE95008D7C9ABE3", 0);
	params[params_n++] = OSSL_PARAM_construct_utf8_string(OSSL_VC_PARAM_VERIFICATION_METHOD, "http://example.com/issuer/1#key-2", 0);
	params[params_n] = OSSL_PARAM_construct_end();

    if((vc = EVP_VC_create(vc_ctx, pkey, params)) == NULL)
        goto err;

    if ((fp_vc = fopen("vc.txt", "w")) == NULL)
    {
        printf("Error opening a file\n");
        goto err;
    }

    for(i = 0; i < strlen(vc); i++){
        fputc(vc[i], fp_vc);
    }
    fclose(fp_vc);

err:
    EVP_PKEY_free(pkey);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);
    EVP_VC_free(evp_vc);
    EVP_VC_CTX_free(vc_ctx);

    return 0;
}
