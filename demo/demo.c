#include "openssl/provider.h"
#include "openssl/params.h"
#include "openssl/core.h"
#include "openssl/crypto.h"
#include "openssl/core_dispatch.h"
#include "openssl/core_names.h"
#include "openssl/did.h"
#include "openssl/store.h"
#include "openssl/encoder.h"
#include "time.h"
#include "sys/time.h"

#define SET_EXPECT(expect, val) ((expect) = (expect) < 0 ? (val) : ((expect) == (val) ? (val) : 0))
EVP_PKEY *load_pubkey(const char *uri, OSSL_LIB_CTX *libctx);

int get_key_type(EVP_PKEY *key)
{
    int ret = 0;
    ret = EVP_PKEY_get_id(key);
    // printf("key type %d\n", ret);
    // const char * name1 = EVP_PKEY_get0_type_name(key2);
    switch (ret)
    {
    case EVP_PKEY_RSA:
        ret = 1;
        break;
    case EVP_PKEY_EC:
        ret = 2;
        break;
    case EVP_PKEY_ED25519:
        ret = 0;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

int load_key(DID_DOCUMENT *did_doc, const char *infile1, const char *infile2, OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    OSSL_ENCODER_CTX *ectx1 = NULL, *ectx2 = NULL;
    EVP_PKEY_CTX *pctx1 = NULL, *pctx2 = NULL;
    unsigned char *sig1 = NULL, *sig2 = NULL;
    size_t len1, len2;
    int type1, type2;
    int ret = 0;

    // load the authorization key
    key1 = load_pubkey(infile1, libctx);
    if (key1 == NULL)
    {
        printf("load key failed\n");
        ret = 0;
        goto error;
    }

    pctx1 = EVP_PKEY_CTX_new_from_pkey(NULL, key1, NULL);
    if (pctx1 == NULL)
    {
        printf("EVP_PKEY_CTX_new_from_pkey failed\n");
        ret = 0;
        goto error;
    }

    if (!EVP_PKEY_public_check(pctx1))
    {
        printf("check key failed\n");
        ret = 0;
        goto error;
    }

    type1 = get_key_type(key1);
    if (type1 == -1)
    {
        printf("check key type failed\n");
        ret = 0;
        goto error;
    }

    ectx1 = OSSL_ENCODER_CTX_new_for_pkey(key1, OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM", "SubjectPublicKeyInfo", NULL);
    if (ectx1 == NULL)
    {
        printf("OSSL_ENCODER_CTX failed\n");
        ret = 0;
        goto error;
    }

    ret = OSSL_ENCODER_to_data(ectx1, &sig1, &len1);
    if (ret == 0)
    {
        printf("OSSL_ENCODER failed\n");
        ret = 0;
        goto error;
    }

    sig1[len1] = '\0';

    // load the assertion key
    key2 = load_pubkey(infile2, libctx);
    if (key2 == NULL)
    {
        printf("load key failed\n");
        ret = 0;
        goto error;
    }

    pctx2 = EVP_PKEY_CTX_new_from_pkey(NULL, key2, NULL);
    if (pctx2 == NULL)
    {
        printf("EVP_PKEY_CTX_new_from_pkey failed\n");
        ret = 0;
        goto error;
    }

    if (!EVP_PKEY_public_check(pctx2))
    {
        printf("check key failed\n");
        ret = 0;
        goto error;
    }

    type2 = get_key_type(key2);
    if (type2 == -1)
    {
        printf("check key type failed\n");
        ret = 0;
        goto error;
    }

    ectx2 = OSSL_ENCODER_CTX_new_for_pkey(key2, OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, "PEM", "SubjectPublicKeyInfo", NULL);
    if (ectx2 == NULL)
    {
        printf("OSSL_ENCODER_CTX failed\n");
        ret = 0;
        goto error;
    }

    ret = OSSL_ENCODER_to_data(ectx2, &sig2, &len2);
    if (ret == 0)
    {
        printf("OSSL_ENCODER failed\n");
        ret = 0;
        goto error;
    }
    sig2[len2] = '\0';

    ret = DID_DOCUMENT_set(did_doc, sig1, len1, type1, sig2, len2, type2);

error:
    OSSL_ENCODER_CTX_free(ectx1);
    OSSL_ENCODER_CTX_free(ectx2);
    EVP_PKEY_CTX_free(pctx1);
    EVP_PKEY_CTX_free(pctx2);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ret;
}

EVP_PKEY *load_pubkey(const char *uri, OSSL_LIB_CTX *libctx)
{
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_PARAM itp[2];
    const OSSL_PARAM *params = NULL;
    int cnt_expectations = 0;
    int expect = -1;

    cnt_expectations++;
    SET_EXPECT(expect, OSSL_STORE_INFO_PUBKEY);

    itp[0] = OSSL_PARAM_construct_utf8_string(OSSL_STORE_PARAM_INPUT_TYPE, "PEM", 0);
    itp[1] = OSSL_PARAM_construct_end();
    params = itp;

    ctx = OSSL_STORE_open_ex(uri, libctx, NULL, NULL, NULL, params, NULL, NULL);
    if (ctx == NULL)
    {
        printf("Could not open file or uri for loading\n");
    }

    if (expect > 0 && !OSSL_STORE_expect(ctx, expect))
        return NULL;

    while (!OSSL_STORE_eof(ctx))
    {
        OSSL_STORE_INFO *info = OSSL_STORE_load(ctx);
        int type;

        /*
         * This can happen (for example) if we attempt to load a file with
         * multiple different types of things in it - but the thing we just
         * tried to load wasn't one of the ones we wanted, e.g. if we're trying
         * to load a certificate but the file has both the private key and the
         * certificate in it. We just retry until eof.
         */
        if (info == NULL)
        {
            continue;
        }
        type = OSSL_STORE_INFO_get_type(info);
        switch (type)
        {
        case OSSL_STORE_INFO_PUBKEY:
            pkey = OSSL_STORE_INFO_get1_PUBKEY(info);
            break;
        default:
            /* skip any other type */
            break;
        }
    }
    OSSL_STORE_close(ctx);
    return pkey;
}

int main(void)
{
    const char *file = "my_keys/server_did_publickey.pem";
    int ret;
    OSSL_PROVIDER *provider_base = NULL;
    OSSL_PROVIDER *provider = NULL;
    FILE *fp_create = NULL;
    FILE *fp_resolve = NULL;
    FILE *fp_update = NULL;
    FILE *fp_revoke = NULL;
    DID_CTX *didctx = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    
    DID_DOCUMENT *did_doc = NULL, *did_doc_rcv = NULL, *did_doc_update = NULL;

    /*FILE *fp = fopen("my_keys/client_did_publickey.pem", "r");
    if (fp != NULL) {
        *//* Go to the end of the file. *//*
        if (fseek(fp, 0L, SEEK_END) == 0) {
            *//* Get the size of the file. *//*
            long bufsize = ftell(fp);
            if (bufsize == -1) { *//* Error *//* }

            *//* Allocate our buffer to that size. *//*
            public_key = malloc(sizeof(char) * (bufsize + 1));

            *//* Go back to the start of the file. *//*
            if (fseek(fp, 0L, SEEK_SET) != 0) { *//* Error *//* }

            *//* Read the entire file into memory. *//*
            size_t newLen = fread(public_key, sizeof(char), bufsize, fp);
            if ( ferror( fp ) != 0 ) {
                fputs("Error reading file", stderr);
            } else {
                public_key[newLen++] = '\0'; *//* Just to be safe. *//*
            }
        }
        fclose(fp);
    }*/

    if ((fp_create = fopen("create_mainnet.txt", "a")) == NULL)
    {
        goto error;
    }
    if ((fp_resolve = fopen("resolve_mainnet.txt", "a")) == NULL)
    {
        goto error;
    }
    if ((fp_update = fopen("update_mainnet.txt", "a")) == NULL)
    {
        goto error;
    }
    if ((fp_revoke = fopen("revoke_mainnet.txt", "a")) == NULL) {
        goto error;
    }

    // load the did provider for did operations
    provider = OSSL_PROVIDER_load(NULL, "didprovider");
    if (provider == NULL)
    {
        printf("DID provider load failed\n");
        goto error;
    }

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
    {
        printf("OSSL_LIB_CTX new failed\n");
        goto error;
    }

    // load the default provider for key operations
    provider_base = OSSL_PROVIDER_load(libctx, "default");
    if (provider_base == NULL)
    {
        printf("default provider load failed\n");
        goto error;
    }

    // Creation of new did context
    didctx = DID_CTX_new(provider);
    if (didctx == NULL)
    {
        printf("DID CTX new failed\n");
        goto error;
    }

    // Creation of new did document
    did_doc = DID_DOCUMENT_new();
    if (did_doc == NULL)
    {
        printf("DID document new failed\n");
        goto error;
    }

    //Creation of empty did document
    did_doc_rcv = DID_DOCUMENT_new();
    if (did_doc_rcv == NULL) {
        printf("DID document new failed\n");
        goto error;
    }

    ret = DID_fetch(NULL, didctx, "OTT", "property");
    if (ret == 0)
    {
        printf("DID fetch failed\n");
        goto error;
    }

    ret = load_key(did_doc, file, file, libctx);
    if (ret == 0)
    {
        printf("Load key failed\n");
        goto error;
    }

    char *new_did = DID_create(didctx, did_doc);

    if (new_did == NULL)
    {
        printf("DID_create failed\n");
        goto error;
    }

    printf("DID %s\n", new_did);

    ret = DID_resolve(didctx, new_did, did_doc_rcv);

    switch (ret)
    {
    case DID_INTERNAL_ERROR:
        printf("DID method internal error\n");
        return -1;
        break;
    case DID_NOT_FOUD:
        printf("DID document not found\n");
        return 0;
        break;
    case DID_REVOKED:
        printf("DID %s REVOKED\n", new_did);
        return 0;
        break;
    case DID_OK:
        printf("DID %s FOUND\n", new_did);
        break;
    default:
        break;
    }
    
error:
    fclose(fp_create);
    fclose(fp_resolve);
    fclose(fp_update);
    fclose(fp_revoke);
    DID_DOCUMENT_free(did_doc);
    DID_DOCUMENT_free(did_doc_rcv);
    DID_DOCUMENT_free(did_doc_update);

    OPENSSL_free(new_did);
    // OPENSSL_free(auth);
    // OPENSSL_free(ass);
    OSSL_PROVIDER_unload(provider);
    OSSL_PROVIDER_unload(provider_base);
    DID_CTX_free(didctx);
    OSSL_LIB_CTX_free(libctx);

    return 0;
}
