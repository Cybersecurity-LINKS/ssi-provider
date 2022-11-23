#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "did_method.h"

static OSSL_FUNC_did_create_fn didprovider_create;
static OSSL_FUNC_did_resolve_fn didprovider_resolve;
static OSSL_FUNC_did_update_fn didprovider_update;
static OSSL_FUNC_did_revoke_fn didprovider_revoke;

#define KEY \
"-----BEGIN PUBLIC KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8pta2RewzPpJ1I/Ir\nxycs1p+gxqVqV32mybVQ011WrUfc4J4ubnRFFfjnlMmXAIWhZANiAAS4PSfpIErh\nA22hFrBh30xz8Tcc2xw0zB7VTVZhIR/YmoenTnOJnLTMGP8LGXWJNz1e7ffq7KR7\nMMDhtk4Wc1I4NGgXuYx54TNt8g15Bn6WJbHt4TZMfeTlod/INe2QgOg=" \
"-----END PUBLIC KEY-----\n"

#define KEY2 \
"PUBLIC KEY 2"

#define KEY3 \
"KEY 3"

#define KEY4 \
"KEY 4"

static void *didprovider_create(void *sig, int siglen){
    method m[2];
    char *my_did_str = malloc(DID_LEN+1);
    int ret = 0;
    IOTA_Index next;


    m[0].method_type = AuthenticationMethod;
    m[0].pk_pem.p = (unsigned char *) KEY;
    m[0].pk_pem.len = strlen(KEY);
    m[0].type = RsaVerificationKey2018;

    m[1].method_type = AssertionMethod;
    m[1].pk_pem.p = (unsigned char *) KEY2;
    m[1].pk_pem.len = strlen(KEY2);
    m[1].type = Ed25519VerificationKey2018;
    
    printf("DID OTT CREATE\n");
    
    create(m,my_did_str, &next);
    printf("NEW DID %s\n", my_did_str); 
    return my_did_str;
}

static void *didprovider_resolve(char* index){
    printf("DID OTT RESOLVE\n");
    did_document *didDocument = NULL;
    didDocument = calloc(1, sizeof(did_document));
    if (didDocument == NULL) {
        return ALLOC_FAILED;
    }
    did_document_init(didDocument);
    return resolve(didDocument,index);

}

static int didprovider_update(char* index, void *sig, int siglen){
    printf("DID OTT UPDATE\n");
    return 0;
}

static int didprovider_revoke(char* index){
    printf("DID OTT REVOKE\n");
    return 0;
}

const OSSL_DISPATCH didprovider_crud_functions[] = {
    {OSSL_FUNC_DID_CREATE, (void(*)(void))didprovider_create},
    {OSSL_FUNC_DID_RESOLVE, (void(*)(void))didprovider_resolve},
    {OSSL_FUNC_DID_UPDATE, (void(*)(void))didprovider_update},
    {OSSL_FUNC_DID_REVOKE, (void(*)(void))didprovider_revoke},
    { 0, NULL }
};

static void *didprovider_fake_create(void *sig, int siglen){
    printf("FAKE CREATE\n");
    return NULL;

}

static void *didprovider_fake_resolve(int index){
    printf("FAKE RESOLVE\n");
    return NULL;

}

static int didprovider_fake_update(int index, void *sig, int siglen){
    printf("FAKE UPDATE\n");
    return 0;
}

static int didprovider_fake_revoke(int index){
    printf("FAKE REVOKE\n");
    return 0;
}

const OSSL_DISPATCH didprovider_fake_functions[] = {
    {OSSL_FUNC_DID_CREATE, (void(*)(void))didprovider_fake_create},
    {OSSL_FUNC_DID_RESOLVE, (void(*)(void))didprovider_fake_resolve},
    {OSSL_FUNC_DID_UPDATE, (void(*)(void))didprovider_fake_update},
    {OSSL_FUNC_DID_REVOKE, (void(*)(void))didprovider_fake_revoke},
    { 0, NULL }
};