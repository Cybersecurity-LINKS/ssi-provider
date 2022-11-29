#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/did.h>
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

static void *didprovider_create(void *sig1, size_t siglen1,int type1,void *sig2, size_t siglen2,int type2){
    method m[2];
    char *my_did_str = malloc(DID_LEN+1);
    int ret = 0;

    m[0].method_type = AuthenticationMethod;
    m[0].pk_pem.p = (unsigned char *) sig1;
    m[0].pk_pem.len = siglen1;
    m[0].type = type1;

    m[1].method_type = AssertionMethod;
    m[1].pk_pem.p = (unsigned char *) sig2;
    m[1].pk_pem.len = siglen2;
    m[1].type = type2;
    
    printf("DID OTT CREATE\n");
    
    ret = did_ott_create(m,my_did_str);
    if(ret != OTT_OK)
        return NULL;
    return my_did_str;
}

int didprovider_resolve(char* index, DID_DOCUMENT* did_doc){
    int ret;
    unsigned char* sig1 = NULL;
    unsigned char* sig2 = NULL;
    printf("DID OTT RESOLVE\n");
    
    if (index == NULL) {
        return DID_INTERNAL_ERROR;
    }
    did_document *didDocument = NULL;
    didDocument = calloc(1, sizeof(did_document));
    if (didDocument == NULL) {
        return DID_INTERNAL_ERROR;
    }
    did_document_init(didDocument);

    ret = did_ott_resolve(didDocument,index);
    if (ret == DID_RESOLVE_ERROR)
        return DID_INTERNAL_ERROR;
    else if (ret == DID_RESOLVE_REVOKED)
        return DID_REVOKED;
    else if (ret == DID_RESOLVE_NOT_FOUND)
        return DID_NOT_FOUD;

    if(didDocument->authMethod.pk_pem.p == NULL || didDocument->assertionMethod.pk_pem.p == NULL)
        return DID_INTERNAL_ERROR;
    
    sig1 = (unsigned char *) strdup(didDocument->authMethod.pk_pem.p);
    sig2 = (unsigned char *) strdup(didDocument->assertionMethod.pk_pem.p);

    //set the keys in the DID_DOCUMENT structure
    if(!DID_DOCUMENT_set(did_doc,sig1, didDocument->authMethod.pk_pem.len, didDocument->authMethod.type, sig2, didDocument->assertionMethod.pk_pem.len, didDocument->assertionMethod.type)){
        printf("DID_DOCUMENT ERROR\n");
        return DID_INTERNAL_ERROR;
    } 
    did_document_free(didDocument);
    return DID_OK;

}

static int didprovider_update(char* index, void *sig1, size_t siglen1,int type1,void *sig2, size_t siglen2,int type2){
    method m[2];
    int ret = 0;

    m[0].method_type = AuthenticationMethod;
    m[0].pk_pem.p = (unsigned char *) sig1;
    m[0].pk_pem.len = siglen1;
    m[0].type = type1;

    m[1].method_type = AssertionMethod;
    m[1].pk_pem.p = (unsigned char *) sig2;
    m[1].pk_pem.len = siglen2;
    m[1].type = type2;
    
    
    printf("DID OTT UPDATE\n");
    
    ret = did_ott_update(m,index);
    if(ret != DID_UPDATE_OK){
        return DID_INTERNAL_ERROR;
    }
    return DID_OK;
}

static int didprovider_revoke(char* index){
    int ret = 0;
    printf("DID OTT REVOKE\n");
    printf("%s\n", index);

    ret = did_ott_revoke(index);

    if(ret != DID_REVOKE_OK){
        return DID_INTERNAL_ERROR;
    }
    return DID_OK;
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