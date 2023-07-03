#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp_ssi.h>
#include "did_method.h"

static OSSL_FUNC_did_newctx_fn did_newctx;
static OSSL_FUNC_did_create_fn did_create;
static OSSL_FUNC_did_resolve_fn did_resolve;
static OSSL_FUNC_did_update_fn did_update;
static OSSL_FUNC_did_revoke_fn did_revoke;
static OSSL_FUNC_did_freectx_fn did_freectx;
static OSSL_FUNC_did_set_ctx_params_fn did_set_ctx_params;
static OSSL_FUNC_did_get_ctx_params_fn did_get_ctx_params;

void *did_newctx(void *provctx)
{ // should i do something with provctx?

    DID_CTX *ctx;

    /*if (!ossl_prov_is_running())
        return NULL;*/

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

void did_freectx(void *didctx)
{

    DID_CTX *ctx = (DID_CTX *)didctx;

    //TO DO
}

void *did_create(void *didctx, OSSL_PARAM params[]){

    const OSSL_PARAM *p;
    DID_CTX *ctx = (DID_CTX *)didctx;

    /* @Context */
    ctx->atContext = OPENSSL_strdup(CONTEXT_DID_V1);

    /* created */
    time_t now = time(0);
    ctx->issuanceDate = (char *)OPENSSL_zalloc(100);
    strftime(ctx->issuanceDate, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* authentication public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_AUTHN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->authentication->pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    /* assertion public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_ASSRTN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->assertion->pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    printf("DID OTT CREATE\n");

    if(!did_ott_create(ctx))
        return NULL;

    return ctx->did;
}

void *did_create(void *sig1, size_t siglen1,int type1,void *sig2, size_t siglen2,int type2){
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

int did_resolve(char* index, DID_DOCUMENT* did_doc){
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

int did_update(char* index, void *sig1, size_t siglen1,int type1,void *sig2, size_t siglen2,int type2){
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

int did_revoke(char* index){
    int ret = 0;
    printf("DID OTT REVOKE\n");
    printf("%s\n", index);

    ret = did_ott_revoke(index);

    if(ret != DID_REVOKE_OK){
        return DID_INTERNAL_ERROR;
    }
    return DID_OK;
}

int did_set_ctx_params(void *didctx, const OSSL_PARAM params[]){

}

int did_get_ctx_params(void *didctx, const OSSL_PARAM params[]){

}

const OSSL_DISPATCH did_crud_functions[] = {
    {OSSL_FUNC_DID_NEWCTX, (void(*)(void))did_newctx},
    {OSSL_FUNC_DID_CREATE, (void(*)(void))did_create},
    {OSSL_FUNC_DID_RESOLVE, (void(*)(void))did_resolve},
    {OSSL_FUNC_DID_UPDATE, (void(*)(void))did_update},
    {OSSL_FUNC_DID_REVOKE, (void(*)(void))did_revoke},
    {OSSL_FUNC_DID_FREECTX, (void(*)(void))did_freectx},
    {OSSL_FUNC_DID_SET_PARAMS, (void(*)(void))did_set_ctx_params},
    {OSSL_FUNC_DID_GET_PARAMS, (void(*)(void))did_get_ctx_params},
    { 0, NULL }
};