#include "vc_internal.h"
#include <time.h>
#include <sys/time.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static OSSL_FUNC_vc_newctx_fn vc_newctx;
static OSSL_FUNC_vc_create_fn vc_create;
static OSSL_FUNC_vc_verify_fn vc_verify;
static OSSL_FUNC_vc_serialize_fn vc_serialize;
static OSSL_FUNC_vc_deserialize_fn vc_deserialize;
static OSSL_FUNC_vc_freectx_fn vc_freectx;
static OSSL_FUNC_vc_set_ctx_params_fn vc_set_ctx_params;
static OSSL_FUNC_vc_get_ctx_params_fn vc_get_ctx_params;

void *vc_newctx(void *provctx){             //should i do something with provctx?
    
    VC_CTX *ctx;
    
    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ctx;    
}

void vc_freectx(void *vcctx){

    VC_CTX *ctx = (VC_CTX *)vcctx;

    if(ctx != NULL) {
        OPENSSL_free(ctx->atContext.p);
        ctx->atContext.p = NULL;
        OPENSSL_free(ctx->id.p);
        ctx->id.p = NULL;
        OPENSSL_free(ctx->type.p);
        ctx->id.p = NULL;
        OPENSSL_free(ctx->issuer.p);
        ctx->issuer.p = NULL;
        OPENSSL_free(ctx->issuanceDate.p);
        ctx->issuanceDate.p = NULL;

        OPENSSL_free(ctx->credentialSubject.id.p);
        ctx->credentialSubject.id.p = NULL;

        OPENSSL_free(ctx->proof.type.p);
        ctx->proof.type.p = NULL;
        OPENSSL_free(ctx->proof.created.p);
        ctx->proof.type.p = NULL;
        OPENSSL_free(ctx->proof.purpose.p);
        ctx->proof.type.p = NULL;
        OPENSSL_free(ctx->proof.verificationMethod.p);
        ctx->proof.type.p = NULL;
        OPENSSL_free(ctx->proof.value.p);
        ctx->proof.type.p = NULL;
    }

}

char *vc_create(void *vcctx, EVP_PKEY *pkey, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    VC_CTX *ctx = (VC_CTX *)vcctx;
    char *str = NULL;

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL)
    {
        return NULL;
    }

    /* assign the metadata and claims contained in params[] to ctx
        and generate the remaining ones from scratch  */

    ctx->atContext.p = OPENSSL_strdup(CONTEXT_VC_V1);
    ctx->atContext.len = strlen(ctx->atContext.p);
    
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);    
    }

    ctx->type.p = OPENSSL_strdup(VC_TYPE);
    ctx->type.len = strlen(ctx->id.p);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);    
    }

    time_t now = time(0);
    ctx->issuanceDate.p = (char *)malloc(100);
    strftime(ctx->issuanceDate.p, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    ctx->issuanceDate.len = strlen(ctx->issuanceDate.p);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);    
    }

    /* Fill the VC JSON object with credential metadata and claims in ctx. */
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    /* assign the proof fields contained in params[] to ctx, the other ones 
        will be generating while in the proof creation */
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->proof.verificationMethod.p = OPENSSL_strdup(str);
        ctx->proof.verificationMethod.len = strlen(str);    
    }

    /* Generate the proof and fill the proof section of the VC JSON object */
    if(!vc_fill_proof(vc, ctx, pkey))
        goto fail;

    /* Fill params[] with the fields of the just created VC to return it to the caller */
    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->atContext.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->issuer.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->issuanceDate.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->credentialSubject.id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_CREATED);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.created.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.purpose.p))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.verificationMethod.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.value.p))
        return 0; 

    /* Also returns the serialized vc */
    char *verifiable_credential = cJSON_Print(vc);
    cJSON_Delete(vc);
    return verifiable_credential;

fail:
    cJSON_Delete(vc);
    return NULL;
}

int vc_verify(void *vcctx, EVP_PKEY *pkey, OSSL_PARAM params[])
{   
    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;
    char *str = NULL;

    if (ctx == NULL)
        return 0;
    if(params == NULL)
        return 0;

    /* creates a JSON to construct the VC */
    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL)
    {
        return 0;
    }

    // the caller does a set ctx parameters
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if(p != NULL) {
        OPENSSL_free(ctx->atContext.p);
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->atContext.p = OPENSSL_strdup(str);
        ctx->atContext.len = strlen(str);    
    }
    
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_TYPE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->proof.type.p = OPENSSL_strdup(str);
        ctx->proof.type.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuanceDate.p = OPENSSL_strdup(str);
        ctx->issuanceDate.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);    
    }

    // Fill the part that contains credential metadata and claims
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    //vc_verify_proof(vc_cjson, vcctx, pkey)

fail:
    cJSON_Delete(vc);
    return 0;
}

int vc_deserialize(void *vcctx, unsigned char *vc_stream, OSSL_PARAM params[])
{

    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;
    char *str = NULL;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 0;
    
    if (vc_cjson_parse(ctx, vc_stream) == VC_PARSE_ERROR)
    {
        return 0;
    }

    if (ctx->atContext.p == NULL || ctx->id.p == NULL || ctx->type.p == NULL || ctx->issuer.p == NULL 
        || ctx->issuanceDate.p == NULL ||   ctx->credentialSubject.id.p == NULL || 
        ctx->proof.type.p == NULL || ctx->proof.created.p == NULL || ctx->proof.purpose.p == NULL ||
        ctx->proof.verificationMethod.p == NULL || ctx->proof.value.p == NULL)
        return 0;

    /* The provider sets the parameters now, from the caller point of view
      this looks like a get_ctx_params */ 
    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->atContext.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->issuer.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->issuanceDate.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->credentialSubject.id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_CREATED);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.created.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.purpose.p))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.verificationMethod.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->proof.value.p))
        return 0;
    
    return 1;
}

int vc_serialize(void *vcctx, unsigned char *vc_stream, OSSL_PARAM params[])
{
    
    /* From the caller point of view this looks like a set_ctx_params */
    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;
    char *str = NULL;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if(p != NULL) {
        OPENSSL_free(ctx->atContext.p);
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->atContext.p = OPENSSL_strdup(str);
        ctx->atContext.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_TYPE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->type.p = OPENSSL_strdup(str);
        ctx->type.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuanceDate.p = OPENSSL_strdup(str);
        ctx->issuanceDate.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_TYPE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.type.p = OPENSSL_strdup(str);
        ctx->proof.type.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_CREATED);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.created.p = OPENSSL_strdup(str);
        ctx->proof.created.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.purpose.p = OPENSSL_strdup(str);
        ctx->proof.purpose.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.verificationMethod.p = OPENSSL_strdup(str);
        ctx->proof.verificationMethod.len = strlen(str);    
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_VALUE);
    if(p != NULL) {
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.value.p = OPENSSL_strdup(str);
        ctx->proof.value.len = strlen(str);    
    }

    cJSON *vc = cJSON_CreateObject();

    // Fill the part that contains credential metadata and claims
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    // Fill the proof
    if(!vc_fill_proof(vc, ctx, NULL))
        goto fail;

    vc_stream = cJSON_Print(vc);
    cJSON_Delete(vc);

    return 1;

fail:
    cJSON_Delete(vc);
    return 0;
}

const OSSL_DISPATCH ssiprovider_vc_functions[] = {
    {OSSL_FUNC_VC_NEWCTX, (void (*)(void))vc_newctx},
    {OSSL_FUNC_VC_CREATE, (void (*)(void))vc_create},
    {OSSL_FUNC_VC_VERIFY, (void (*)(void))vc_verify},
    {OSSL_FUNC_VC_SERIALIZE, (void (*)(void))vc_serialize},
    {OSSL_FUNC_VC_DESERIALIZE, (void (*)(void))vc_deserialize},
    {OSSL_FUNC_VC_FREECTX, (void (*)(void))vc_freectx}
    {0, NULL}};