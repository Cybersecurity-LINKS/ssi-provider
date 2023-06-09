#include "vc_internal.h"
#include <time.h>
#include <sys/time.h>
#include <openssl/err.h>
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
    
    /*if (!ossl_prov_is_running())
        return NULL;*/

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
		if (ctx->id.p != NULL) {
			OPENSSL_free(ctx->id.p);
			ctx->id.p = NULL;
		}
        OPENSSL_free(ctx->type.p);
        ctx->id.p = NULL;
        OPENSSL_free(ctx->issuer.p);
        ctx->issuer.p = NULL;
        OPENSSL_free(ctx->issuanceDate.p);
        ctx->issuanceDate.p = NULL;
        OPENSSL_free(ctx->expirationDate.p);
        ctx->expirationDate.p = NULL;

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

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL)
    {
        return NULL;
    }

    /* Fill ctx with metadata and claims. Some fields are 
    retrieved from params[], some other are generated on the fly. */
    ctx->atContext.p = OPENSSL_strdup(CONTEXT_VC_V1);
    ctx->atContext.len = strlen(ctx->atContext.p);
    
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);
        OPENSSL_free(str);
    }

    ctx->type.p = OPENSSL_strdup(VC_TYPE);
    ctx->type.len = strlen(ctx->type.p);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);
        OPENSSL_free(str);
    }

    time_t now = time(0);
    ctx->issuanceDate.p = (char *)malloc(100);
    strftime(ctx->issuanceDate.p, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    ctx->issuanceDate.len = strlen(ctx->issuanceDate.p);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->expirationDate.p = OPENSSL_strdup(str);
        ctx->expirationDate.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);
        OPENSSL_free(str);
    }

    /* Starting from ctx fill the JSON object with 
    credential metadata and claims. */
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    /* Fill ctx with proof. Some fields are 
    retrieved from params[], some other are 
    generated on the fly in the proof creation. */
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->proof.verificationMethod.p = OPENSSL_strdup(str);
        ctx->proof.verificationMethod.len = strlen(str);
        OPENSSL_free(str);
    }

    /* Generate the proof and fill the JSON object with the proof */
    if(!vc_fill_proof(vc, ctx, pkey))
        goto fail;

    /* return to the caller the fields of the 
    created vc through params[]*/
    /*if(!vc_get_ctx_params((void *)ctx, params))
        return 0;*/

    /* Return the serialized vc */
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

    if (ctx == NULL)
        return 0;
    if(params == NULL)
        return 0;

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL)
    {
        return 0;
    }

    /* Fill ctx with metadata and claims. */
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->atContext.p = OPENSSL_strdup(str);
        ctx->atContext.len = strlen(str);
        OPENSSL_free(str);
    }
    
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_TYPE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->type.p = OPENSSL_strdup(str);
        ctx->type.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuanceDate.p = OPENSSL_strdup(str);
        ctx->issuanceDate.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->expirationDate.p = OPENSSL_strdup(str);
        ctx->expirationDate.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_VALUE);
	if (p != NULL) {
		char *str = NULL;
		if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
			goto fail;
		ctx->proof.value.p = OPENSSL_strdup(str);
		ctx->proof.value.len = strlen(str);
		OPENSSL_free(str);
	}

    if(!vc_validate(ctx))
        goto fail;

    /* Starting from ctx fill the JSON object with 
    credential metadata and claims. */
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    if(!vc_verify_proof(vc, ctx, pkey))
        goto fail;

fail:
    cJSON_Delete(vc);
    return 0;
}

int vc_deserialize(void *vcctx, unsigned char *vc_stream, OSSL_PARAM params[])
{

    VC_CTX *ctx = (VC_CTX *)vcctx;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 0;
    
    /* parse the serialized vc and save the fields in ctx */
    if (vc_cjson_parse(ctx, vc_stream) == VC_PARSE_ERROR)
    {
        return 0;
    }

    if (ctx->atContext.p == NULL || ctx->id.p == NULL || ctx->type.p == NULL || ctx->issuer.p == NULL 
        || ctx->issuanceDate.p == NULL || ctx->expirationDate.p == NULL || ctx->credentialSubject.id.p == NULL || 
        ctx->proof.type.p == NULL || ctx->proof.created.p == NULL || ctx->proof.purpose.p == NULL ||
        ctx->proof.verificationMethod.p == NULL || ctx->proof.value.p == NULL)
        return 0;

    /* return the fields of the VC through params[] */ 
    if(!vc_get_ctx_params((void *)ctx, params))
        return 0;
    
    return 1;
}

unsigned char* vc_serialize(void *vcctx, OSSL_PARAM params[])
{
    VC_CTX *ctx = (VC_CTX *)vcctx;
    
    if (ctx == NULL)
        return NULL;
    if (params == NULL)
        return NULL;
    
    /* retrieves from params[] the fields of the VC 
    and assign it to ctx  */
    if(!vc_set_ctx_params((void *)ctx, params))
        return NULL;

    cJSON *vc = cJSON_CreateObject();

    /* Starting from ctx fill the JSON object with 
    credential metadata and claims. */
    if(!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    /* Starting from ctx fill the JSON object with 
    proof. */
    if(!vc_fill_proof(vc, ctx, NULL))
        goto fail;

    char *vc_stream = NULL;
    /* serialize the VC */
    vc_stream = strdup(cJSON_Print(vc));
    cJSON_Delete(vc);
    return vc_stream;

fail:
    cJSON_Delete(vc);
    return NULL;
}

int vc_set_ctx_params (void *vcctx, const OSSL_PARAM params[]) {

    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->atContext.p = OPENSSL_strdup(str);
        ctx->atContext.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->id.p = OPENSSL_strdup(str);
        ctx->id.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_TYPE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->type.p = OPENSSL_strdup(str);
        ctx->type.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuer.p = OPENSSL_strdup(str);
        ctx->issuer.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuanceDate.p = OPENSSL_strdup(str);
        ctx->issuanceDate.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->expirationDate.p = OPENSSL_strdup(str);
        ctx->expirationDate.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->credentialSubject.id.p = OPENSSL_strdup(str);
        ctx->credentialSubject.id.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_TYPE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.type.p = OPENSSL_strdup(str);
        ctx->proof.type.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_CREATED);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.created.p = OPENSSL_strdup(str);
        ctx->proof.created.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.purpose.p = OPENSSL_strdup(str);
        ctx->proof.purpose.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.verificationMethod.p = OPENSSL_strdup(str);
        ctx->proof.verificationMethod.len = strlen(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_VALUE);
    if(p != NULL) {
    	char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.value.p = OPENSSL_strdup(str);
        ctx->proof.value.len = strlen(str);
        OPENSSL_free(str);
    }

    return 1;
}

int vc_get_ctx_params(void *vcctx, OSSL_PARAM params[]) {
    
    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->atContext.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->issuer.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->issuanceDate.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->expirationDate.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->credentialSubject.id.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->proof.type.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_CREATED);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->proof.created.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->proof.purpose.p))
        return 0;
    
    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->proof.verificationMethod.p))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, ctx->proof.value.p))
        return 0;

    return 1;
}

const OSSL_DISPATCH vc_functions[] = {
    {OSSL_FUNC_VC_NEWCTX, (void (*)(void))vc_newctx},
    {OSSL_FUNC_VC_CREATE, (void (*)(void))vc_create},
    {OSSL_FUNC_VC_VERIFY, (void (*)(void))vc_verify},
    {OSSL_FUNC_VC_SERIALIZE, (void (*)(void))vc_serialize},
    {OSSL_FUNC_VC_DESERIALIZE, (void (*)(void))vc_deserialize},
    {OSSL_FUNC_VC_FREECTX, (void (*)(void))vc_freectx},
    {OSSL_FUNC_VC_SET_CTX_PARAMS, (void (*)(void))vc_set_ctx_params},
    {OSSL_FUNC_VC_GET_CTX_PARAMS, (void (*)(void))vc_get_ctx_params},
    {0, NULL}};
