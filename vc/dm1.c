/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "dm1_internal.h"
#include "../ssiprov.h"
#include <time.h>
#include <sys/time.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static OSSL_FUNC_vc_newctx_fn dm1_newctx;
static OSSL_FUNC_vc_create_fn dm1_create;
static OSSL_FUNC_vc_verify_fn dm1_verify;
static OSSL_FUNC_vc_serialize_fn dm1_serialize;
static OSSL_FUNC_vc_deserialize_fn dm1_deserialize;
static OSSL_FUNC_vc_freectx_fn dm1_freectx;
static OSSL_FUNC_vc_set_ctx_params_fn dm1_set_ctx_params;
static OSSL_FUNC_vc_get_ctx_params_fn dm1_get_ctx_params;

void *dm1_newctx(void *provctx)
{ 
    VC_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    return ctx;
}

void dm1_freectx(void *vcctx)
{

    VC_CTX *ctx = (VC_CTX *)vcctx;

    if (ctx != NULL) {
        if (ctx->atContext != NULL) {
            OPENSSL_free(ctx->atContext);
            ctx->atContext = NULL;
        }

        if (ctx->id != NULL) {
            OPENSSL_free(ctx->id);
            ctx->id = NULL;
        }

        if (ctx->type != NULL) {
            OPENSSL_free(ctx->type);
            ctx->type = NULL;
        }

        if (ctx->issuer != NULL) {
            OPENSSL_free(ctx->issuer);
            ctx->issuer = NULL;
        }

        if (ctx->issuanceDate != NULL) {
            OPENSSL_free(ctx->issuanceDate);
            ctx->issuanceDate = NULL;
        }

        if (ctx->expirationDate != NULL) {
            OPENSSL_free(ctx->expirationDate);
            ctx->expirationDate = NULL;
        }

        if (ctx->credentialSubject.id != NULL) {
            OPENSSL_free(ctx->credentialSubject.id);
            ctx->credentialSubject.id = NULL;
        }

        if (ctx->proof.type != NULL) {
            OPENSSL_free(ctx->proof.type);
            ctx->proof.type = NULL;
        }

        if (ctx->proof.created != NULL) {
            OPENSSL_free(ctx->proof.created);
            ctx->proof.created = NULL;
        }

        if (ctx->proof.purpose != NULL) {
            OPENSSL_free(ctx->proof.purpose);
            ctx->proof.purpose = NULL;
        }

        if (ctx->proof.verificationMethod != NULL) {
            OPENSSL_free(ctx->proof.verificationMethod);
            ctx->proof.verificationMethod = NULL;
        }

        if (ctx->proof.value != NULL) {
            OPENSSL_free(ctx->proof.value);
            ctx->proof.value = NULL;
        }
    }
}

char *dm1_create(void *vcctx, EVP_PKEY *pkey, OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    VC_CTX *ctx = (VC_CTX *)vcctx;

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL) {
        return NULL;
    }

    /* Fill ctx with metadata and claims. Some fields are
    retrieved from params[], some other are generated on the fly. */
    ctx->atContext = OPENSSL_strdup(CONTEXT_VC_V1);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    ctx->type = OPENSSL_strdup(VC_TYPE);

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    time_t now = time(0);
    ctx->issuanceDate = (char *)OPENSSL_zalloc(100);
    strftime(ctx->issuanceDate, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->expirationDate = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    /* Starting from ctx fill the JSON object with
    credential metadata and claims. */
    if (!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    /* Fill ctx with proof. Some fields are
    retrieved from params[], some other are
    generated on the fly in the proof creation. */
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->proof.verificationMethod = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    /* Generate the proof and fill the JSON object with the proof */
    if (!vc_fill_proof(vc, ctx, pkey))
        goto fail;

    /* Return the serialized vc */
    char *verifiable_credential = cJSON_Print(vc);
    cJSON_Delete(vc);
    return verifiable_credential;

fail:
    cJSON_Delete(vc);
    return NULL;
}

int dm1_verify(void *vcctx, EVP_PKEY *pkey, OSSL_PARAM params[]) 
{
    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 0;

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL) {
        return 0;
    }

    /* Fill ctx with metadata and claims. */
    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->atContext = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->type = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuer = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->issuanceDate = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->expirationDate = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->credentialSubject.id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            goto fail;
        ctx->proof.value = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    if (!vc_validate(ctx))
        goto fail;

    /* Starting from ctx fill the JSON object with
    credential metadata and claims. */
    if (!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    if (!vc_verify_proof(vc, ctx, pkey))
        goto fail;

    cJSON_Delete(vc);
    return 1;

fail:
    cJSON_Delete(vc);
    return 0;
}

int dm1_deserialize(void *vcctx, unsigned char *vc_stream, OSSL_PARAM params[])
{
    VC_CTX *ctx = (VC_CTX *)vcctx;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 0;

    /* parse the serialized vc and save the fields in ctx */
    if (!vc_cjson_parse(ctx, vc_stream))
        return 0;

    /* return the fields of the VC through params[] */
    if (!dm1_get_ctx_params((void *)ctx, params))
        return 0;

    return 1;
}

char *dm1_serialize(void *vcctx, OSSL_PARAM params[])
{
    VC_CTX *ctx = (VC_CTX *)vcctx;

    if (ctx == NULL)
        return NULL;
    if (params == NULL)
        return NULL;

    /* retrieves from params[] the fields of the VC
    and assign it to ctx  */
    if (!dm1_set_ctx_params((void *)ctx, params))
        return NULL;

    cJSON *vc = cJSON_CreateObject();

    /* Starting from ctx fill the JSON object with
    credential metadata and claims. */
    if (!vc_fill_metadata_claim(vc, ctx))
        goto fail;

    /* Starting from ctx fill the JSON object with
    proof. */
    if (!vc_fill_proof(vc, ctx, NULL))
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

int dm1_set_ctx_params(void *vcctx, const OSSL_PARAM params[])
{
    VC_CTX *ctx = (VC_CTX *)vcctx;
    const OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->atContext = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ID);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->type = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuer = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->issuanceDate = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->expirationDate = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->credentialSubject.id = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_TYPE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.type = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_CREATED);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.created = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.purpose = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.verificationMethod = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL) {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_VC_FIELD))
            return 0;
        ctx->proof.value = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    return 1;
}

int dm1_get_ctx_params(void *vcctx, OSSL_PARAM params[])
{

    VC_CTX *ctx = (VC_CTX *)vcctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_CONTEXT);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->atContext))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->id))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUER);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->issuer))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_ISSUANCE_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->issuanceDate))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_EXPIRATION_DATE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->expirationDate))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_SUBJECT);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->credentialSubject.id))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->proof.type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_CREATED);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->proof.created))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_PURPOSE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->proof.purpose))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_VERIFICATION_METHOD);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->proof.verificationMethod))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_VC_PARAM_PROOF_VALUE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->proof.value))
        return 0;

    return 1;
}

const OSSL_DISPATCH vc_functions[] = {
    {OSSL_FUNC_VC_NEWCTX, (void (*)(void))dm1_newctx},
    {OSSL_FUNC_VC_CREATE, (void (*)(void))dm1_create},
    {OSSL_FUNC_VC_VERIFY, (void (*)(void))dm1_verify},
    {OSSL_FUNC_VC_SERIALIZE, (void (*)(void))dm1_serialize},
    {OSSL_FUNC_VC_DESERIALIZE, (void (*)(void))dm1_deserialize},
    {OSSL_FUNC_VC_FREECTX, (void (*)(void))dm1_freectx},
    {OSSL_FUNC_VC_SET_CTX_PARAMS, (void (*)(void))dm1_set_ctx_params},
    {OSSL_FUNC_VC_GET_CTX_PARAMS, (void (*)(void))dm1_get_ctx_params},
    {0, NULL}};
