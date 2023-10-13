/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include "did_internal.h"

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

    if (ctx != NULL)
    {
        if (ctx->atContext != NULL)
        {
            OPENSSL_free(ctx->atContext);
            ctx->atContext = NULL;
        }

        if (ctx->id != NULL)
        {
            OPENSSL_free(ctx->id);
            ctx->id = NULL;
        }

        if (ctx->created != NULL)
        {
            OPENSSL_free(ctx->created);
            ctx->created = NULL;
        }

        if (ctx->authentication.id != NULL)
        {
            OPENSSL_free(ctx->authentication.id);
            ctx->authentication.id = NULL;
        }

        if (ctx->authentication.type != NULL)
        {
            OPENSSL_free(ctx->authentication.type);
            ctx->authentication.type = NULL;
        }

        if (ctx->authentication.controller != NULL)
        {
            OPENSSL_free(ctx->authentication.controller);
            ctx->authentication.controller = NULL;
        }

        if (ctx->authentication.pkey != NULL)
        {
            OPENSSL_free(ctx->authentication.pkey);
            ctx->authentication.pkey = NULL;
        }

        if (ctx->assertion.id != NULL)
        {
            OPENSSL_free(ctx->assertion.id);
            ctx->assertion.id = NULL;
        }

        if (ctx->assertion.type != NULL)
        {
            OPENSSL_free(ctx->assertion.type);
            ctx->assertion.type = NULL;
        }

        if (ctx->assertion.controller != NULL)
        {
            OPENSSL_free(ctx->assertion.controller);
            ctx->assertion.controller = NULL;
        }

        if (ctx->assertion.pkey != NULL)
        {
            OPENSSL_free(ctx->assertion.pkey);
            ctx->assertion.pkey = NULL;
        }
    }
}

char *did_create(void *didctx, OSSL_PARAM params[]){

    /* printf("DID OTT CREATE\n"); */
    
    const OSSL_PARAM *p;
    DID_CTX *ctx = (DID_CTX *)didctx;

    /* @Context */
    ctx->atContext = OPENSSL_strdup(CONTEXT_DID_V1);

    /* created */
    time_t now = time(0);
    ctx->created = (char *)OPENSSL_zalloc(100);
    strftime(ctx->created, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* authentication public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_AUTHN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->authentication.pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    /* assertion public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_ASSRTN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->assertion.pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    if(!did_ott_create(ctx))
        goto fail;

    return ctx->id;
fail:
    return NULL;
}

int did_resolve(void *didctx, char *did, OSSL_PARAM params[]){

    DID_CTX *ctx = (DID_CTX *)didctx;

    int ret;
    /* printf("DID OTT RESOLVE\n"); */
    
    if (did == NULL) {
        return 0;
    }

    ret = did_ott_resolve(ctx, did);
    if (ret == DID_RESOLVE_ERROR){
    	printf("DID RESOLVE INTERNAL ERROR\n");
        return 0;
    }
    else if (ret == DID_RESOLVE_REVOKED){
    	printf("DID DOCUMENT REVOKED\n");
        return 0;
    }
    else if (ret == DID_RESOLVE_NOT_FOUND){
    	printf("DID DOCUMENT NOT FOUND\n");
        return 0;
    }

    /* return the fields of the DID DOCUMENT through params[] */
    if(!did_get_ctx_params((void *)ctx, params))
        return 0;

    printf("RESOLVE SUCCESSFUL\n");
    return 1;
}

char* did_update(void *didctx, OSSL_PARAM params[]) {

    /* printf("DID OTT UPDATE\n"); */

    const OSSL_PARAM *p;
    DID_CTX *ctx = (DID_CTX *)didctx;

    /* @Context */
    ctx->atContext = OPENSSL_strdup(CONTEXT_DID_V1);

    /* created */
    time_t now = time(0);
    ctx->created = (char *)OPENSSL_zalloc(100);
    strftime(ctx->created, 100, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* authentication public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_AUTHN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->authentication.pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    /* assertion public key */
    p = OSSL_PARAM_locate_const(params, OSSL_DID_PARAM_ASSRTN_METH_PKEY);
    if (p != NULL)
    {
        char *str = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &str, MAX_DID_FIELD))
            goto fail;
        ctx->assertion.pkey = OPENSSL_strdup(str);
        OPENSSL_free(str);
    }

    if(!did_ott_update(ctx))
        goto fail;

    return ctx->id;
fail:
    return NULL;
}

int did_revoke(void *didctx){
    
    DID_CTX *ctx = (DID_CTX *)didctx;
    
    /* printf("DID OTT REVOKE\n"); */
    printf("%s\n",ctx->id);

    if(!did_ott_revoke(ctx))
        return 0;

    return 1;
}

int did_set_ctx_params(void *didctx, const OSSL_PARAM params[]){

    return 1;
}

int did_get_ctx_params(void *didctx, OSSL_PARAM params[]){

    DID_CTX *ctx = (DID_CTX *)didctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_CONTEXT);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->atContext))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->id))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_CREATED);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->created))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_AUTHN_METH_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->authentication.id))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_AUTHN_METH_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->authentication.type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_AUTHN_METH_CONTROLLER);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->authentication.controller))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_AUTHN_METH_PKEY);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->authentication.pkey))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_ASSRTN_METH_ID);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->assertion.id))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_ASSRTN_METH_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->assertion.type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_ASSRTN_METH_CONTROLLER);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->assertion.controller))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DID_PARAM_ASSRTN_METH_PKEY);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, (const char *)ctx->assertion.pkey))
        return 0;

    return 1;  
}

const OSSL_DISPATCH did_crud_functions[] = {
    {OSSL_FUNC_DID_NEWCTX, (void(*)(void))did_newctx},
    {OSSL_FUNC_DID_CREATE, (void(*)(void))did_create},
    {OSSL_FUNC_DID_RESOLVE, (void(*)(void))did_resolve},
    {OSSL_FUNC_DID_UPDATE, (void(*)(void))did_update},
    {OSSL_FUNC_DID_REVOKE, (void(*)(void))did_revoke},
    {OSSL_FUNC_DID_FREECTX, (void(*)(void))did_freectx},
    {OSSL_FUNC_DID_SET_CTX_PARAMS, (void(*)(void))did_set_ctx_params},
    {OSSL_FUNC_DID_GET_CTX_PARAMS, (void(*)(void))did_get_ctx_params},
    { 0, NULL }
};
