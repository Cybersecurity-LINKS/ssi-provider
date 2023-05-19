#include "vc_internal.h"
#include <openssl/evp.h>

static int get_key_type(EVP_PKEY *key)
{
    int ret = 0;
    ret = EVP_PKEY_get_id(key);
    // printf("key type %d\n", ret);
    // const char * name1 = EVP_PKEY_get0_type_name(key2);
    switch (ret)
    {
    case EVP_PKEY_RSA:
        ret = RsaVerificationKey2023;
        break;
    case EVP_PKEY_EC:
        ret = EcdsaSecp256r1VerificationKey2023;
        break;
    case EVP_PKEY_ED25519:
        ret = Ed25519VerificationKey2023;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

static int compute_sig(char *md_name, EVP_PKEY *pkey, char *tbs, char **b64_sig)
{
    EVP_MD *md;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;
    unsigned char *sig;

    mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL);

    /*EVP_PKEY = RSA fai delle cose*/

    if (EVP_DigestSign(mctx, NULL, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(mctx, (unsigned char *)sig, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    //ENCODE BASE 64
    size_t b64_sig_size = (((siglen + 2) / 3) * 4) + 1;
    *b64_sig = (unsigned char*) OPENSSL_malloc(b64_sig_size);
    if(b64_sig == NULL)
        goto fail;
    if(!EVP_EncodeBlock(*b64_sig, sig, siglen)) 
        goto fail;

    OPENSSL_free(sig);
    return 1;

fail:
    OPENSSL_free(sig);
    return 0;
}

int vc_cjson_parse(VC_CTX *ctx, unsigned char *vc_stream)
{

    cJSON *vc_json = cJSON_Parse((const char *)vc_stream);
    if (vc_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }

        return VC_PARSE_ERROR;
    }

    // atContext
    const cJSON *atContext = NULL;
    atContext = cJSON_GetObjectItemCaseSensitive(vc_json, "@context");

    if (cJSON_IsString(atContext) && atContext->valuestring != NULL)
    {
        ctx->atContext.len = strlen(atContext->valuestring);
        ctx->atContext.p = (unsigned char *)strdup(atContext->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // id
    const cJSON *id_cJSON = NULL;
    id_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "id");
    if (cJSON_IsString(id_cJSON) && id_cJSON->valuestring != NULL)
    {
        ctx->id.len = strlen(id_cJSON->valuestring);
        ctx->id.p = (unsigned char *)strdup(id_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // type
    const cJSON *type_cJSON = NULL;
    type_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL)
    {
        ctx->type.len = strlen(type_cJSON->valuestring);
        ctx->type.p = (unsigned char *)strdup(type_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // issuer
    const cJSON *issuer_cJSON = NULL;
    issuer_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "issuer");
    if (cJSON_IsString(issuer_cJSON) && issuer_cJSON->valuestring != NULL)
    {
        ctx->issuer.len = strlen(issuer_cJSON->valuestring);
        ctx->issuer.p = (unsigned char *)strdup(issuer_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // issuance date
    const cJSON *issDate_cJSON = NULL;
    issDate_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "issuanceDate");
    if (cJSON_IsString(issDate_cJSON) && issDate_cJSON->valuestring != NULL)
    {
        ctx->issuanceDate.len = strlen(issDate_cJSON->valuestring);
        ctx->issuanceDate.p = (unsigned char *)strdup(issDate_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // credential subject
    const cJSON *subject_cJSON = NULL;
    const cJSON *subject_id_cJSON = NULL;

    subject_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "credentialSubject");
    if (subject_cJSON == NULL || !cJSON_IsObject(subject_cJSON))
    {
        return VC_PARSE_ERROR;
    }
    subject_id_cJSON = cJSON_GetObjectItemCaseSensitive(subject_cJSON, "id");
    if (cJSON_IsString(subject_id_cJSON) && subject_id_cJSON->valuestring != NULL)
    {
        ctx->credentialSubject.id.len = strlen(subject_id_cJSON->valuestring);
        ctx->credentialSubject.id.p = (unsigned char *)strdup(subject_id_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    // proof
    const cJSON *proof_cJSON = NULL;

    const cJSON *proof_type_cJSON = NULL;
    const cJSON *proof_created_cJSON = NULL;
    const cJSON *proof_purpose_cJSON = NULL;
    const cJSON *proof_vmethod_cJSON = NULL;
    const cJSON *proof_value_cJSON = NULL;

    proof_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "proof");
    if (proof_cJSON == NULL || !cJSON_IsObject(proof_cJSON))
    {
        return VC_PARSE_ERROR;
    }

    proof_type_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "type");
    if (cJSON_IsString(proof_type_cJSON) && proof_created_cJSON->valuestring != NULL)
    {
        ctx->proof.type.len = strlen(proof_type_cJSON->valuestring);
        ctx->proof.type.p = (unsigned char *)strdup(proof_type_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_created_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "created");
    if (cJSON_IsString(proof_created_cJSON) && proof_created_cJSON->valuestring != NULL)
    {
        ctx->proof.created.len = strlen(proof_created_cJSON->valuestring);
        ctx->proof.created.p = (unsigned char *)strdup(proof_created_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_purpose_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofPurpose");
    if (cJSON_IsString(proof_purpose_cJSON) && proof_purpose_cJSON->valuestring != NULL)
    {
        ctx->proof.purpose.len = strlen(proof_purpose_cJSON->valuestring);
        ctx->proof.purpose.p = (unsigned char *)strdup(proof_purpose_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_vmethod_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "verificationMethod");
    if (cJSON_IsString(proof_vmethod_cJSON) && proof_vmethod_cJSON->valuestring != NULL)
    {
        ctx->proof.verificationMethod.len = strlen(proof_vmethod_cJSON->valuestring);
        ctx->proof.verificationMethod.p = (unsigned char *)strdup(proof_vmethod_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_value_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofValue");
    if (cJSON_IsString(proof_value_cJSON) && proof_value_cJSON->valuestring != NULL)
    {
        ctx->proof.value.len = strlen(proof_value_cJSON->valuestring);
        ctx->proof.value.p = (unsigned char *)strdup(proof_value_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    cJSON_Delete(vc_json);

    return VC_PARSE_OK;

    return 1;
}

int vc_fill_metadata_claim(cJSON *vc, VC_CTX *ctx)
{

    //@context
    if (cJSON_AddStringToObject(vc, "@context", ctx->atContext.p) == NULL)
    {
        goto fail;
    }

    // id
    if (cJSON_AddStringToObject(vc, "id", ctx->id.p) == NULL)
    {
        goto fail;
    }

    // type
    if (cJSON_AddStringToObject(vc, "type", ctx->type.p) == NULL)
    {
        goto fail;
    }

    // issuer
    if (cJSON_AddStringToObject(vc, "issuer", ctx->issuer.p) == NULL)
    {
        goto fail;
    }

    // issuanceDate
    if (cJSON_AddStringToObject(vc, "issuanceDate", ctx->issuanceDate.p) == NULL)
    {
        goto fail;
    }

    // credential subject
    cJSON *cSubject = cJSON_CreateObject();
    if (cSubject == NULL)
    {
        goto fail;
    }

    cJSON_AddStringToObject(cSubject, "id", ctx->credentialSubject.id.p);
    cJSON_AddItemToObject(vc, "authenticationMethod", cSubject);

    return 1;

fail:
    return 0;
}

int vc_fill_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
{
    int key_type;

    // proof
    cJSON *proof = cJSON_CreateObject();
    if (proof == NULL)
    {
        goto fail;
    }

    /* If we don't pass the key then we are serializing not creating the vc */
    if (pkey != NULL)
    {
        char *md_name = NULL;

        // get the data to be signed
        char *tbs = cJSON_Print(vc);

        // get key type from openssl
        if ((key_type = get_key_type(pkey) == -1))
            goto fail;

        // type field and selects the digest to compute the signature
        switch (key_type)
        {
        case RsaVerificationKey2023:
            ctx->proof.type.p = OPENSSL_strdup("RsaVerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case EcdsaSecp256r1VerificationKey2023:
            ctx->proof.type.p = OPENSSL_strdup("EcdsaSecp256r1VerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case Ed25519VerificationKey2023:
            ctx->proof.type.p = OPENSSL_strdup("Ed25519VerificationKey2023");
            break;
        default:
            printf("Unrecognised key type\n");
            goto fail;
        }

        if (!compute_sig(md_name, pkey, tbs, &ctx->proof.value.p))
            goto fail;
    } 
    
    //type
    cJSON_AddStringToObject(proof, "type", ctx->proof.type.p);

    // created
    if (ctx->proof.created.p == NULL)
    {
        ctx->proof.created.p = (char *)malloc(100);
        time_t now = time(0);
        strftime(ctx->proof.created.p, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    }
    cJSON_AddStringToObject(proof, "created", ctx->proof.created.p);

    // purpose
    if(ctx->proof.purpose.p == NULL)
    {
        ctx->proof.purpose.p = OPENSSL_strdup(VC_PURPOSE);
    }
    cJSON_AddStringToObject(proof, "proofPurpose", ctx->proof.purpose.p);

    // verification method
    cJSON_AddStringToObject(proof, "verficationMethod", ctx->proof.verificationMethod.p);

    // value
    cJSON_AddStringToObject(proof, "proofValue", ctx->proof.value.p);

    cJSON_AddItemToObject(vc, "proof", proof);
    return 1;

fail:
    return 0;
}

int vc_validate(VC_CTX *ctx){

    time_t now = time(0);
    char curr_time[50];
    strftime(curr_time, 50, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    if(ctx->issuanceDate.p == NULL || strcmp(ctx->issuanceDate.p, curr_time) > 0)
        return 0;

    if(ctx->expirationDate.p != NULL && strcmp(ctx->expirationDate.p, curr_time) < 0)
        return 0;

    if(ctx->atContext.p == NULL || !strcmp(ctx->atContext.p, CONTEXT_VC_V1))
        return 0;

    if(ctx->type.p == NULL || !strcmp(ctx->type.p, VC_TYPE))
        return 0;

    if(ctx->credentialSubject.id.p == NULL || strlen(ctx->credentialSubject.id.p))
        return 0;

    return 1;
}

int vc_verify_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey){

    // riempi la vc_json di metadata and claims con i campi di ctx

    // printala con cJSON print

    // verify_signature(vc_stream, EVP_PKEY, ctx->proof.value.p)

}