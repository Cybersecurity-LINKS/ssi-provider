#include "vc_internal.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>

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

static int compute_sig(char *md_name, EVP_PKEY *pkey, int key_type, char *tbs, char **b64_sig)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;
    unsigned char *sig;

    /* compute signature following standard OpenSSL procedure */
    mctx = EVP_MD_CTX_new();
    if (!EVP_DigestSignInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL) <= 0)
        return 0;

    if (key_type == RsaVerificationKey2023)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 
        || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
            return 0;
    }

    if (EVP_DigestSign(mctx, NULL, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(mctx, (unsigned char *)sig, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    /* ENCODE signature BASE 64  with OpenSSL EVP_EncodeBlock() utility */
    size_t b64_sig_size = (((siglen + 2) / 3) * 4) + 1;
    *b64_sig = (unsigned char *)OPENSSL_malloc(b64_sig_size);
    if (b64_sig == NULL)
        goto fail;
    if (!EVP_EncodeBlock(*b64_sig, sig, siglen))
        goto fail;

    OPENSSL_free(sig);
    return 1;

fail:
    OPENSSL_free(sig);
    return 0;
}

static int verify_sig(char *md_name, EVP_PKEY *pkey, int key_type, char *tbs, char *b64_sig)
{
    EVP_MD *md = NULL;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t sig_size = 0;
    unsigned char *sig;

    /* DECODE BASE 64 signature with OpenSSL EVP_DecodeBlock() utility */
    sig_size = (strlen(b64_sig) * 3) / 4;
    sig = (unsigned char *)OPENSSL_malloc(sig_size);
    if (sig == NULL)
        return 0;
    if (!EVP_DecodeBlock(sig, b64_sig, sig_size))
        goto fail;
    
    /* verify signature following standard OpenSSL procedure */
    mctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL) <= 0)
        goto fail;

    if (key_type == RsaVerificationKey2023) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
				|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
				RSA_PSS_SALTLEN_DIGEST) <= 0)
                return 0;
    }

    if (EVP_DigestVerify(mctx, sig, sig_size, tbs, strlen(tbs)) <= 0)
        goto fail;

    OPENSSL_free(sig);
    return 1;

fail:
    OPENSSL_free(sig);
    return 0;
}

/* static int sign_data(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
{
    char *md_name = NULL;
    int key_type;

    // get the data to be signed
    char *tbs = cJSON_Print(vc);

    // get key type from openssl
    if ((key_type = get_key_type(pkey) == -1))
        return 0;

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
        return 0;
    }

    if (!compute_sig(md_name, pkey, tbs, &ctx->proof.value.p))
        return 0;

    return 1;
}
*/

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

    // expiration date
    const cJSON *expDate_cJSON = NULL;
    expDate_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "expirationDate");
    if (cJSON_IsString(expDate_cJSON) && expDate_cJSON->valuestring != NULL)
    {
        ctx->expirationDate.len = strlen(expDate_cJSON->valuestring);
        ctx->expirationDate.p = (unsigned char *)strdup(expDate_cJSON->valuestring);
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

/* fill the metadata and claim section of the VC */
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

    // expirationDate
    if (cJSON_AddStringToObject(vc, "expirationDate", ctx->expirationDate.p) == NULL)
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
    cJSON_AddItemToObject(vc, "credentialSubject", cSubject);

    return 1;

fail:
    return 0;
}

/* fill the proof section of the VC*/
int vc_fill_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
{
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
        int key_type;

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

        if (!compute_sig(md_name, pkey, key_type, tbs, &ctx->proof.value.p))
            goto fail;
    }

    // type
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
    if (ctx->proof.purpose.p == NULL)
    {
        ctx->proof.purpose.p = OPENSSL_strdup(VC_PURPOSE);
    }
    cJSON_AddStringToObject(proof, "proofPurpose", ctx->proof.purpose.p);

    // verification method
    cJSON_AddStringToObject(proof, "verficationMethod", ctx->proof.verificationMethod.p);

    // value
    cJSON_AddStringToObject(proof, "proofValue", ctx->proof.value.p);

    cJSON_AddItemToObject(vc, "proof", proof);

    cJSON_Delete(proof);
    return 1;

fail:
    cJSON_Delete(proof);
    return 0;
}

/* check the VC structure is valid */
int vc_validate(VC_CTX *ctx)
{
    time_t now = time(0);
    char curr_time[50];
    strftime(curr_time, 50, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* the issuance date MUSTs be less then current time */
    if (ctx->issuanceDate.p == NULL || strcmp(ctx->issuanceDate.p, curr_time) > 0)
        return 0;

    /* the expiration date MUST be greater then current time */ 
    if (ctx->expirationDate.p != NULL && strcmp(ctx->expirationDate.p, curr_time) < 0)
        return 0;

    /* @context MUST be equal to "https://www.w3.org/2018/credentials/v1" */
    if (ctx->atContext.p == NULL || !strcmp(ctx->atContext.p, CONTEXT_VC_V1))
        return 0;

    /* credentail type MUST be "VerifiableCredential" */
    if (ctx->type.p == NULL || !strcmp(ctx->type.p, VC_TYPE))
        return 0;

    /* credential subjcet MUST be not null*/
    if (ctx->credentialSubject.id.p == NULL || strlen(ctx->credentialSubject.id.p))
        return 0;

    return 1;
}

/* check the VC proof is valid */
int vc_verify_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
{
    char *md_name = NULL;
    int key_type;

    // get the data to be signed
    char *tbs = cJSON_Print(vc);

    // get key type from openssl
    if ((key_type = get_key_type(pkey) == -1))
        return 0;

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
        return 0;
    }

    if (!verify_sig(md_name, pkey, key_type, tbs, ctx->proof.value.p))
        return 0;
}