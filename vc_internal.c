#include "vc_internal.h"
#include <openssl/evp.h>

int get_key_type(EVP_PKEY *key)
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

int compute_sig(char *md_name, EVP_PKEY *pkey, char *tbs, char *sig)
{

    EVP_MD *md;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;

    mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL);

    /*EVP_PKEY = RSA fai delle cose*/

    if (EVP_DigestSign(mctx, NULL, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(mctx, (unsigned char *)sig, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return 0;

    return 1;
}

int vc_cjson_parse(VC_CTX *vc, unsigned char *vc_stream)
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
        vc->atContext.len = strlen(atContext->valuestring);
        vc->atContext.p = (unsigned char *)strdup(atContext->valuestring);
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
        vc->id.len = strlen(id_cJSON->valuestring);
        vc->id.p = (unsigned char *)strdup(id_cJSON->valuestring);
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
        vc->type.len = strlen(type_cJSON->valuestring);
        vc->type.p = (unsigned char *)strdup(type_cJSON->valuestring);
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
        vc->issuer.len = strlen(issuer_cJSON->valuestring);
        vc->issuer.p = (unsigned char *)strdup(issuer_cJSON->valuestring);
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
        vc->issuanceDate.len = strlen(issDate_cJSON->valuestring);
        vc->issuanceDate.p = (unsigned char *)strdup(issDate_cJSON->valuestring);
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
        vc->credentialSubject.id.len = strlen(subject_id_cJSON->valuestring);
        vc->credentialSubject.id.p = (unsigned char *)strdup(subject_id_cJSON->valuestring);
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
        vc->proof.type.len = strlen(proof_type_cJSON->valuestring);
        vc->proof.type.p = (unsigned char *)strdup(proof_type_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_created_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "created");
    if (cJSON_IsString(proof_created_cJSON) && proof_created_cJSON->valuestring != NULL)
    {
        vc->proof.created.len = strlen(proof_created_cJSON->valuestring);
        vc->proof.created.p = (unsigned char *)strdup(proof_created_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_purpose_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofPurpose");
    if (cJSON_IsString(proof_purpose_cJSON) && proof_purpose_cJSON->valuestring != NULL)
    {
        vc->proof.purpose.len = strlen(proof_purpose_cJSON->valuestring);
        vc->proof.purpose.p = (unsigned char *)strdup(proof_purpose_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_vmethod_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "verificationMethod");
    if (cJSON_IsString(proof_vmethod_cJSON) && proof_vmethod_cJSON->valuestring != NULL)
    {
        vc->proof.verificationMethod.len = strlen(proof_vmethod_cJSON->valuestring);
        vc->proof.verificationMethod.p = (unsigned char *)strdup(proof_vmethod_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    proof_value_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofValue");
    if (cJSON_IsString(proof_value_cJSON) && proof_value_cJSON->valuestring != NULL)
    {
        vc->proof.value.len = strlen(proof_value_cJSON->valuestring);
        vc->proof.value.p = (unsigned char *)strdup(proof_value_cJSON->valuestring);
    }
    else
    {
        return VC_PARSE_ERROR;
    }

    cJSON_Delete(vc_json);

    return VC_PARSE_OK;

    return 1;
}

int vc_fill_metadata_claim(cJSON *vc, char *context, char *id, char *type, char *issuer, char *issuance_date, char *subject)
{
    cJSON *cSubject = NULL;

    //@context
    if (cJSON_AddStringToObject(vc, "@context", context) == NULL)
    {
        goto fail;
    }

    // id
    if (cJSON_AddStringToObject(vc, "id", id) == NULL)
    {
        goto fail;
    }

    // type
    if (cJSON_AddStringToObject(vc, "type", type) == NULL)
    {
        goto fail;
    }

    // issuer
    if (cJSON_AddStringToObject(vc, "issuer", issuer) == NULL)
    {
        goto fail;
    }

    // issuanceDate
    if (issuance_date == NULL)
    {
        time_t now = time(0);
        issuance_date = (char *)malloc(100);
        strftime(issuance_date, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    }

    // issuanceDate
    if (cJSON_AddStringToObject(vc, "issuanceDate", issuance_date) == NULL)
    {
        goto fail;
    }

    // credential subject
    cSubject = cJSON_CreateObject();
    if (cSubject == NULL)
    {
        goto fail;
    }

    cJSON_AddStringToObject(cSubject, "id", subject);
    
    return 1;

fail:
    return 0;
}

int vc_fill_proof(cJSON *vc, EVP_PKEY *pkey, char *type, char *created, char *verification_method, char *purpose, char *value)
{
    int key_type;
    char *sig = NULL;
    int key_type;

    // proof
    cJSON *proof = cJSON_CreateObject();
    if (proof == NULL)
    {
        goto fail;
    }

    if (pkey != NULL && value == NULL)
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
            cJSON_AddStringToObject(proof, "type", "RsaVerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case EcdsaSecp256r1VerificationKey2023:
            cJSON_AddStringToObject(proof, "type", "EcdsaSecp256r1VerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case Ed25519VerificationKey2023:
            cJSON_AddStringToObject(proof, "type", "Ed25519VerificationKey2023");
            break;
        default:
            printf("Unrecognised key type\n");
            goto fail;
        }

        if (!compute_sig(md_name, pkey, tbs, value))
            goto fail;
    } else {
        cJSON_AddStringToObject(proof, "type", type);
    }

    // created
    if (created == NULL)
    {
        created = (char *)malloc(100);
        time_t now = time(0);
        strftime(created, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    }
    cJSON_AddStringToObject(proof, "created", created);

    // purpose
    cJSON_AddStringToObject(proof, "proofPurpose", "assertionMethod");

    // verification method
    cJSON_AddStringToObject(proof, "verficationMethod", verification_method);

    /*ENCODE BASE 64*/

    // value
    cJSON_AddStringToObject(proof, "proofValue", value);

    return 1;

fail:
    return 0;
}