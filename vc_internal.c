#include "vc_internal.h"
#include <openssl/evp.h>

void vc_init(verifiable_credential *vc)
{
    memset(vc, 0, sizeof(verifiable_credential));
}

void vc_free(verifiable_credential *vc)
{
    if(vc == NULL)
        return;

    free(vc->atContext.p);
    free(vc->id.p);
    free(vc->type.p);
    free(vc->issuer.p);
    free(vc->issuanceDate.p);

    free(vc->credentialSubject.id.p);

    free(vc->proof.type.p);
    free(vc->proof.created.p);
    free(vc->proof.purpose.p);
    free(vc->proof.verificationMethod.p);
    free(vc->proof.signature.p);
}

int compute_sig(char *md_name, EVP_PKEY *pkey, char *tbs, char* sig) {

    EVP_MD *md;
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;

    mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL);

    /*EVP_PKEY = RSA fai delle cose*/

    if(EVP_DigestSign(mctx, NULL, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return -1;

    sig = OPENSSL_malloc(siglen);
    if(sig == NULL || EVP_DigestSign(mctx, (unsigned char *)sig, &siglen, tbs, EVP_MAX_MD_SIZE) <= 0)
        return -1;

    /* CODIFICA BASE 64 */

    return 1;
}

int vc_cjson_parse(verifiable_credential *vc, unsigned char *vc_stream) {

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

    //id
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

    //type
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

    //issuer
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

    //issuance date
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

    //credential subject
    const cJSON *subject_cJSON = NULL;
    const cJSON *subject_id_cJSON = NULL;\

    subject_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "credentialSubject");
    if (subject_cJSON == NULL || !cJSON_IsObject(subject_cJSON))
    {
        return VC_PARSE_ERROR;
    }
    subject_id_cJSON = cJSON_GetObjectItemCaseSensitive(subject_cJSON, "id");
    if(cJSON_IsString(subject_id_cJSON) && subject_id_cJSON->valuestring != NULL)
    {
        vc->credentialSubject.id.len = strlen(subject_id_cJSON->valuestring);
        vc->credentialSubject.id.p = (unsigned char *)strdup(subject_id_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    //proof
    const cJSON *proof_cJSON = NULL;

    const cJSON *proof_type_cJSON = NULL;
    const cJSON *proof_created_cJSON = NULL;
    const cJSON *proof_purpose_cJSON = NULL;
    const cJSON *proof_vmethod_cJSON = NULL;
    const cJSON *proof_signature_cJSON = NULL;

    proof_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "proof");
    if (proof_cJSON == NULL || !cJSON_IsObject(proof_cJSON))
    {
        return VC_PARSE_ERROR;
    }
    
    proof_type_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "type");
    if(cJSON_IsString(proof_type_cJSON) && proof_created_cJSON->valuestring != NULL)
    {
        vc->proof.type.len = strlen(proof_type_cJSON->valuestring);
        vc->proof.type.p = (unsigned char *)strdup(proof_type_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    proof_created_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "created");
    if(cJSON_IsString(proof_created_cJSON) && proof_created_cJSON->valuestring != NULL)
    {
        vc->proof.created.len = strlen(proof_created_cJSON->valuestring);
        vc->proof.created.p = (unsigned char *)strdup(proof_created_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    proof_purpose_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofPurpose");
    if(cJSON_IsString(proof_purpose_cJSON) && proof_purpose_cJSON->valuestring != NULL)
    {
        vc->proof.purpose.len = strlen(proof_purpose_cJSON->valuestring);
        vc->proof.purpose.p = (unsigned char *)strdup(proof_purpose_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    proof_vmethod_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "verificationMethod");
    if(cJSON_IsString(proof_vmethod_cJSON) && proof_vmethod_cJSON->valuestring != NULL)
    {
        vc->proof.verificationMethod.len = strlen(proof_vmethod_cJSON->valuestring);
        vc->proof.verificationMethod.p = (unsigned char *)strdup(proof_vmethod_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    proof_signature_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofValue");
    if(cJSON_IsString(proof_signature_cJSON) && proof_signature_cJSON->valuestring != NULL)
    {
        vc->proof.signature.len = strlen(proof_signature_cJSON->valuestring);
        vc->proof.signature.p = (unsigned char *)strdup(proof_signature_cJSON->valuestring);
    }
     else
    {
        return VC_PARSE_ERROR;
    }

    cJSON_Delete(vc_json);

    return VC_PARSE_OK;

    return 1;
}