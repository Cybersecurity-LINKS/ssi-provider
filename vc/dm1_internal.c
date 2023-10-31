/*
 * Copyright 2023 Fondazione Links.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

#include "dm1_internal.h"
#include <openssl/rsa.h>

static int get_key_type(EVP_PKEY *key)
{
    int ret = 0;
    ret = EVP_PKEY_get_id(key);
    
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
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t siglen = 0;
    unsigned char *sig = NULL;

    /* compute signature following OpenSSL procedure */
    mctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL) <= 0)
        return 0;

    if (key_type == RsaVerificationKey2023)
    {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 
        || EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
            return 0;
    }

    if (EVP_DigestSign(mctx, NULL, &siglen, (const unsigned char*)tbs, strlen(tbs)) <= 0)
        return 0;

    sig = OPENSSL_malloc(siglen);
    if (sig == NULL || EVP_DigestSign(mctx, sig, &siglen, (const unsigned char*)tbs, strlen(tbs)) <= 0)
        return 0;

    /* ENCODE signature BASE 64  with OpenSSL EVP_EncodeBlock() utility */
    size_t b64_sig_size = (((siglen + 2) / 3) * 4) + 1;
    *b64_sig = (char *)OPENSSL_malloc(b64_sig_size);
    if (*b64_sig == NULL)
        goto fail;
    if(!EVP_EncodeBlock((unsigned char *)*b64_sig, sig, siglen))
        goto fail;
    OPENSSL_free(sig);
    return 1;

fail:
    OPENSSL_free(sig);
    return 0;
}

static int verify_sig(char *md_name, EVP_PKEY *pkey, int key_type, char *tbs, char *b64_sig)
{
    EVP_MD_CTX *mctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t sig_size = 0;
    unsigned char *sig;

    /* DECODE BASE 64 signature with OpenSSL EVP_DecodeBlock() utility */
    switch(key_type)
    {
    case RsaVerificationKey2023:
		sig_size = 256;
		break;
	case EcdsaSecp256r1VerificationKey2023: ;
        size_t b64_len = strlen(b64_sig);
		if(b64_sig[b64_len-2] == '='){
			sig_size = 70;
		}
		else if(b64_sig[b64_len-1] == '='){
			sig_size = 71;
		}
		else
			sig_size = 72;
		break;
	case Ed25519VerificationKey2023:
		sig_size = 64;
		break;
	default:
		printf("Unrecognised key type\n");
		return 0;
    }
	
    sig = (unsigned char *)OPENSSL_malloc(sig_size);
    if (sig == NULL)
        return 0;
    
    if (!EVP_DecodeBlock(sig, (unsigned char *)b64_sig, strlen(b64_sig)))
        goto fail;

    /* verify signature following standard OpenSSL procedure */
    mctx = EVP_MD_CTX_new();
    if (EVP_DigestVerifyInit_ex(mctx, &pctx, md_name, NULL, NULL, pkey, NULL) <= 0)
        goto fail;

    if (key_type == RsaVerificationKey2023) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0
				|| EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx,
				RSA_PSS_SALTLEN_DIGEST) <= 0)
                goto fail;
    }

	if (EVP_DigestVerify(mctx, sig, sig_size, (const unsigned char *)tbs, strlen(tbs)) <= 0)
		goto fail;

    OPENSSL_free(sig);
    return 1;

fail:
    OPENSSL_free(sig);
    return 0;
}

int dm1_cjson_parse(VC_CTX *ctx, char *vc_stream)
{

    cJSON *vc_json = cJSON_Parse((const char *)vc_stream);
    if (vc_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }

        goto fail;
    }

    // atContext
    const cJSON *atContext = NULL;
    atContext = cJSON_GetObjectItemCaseSensitive(vc_json, "@context");

    if (cJSON_IsString(atContext) && atContext->valuestring != NULL)
        ctx->atContext = OPENSSL_strdup(atContext->valuestring);
    else
        goto fail;

    // id
    const cJSON *id_cJSON = NULL;
    id_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "id");
    if (cJSON_IsString(id_cJSON) && id_cJSON->valuestring != NULL)
        ctx->id = OPENSSL_strdup(id_cJSON->valuestring);
    else
        goto fail;

    // type
    const cJSON *type_cJSON = NULL;
    type_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL)
        ctx->type = OPENSSL_strdup(type_cJSON->valuestring);
    else
        goto fail;

    // issuer
    const cJSON *issuer_cJSON = NULL;
    issuer_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "issuer");
    if (cJSON_IsString(issuer_cJSON) && issuer_cJSON->valuestring != NULL)
        ctx->issuer = OPENSSL_strdup(issuer_cJSON->valuestring);
    else
        goto fail;

    // issuance date
    const cJSON *issDate_cJSON = NULL;
    issDate_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "issuanceDate");
    if (cJSON_IsString(issDate_cJSON) && issDate_cJSON->valuestring != NULL)
        ctx->issuanceDate = OPENSSL_strdup(issDate_cJSON->valuestring);
    else
        goto fail;

    // expiration date
    const cJSON *expDate_cJSON = NULL;
    expDate_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "expirationDate");
    if (cJSON_IsString(expDate_cJSON) && expDate_cJSON->valuestring != NULL)
        ctx->expirationDate = OPENSSL_strdup(expDate_cJSON->valuestring);
    else
        goto fail;

    // credential subject
    const cJSON *subject_cJSON = NULL;
    const cJSON *subject_id_cJSON = NULL;

    subject_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "credentialSubject");
    if (subject_cJSON == NULL || !cJSON_IsObject(subject_cJSON))
        goto fail;

    subject_id_cJSON = cJSON_GetObjectItemCaseSensitive(subject_cJSON, "id");
    if (cJSON_IsString(subject_id_cJSON) && subject_id_cJSON->valuestring != NULL)
        ctx->credentialSubject.id = OPENSSL_strdup(subject_id_cJSON->valuestring);
    else
        goto fail;

    // proof
    const cJSON *proof_cJSON = NULL;

    const cJSON *proof_type_cJSON = NULL;
    const cJSON *proof_created_cJSON = NULL;
    const cJSON *proof_purpose_cJSON = NULL;
    const cJSON *proof_vmethod_cJSON = NULL;
    const cJSON *proof_value_cJSON = NULL;

    proof_cJSON = cJSON_GetObjectItemCaseSensitive(vc_json, "proof");
    if (proof_cJSON == NULL || !cJSON_IsObject(proof_cJSON))
        goto fail;

    proof_type_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "type");
    if (cJSON_IsString(proof_type_cJSON) && proof_type_cJSON->valuestring != NULL)
        ctx->proof.type = OPENSSL_strdup(proof_type_cJSON->valuestring);
    else
        goto fail;

    proof_created_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "created");
    if (cJSON_IsString(proof_created_cJSON) && proof_created_cJSON->valuestring != NULL)
        ctx->proof.created = OPENSSL_strdup(proof_created_cJSON->valuestring);
    else
        goto fail;

    proof_purpose_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofPurpose");
    if (cJSON_IsString(proof_purpose_cJSON) && proof_purpose_cJSON->valuestring != NULL)
        ctx->proof.purpose = OPENSSL_strdup(proof_purpose_cJSON->valuestring);
    else
        goto fail;
    

    proof_vmethod_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "verificationMethod");
    if (cJSON_IsString(proof_vmethod_cJSON) && proof_vmethod_cJSON->valuestring != NULL)
        ctx->proof.verificationMethod = OPENSSL_strdup(proof_vmethod_cJSON->valuestring);
    else
        goto fail;

    proof_value_cJSON = cJSON_GetObjectItemCaseSensitive(proof_cJSON, "proofValue");
    if (cJSON_IsString(proof_value_cJSON) && proof_value_cJSON->valuestring != NULL)
        ctx->proof.value = OPENSSL_strdup(proof_value_cJSON->valuestring);
    else
        goto fail;

    cJSON_Delete(vc_json);
    return 1;

fail:
    cJSON_Delete(vc_json);
    return 0;
}

/* fill the metadata and claim section of the VC */
int dm1_fill_metadata_claim(cJSON *vc, VC_CTX *ctx)
{

    //@context
    if (cJSON_AddStringToObject(vc, "@context", ctx->atContext) == NULL)
    {
        goto fail;
    }

    // id
    if (cJSON_AddStringToObject(vc, "id", ctx->id) == NULL)
    {
        goto fail;
    }

    // type
    if (cJSON_AddStringToObject(vc, "type", ctx->type) == NULL)
    {
        goto fail;
    }

    // issuer
    if (cJSON_AddStringToObject(vc, "issuer", ctx->issuer) == NULL)
    {
        goto fail;
    }

    // issuanceDate
    if (cJSON_AddStringToObject(vc, "issuanceDate", ctx->issuanceDate) == NULL)
    {
        goto fail;
    }

    // expirationDate
    if (cJSON_AddStringToObject(vc, "expirationDate", ctx->expirationDate) == NULL)
    {
        goto fail;
    }


    // credential subject
    cJSON *cSubject = cJSON_CreateObject();
    if (cSubject == NULL)
    {
        goto fail;
    }

    cJSON_AddStringToObject(cSubject, "id", ctx->credentialSubject.id);
    cJSON_AddItemToObject(vc, "credentialSubject", cSubject);

    return 1;

fail:
    return 0;
}

/* fill the proof section of the VC*/
int dm1_fill_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
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

        key_type = get_key_type(pkey);
        // type field and selects the digest to compute the signature
        switch (key_type)
        {
        case RsaVerificationKey2023:
            ctx->proof.type = OPENSSL_strdup("RsaVerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case EcdsaSecp256r1VerificationKey2023:
            ctx->proof.type = OPENSSL_strdup("EcdsaSecp256r1VerificationKey2023");
            md_name = (char *)malloc(10);
            strcpy(md_name, "SHA256");
            break;
        case Ed25519VerificationKey2023:
            ctx->proof.type = OPENSSL_strdup("Ed25519VerificationKey2023");
            break;
        default:
            printf("Unrecognised key type\n");
            goto fail;
        }

        if (!compute_sig(md_name, pkey, key_type, tbs, &ctx->proof.value)){
            free(md_name);
            goto fail;
        }
        
        free(md_name);
    }

    // type
    cJSON_AddStringToObject(proof, "type", ctx->proof.type);

    // created
    if (ctx->proof.created == NULL)
    {
        ctx->proof.created = (char *)OPENSSL_zalloc(100);
        time_t now = time(0);
        strftime(ctx->proof.created, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    }
    cJSON_AddStringToObject(proof, "created", ctx->proof.created);

    // purpose
    if (ctx->proof.purpose == NULL)
    {
        ctx->proof.purpose = OPENSSL_strdup(VC_PURPOSE);
    }
    cJSON_AddStringToObject(proof, "proofPurpose", ctx->proof.purpose);

    // verification method
    cJSON_AddStringToObject(proof, "verificationMethod", ctx->proof.verificationMethod);

    // value
    cJSON_AddStringToObject(proof, "proofValue", ctx->proof.value);

    cJSON_AddItemToObject(vc, "proof", proof);

    return 1;

fail:
    cJSON_Delete(proof);
    return 0;
}

/* check the VC structure is valid */
int dm1_validate(VC_CTX *ctx)
{
    time_t now = time(0);
    char curr_time[50];
    strftime(curr_time, 50, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* the issuance date MUST be less then current time */
    if (ctx->issuanceDate == NULL || strcmp(ctx->issuanceDate, curr_time) > 0)
        return 0;

    /* the expiration date MUST be greater then current time */ 
    if (ctx->expirationDate != NULL && strcmp(ctx->expirationDate, curr_time) < 0)
        return 0;

    /* @context MUST be equal to "https://www.w3.org/2018/credentials/v1" */
    if (ctx->atContext == NULL || strcmp(ctx->atContext, CONTEXT_VC_V1) != 0)
        return 0;

    /* credentail type MUST be "VerifiableCredential" */
    if (ctx->type == NULL || strcmp(ctx->type, VC_TYPE) != 0)
        return 0;

    /* credential subjcet MUST be not null*/
    if (ctx->credentialSubject.id == NULL || strlen(ctx->credentialSubject.id) == 0)
        return 0;
    
    return 1;
}

/* check the VC proof is valid */
int dm1_verify_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey)
{
    char *md_name = NULL;
    int key_type;

    // get the data to be signed
    char *tbs = cJSON_Print(vc);

    // get key type from openssl
    key_type = get_key_type(pkey);

    // type field and selects the digest to compute the signature
    switch(key_type)
    {
    case RsaVerificationKey2023:
        ctx->proof.type = OPENSSL_strdup("RsaVerificationKey2023");
        md_name = (char *)malloc(10);
        strcpy(md_name, "SHA256");
        break;
    case EcdsaSecp256r1VerificationKey2023:
        ctx->proof.type = OPENSSL_strdup("EcdsaSecp256r1VerificationKey2023");
        md_name = (char *)malloc(10);
        strcpy(md_name, "SHA256");
        break;
    case Ed25519VerificationKey2023:
        ctx->proof.type = OPENSSL_strdup("Ed25519VerificationKey2023");
        break;
    default:
        printf("Unrecognised key type\n");
        return 0;
    }

    if (!verify_sig(md_name, pkey, key_type, tbs, ctx->proof.value)){
        free(md_name);
        return 0;
    }

    free(md_name);
    return 1;
}
