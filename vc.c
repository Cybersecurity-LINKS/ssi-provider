#include "vc_internal.h"
#include <time.h>
#include <sys/time.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

static OSSL_FUNC_vc_create_fn vc_create;
static OSSL_FUNC_vc_verify_fn vc_verify;
static OSSL_FUNC_vc_serialize_fn vc_serialize;
static OSSL_FUNC_vc_deserialize_fn vc_deserialize;

static char *vc_create(char *id, char *issuer, char *subject, char *v_method, EVP_PKEY *pkey, int key_type) 
{   
    cJSON *proof = NULL;
    cJSON *cSubject = NULL;
    char time_buf[100], time_buf2[100];
    char *sig_type = NULL, *md_name = NULL;
    char *sig = NULL;

    cJSON *vc = cJSON_CreateObject();
    if (vc == NULL)
    {
        return NULL;
    }
    
    //@context
    if (cJSON_AddStringToObject(vc, "@context", CONTEXT_VC_V1) == NULL)
    {
        goto fail;
    }

    //id
    if (cJSON_AddStringToObject(vc, "id", id) == NULL)
    {
        goto fail;
    }

    //type
    if (cJSON_AddStringToObject(vc, "type", "VerifiableCredential") == NULL)
    {
        goto fail;
    }

    //issuer
    if (cJSON_AddStringToObject(vc, "issuer", issuer) == NULL)
    {
        goto fail;
    }

    //issuanceDate
    time_t now = time(0);
    strftime(time_buf, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    if (cJSON_AddStringToObject(vc, "issuanceDate", time_buf) == NULL)
    {
        goto fail;
    }

    //credential subject
    cSubject = cJSON_CreateObject();
    if(cSubject == NULL)
    {
        goto fail;
    }

    cJSON_AddStringToObject(cSubject, "id", subject);

    char *tbs = cJSON_Print(vc);

    //proof
    proof = cJSON_CreateObject();
    if (proof == NULL){
        goto fail;
    }

    switch (key_type)
    {
    case RsaVerificationKey2023:
        cJSON_AddStringToObject(proof, "type", "RsaVerificationKey2023");
        md_name = (char *)malloc(10);
        strcpy(md_name, "sha256");
        break;
    case EcdsaSecp256r1VerificationKey2023:
        cJSON_AddStringToObject(proof, "type", "EcdsaSecp256r1VerificationKey2023");
        md_name = (char *)malloc(10);
        strcpy(md_name, "sha256");
        break;
    case Ed25519VerificationKey2023:
        cJSON_AddStringToObject(proof, "type", "Ed25519VerificationKey2023");
        break;
    default:
        printf("Unrecognised key type\n");
        goto fail;
    }

    time_t now = time(0);
    strftime(time_buf2, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now)); 
    cJSON_AddStringToObject(proof, "created", time_buf2);
    cJSON_AddStringToObject(proof, "proofPurpose", "assertionMethod");
    cJSON_AddStringToObject(proof, "verficationMethod", v_method);

    if(compute_sig(md_name, pkey, tbs, sig) == -1)
        goto fail;

    cJSON_AddStringToObject(proof, "proofValue", sig);

    char *verifiable_credential = cJSON_Print(vc);
    cJSON_Delete(vc);
    return verifiable_credential;
    
fail:
    cJSON_Delete(vc);
    return NULL;
}

int vc_deserialize (unsigned char *vc_stream, VC *vc){

    int ret;
    verifiable_credential *vc_ = NULL;
    vc_ = calloc(1, sizeof(verifiable_credential));
    if (vc_ == NULL) {
        return DID_INTERNAL_ERROR;
    }
    vc_init(vc_);

    ret = vc_cjson_parse(vc_, vc_stream);
    if(ret == VC_PARSE_ERROR)
        /* return error */

    vc_free(vc);
    return 1;  
}

int vc_serialize (unsigned char *vc_stream, VC *vc){

    return 1;
}



const OSSL_DISPATCH ssiprovider_vc_functions[] = {
    {OSSL_FUNC_VC_CREATE, (void(*)(void)) vc_create},
    {OSSL_FUNC_VC_VERIFY, (void(*)(void)) vc_verify},
    {OSSL_FUNC_VC_SERIALIZE, (void(*)(void)) vc_serialize},
    {OSSL_FUNC_VC_DESERIALIZE, (void(*)(void))vc_deserialize},
    { 0, NULL }
};