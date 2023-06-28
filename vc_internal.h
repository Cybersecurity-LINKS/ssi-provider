#include <string.h>
#include "cJSON.h"
#include <openssl/evp.h>

#define CONTEXT_VC_V1          "https://www.w3.org/2018/credentials/v1"
#define VC_TYPE                "VerifiableCredential"
#define VC_PURPOSE             "assertionMethod"

#define MAX_VC_FIELD            1000

typedef struct c_subj {
    char* id;
} c_subj;

typedef struct proof {
    char* type;
    char* created;
    char* purpose;
    char* verificationMethod;
    char* value;
} proof;

typedef struct verifiable_credential {
    char* atContext;
    char* id;
    char* type;
    char* issuer;
    char* issuanceDate;
    char* expirationDate;
    c_subj credentialSubject; 
    proof proof;
} VC_CTX;

typedef enum {
    RsaVerificationKey2023,             //0
    EcdsaSecp256r1VerificationKey2023,  //1
    Ed25519VerificationKey2023,         //2
} KEY_TYPES;

int vc_cjson_parse(VC_CTX *ctx, unsigned char *vc_stream);

int vc_fill_metadata_claim(cJSON *vc, VC_CTX *ctx);

int vc_fill_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey);

int vc_validate(VC_CTX *ctx);

int vc_verify_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey);