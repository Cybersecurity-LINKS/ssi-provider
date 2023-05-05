#include <string.h>
#include "cJSON.h"

#define CONTEXT_VC_V1          "https://www.w3.org/2018/credentials/v1"

#define VC_PARSE_OK             1
#define VC_PARSE_ERROR          -10

typedef struct vc_buf {
    unsigned char *p;
    size_t len;
} vc_buf;

typedef struct c_subj {
    vc_buf id;
} c_subj;

typedef struct proof {
    vc_buf type;
    vc_buf created;
    vc_buf purpose;
    vc_buf verificationMethod;
    vc_buf signature;
} proof;

typedef struct verifiable_credential {
    vc_buf atContext;
    vc_buf id;
    vc_buf type;
    vc_buf issuer;
    vc_buf issuanceDate;
    c_subj credentialSubject; 
    proof proof;
} verifiable_credential;

typedef enum {
    //da inserirne anche altre se servono
    RsaVerificationKey2023,             //0
    EcdsaSecp256r1VerificationKey2023,  //1
    Ed25519VerificationKey2023,         //2
} KEY_TYPES;

void vc_init(verifiable_credential *vc);

void vc_free(verifiable_credential *vc);

int compute_sig(char *md_name, EVP_PKEY *pkey, char *tbs, char* sig);

int vc_cjson_parse(verifiable_credential *vc, unsigned char *vc_stream);

int vc_cjson_print(verifiable_credential *vc, unsigned char *vc_stream);