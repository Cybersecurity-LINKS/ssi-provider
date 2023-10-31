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

#include <string.h>
#include "../cJSON.h"
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

int dm1_cjson_parse(VC_CTX *ctx, char *vc_stream);

int dm1_fill_metadata_claim(cJSON *vc, VC_CTX *ctx);

int dm1_fill_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey);

int dm1_validate(VC_CTX *ctx);

int dm1_verify_proof(cJSON *vc, VC_CTX *ctx, EVP_PKEY *pkey);