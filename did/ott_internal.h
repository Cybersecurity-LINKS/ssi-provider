/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OTT_UTIL_H
#define OTT_UTIL_H

#include "ott_primitives.h"
#include "time.h"
#include <string.h>

#define DID_PREFIX_LEN          8+1
#define DID_PREFIX              "did:ott:"

#define CONTEXT_DID_V1          "https://www.w3.org/ns/did/v1"

#define DID_LEN                 (INDEX_HEX_SIZE + DID_PREFIX_LEN)
#define REVOKE_MSG_SIZE         1
#define KEY_ID_PREFIX           "#keys-"
#define KEY_ID_PREFIX_LEN       6
#define KEY_INDEX_LEN           2 //max 99 keys
#define MAX_KEY_ID_LEN          (DID_LEN + KEY_ID_PREFIX_LEN + KEY_INDEX_LEN)

#define DID_CREATE_ERROR        -10
#define DID_RESOLVE_NOT_FOUND   -15
#define DID_RESOLVE_ERROR       -20
#define ALLOC_FAILED            -30
#define NO_VALID_KEY_TYPE       -40
#define DID_REVOKE_ERROR        -50
#define DID_UPDATE_ERROR        -60
#define DID_RESOLVE_REVOKED     1
#define DID_RESOLVE_OK          0
#define DID_CREATE_OK           0
#define DID_REVOKE_OK           0
#define DID_UPDATE_OK           0

#define MAX_DID_FIELD            1000

typedef struct method {
	char *id;
	char *type;
	char *controller;
	char *pkey;
} method;

typedef struct did_document {
    char *atContext;
    char *id;
    char *created;  
    method authentication;
    method assertion; 
} DID_CTX;

typedef enum {
    RsaVerificationKey2023,             //0
    EcdsaSecp256r1VerificationKey2023,  //1
    Ed25519VerificationKey2023,         //2
} KEY_TYPES;

typedef enum {
    AuthenticationMethod,
    AssertionMethod
} METHOD_TYPES;

int ott_create_internal(DID_CTX *ctx);

int ott_resolve_internal(DID_CTX *ctx, char *did);

int ott_update_internal(DID_CTX *ctx);

int ott_revoke_internal(DID_CTX *ctx);

#endif


