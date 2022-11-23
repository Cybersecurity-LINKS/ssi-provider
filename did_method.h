#ifndef DID_METHOD_H
#define DID_METHOD_H

#include "WAM.h"
#include "time.h"
#include <string.h>

#define DID_PREFIX_LEN          8+1
#define DID_PREFIX              "did:ott:"

//here we define the contexts
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

typedef struct ott_buf {
    unsigned char *p;
    size_t len;
} ott_buf;

typedef struct method {
    ott_buf id;
    int type;
    ott_buf controller;
    ott_buf pk_pem;
    int method_type;
    struct method *next;
} method;

typedef struct context {
    ott_buf val;
    struct context *next;
} context;

typedef struct did_document {
    context atContext;
    ott_buf id;
    ott_buf created;
    method authMethod;
    method assertionMethod;
} did_document;


typedef enum {
    //da inserirne anche altre se servono
    Ed25519VerificationKey2018,             // 0
    RsaVerificationKey2018,                 // 1
    EcdsaSecp256k1VerificationKey2019,      // 2
} KEY_TYPES;

typedef enum {
    //da aggiungerne altri se si vuole
    AuthenticationMethod,
    AssertionMethod
} METHOD_TYPES;

char *key_types_to_string(KEY_TYPES type);

int find_key_type(char *key_type);

void did_document_init(did_document *did_doc);

void did_document_free(did_document *did_doc);

int did_ott_create(method *methods, char *did_new);

int did_ott_resolve(did_document *didDocument, char *did);

int did_ott_update(method *methods,char * did);

int did_ott_revoke(char *did);


//int update2(method *methods, int size,  data *dt);
#endif //DID_METHOD_H


