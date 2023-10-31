/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "ott_internal.h"
#include <time.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAINNET {.hostname = "192.168.94.191\0",\
                .port = 14265,\
                .tls = true}

#define MAINNET_PUBLIC {.hostname = "chrysalis-nodes.iota.org\0",\
                .port = 443,\
                .tls = true}

#define TESTNET {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",\
                .port = 80,\
                .tls = false}
                
#define PRIVATE_TANGLE {.hostname = "chrysalis.linksfoundation.com",\
                .port = 14265,\
                .tls = false}

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

static char *key_types_to_string(KEY_TYPES type)
{
    switch (type)
    {
    case RsaVerificationKey2023:
        return "RsaVerificationKey2023";
    case EcdsaSecp256r1VerificationKey2023:
        return "EcdsaSecp256r1VerificationKey2023";
    case Ed25519VerificationKey2023:
        return "Ed25519VerificationKey2023";
    default:
        return NULL;
    }
}

static char *did_doc_fill(DID_CTX *ctx)
{
    cJSON *auth_method = NULL;
    cJSON *assrtn_method = NULL;

    cJSON *did_doc = cJSON_CreateObject();
    if (did_doc == NULL)
    {
        return NULL;
    }
    //@context
    if (cJSON_AddStringToObject(did_doc, "@context", ctx->atContext) == NULL)
    {
        goto fail;
    }

    // id
    if (cJSON_AddStringToObject(did_doc, "id", ctx->id) == NULL)
    {
        goto fail;
    }
    
    if (cJSON_AddStringToObject(did_doc, "created", ctx->created) == NULL)
    {
        goto fail;
    }
    
    // AuthenticationMethod
    auth_method = cJSON_CreateObject();
    if (auth_method == NULL)
    {
        goto fail;
    }
    
    cJSON_AddStringToObject(auth_method, "id", ctx->authentication.id);
    cJSON_AddStringToObject(auth_method, "type", ctx->authentication.type);
    cJSON_AddStringToObject(auth_method, "controller", ctx->authentication.controller);
    cJSON_AddStringToObject(auth_method, "publicKeyPem", ctx->authentication.pkey);
    cJSON_AddItemToObject(did_doc, "authenticationMethod", auth_method);

    // AssertionMethod
    assrtn_method = cJSON_CreateObject();
    if (assrtn_method == NULL)
    {
        goto fail;
    }
    
    cJSON_AddStringToObject(assrtn_method, "id", ctx->assertion.id);
    cJSON_AddStringToObject(assrtn_method, "type", ctx->assertion.type);
    cJSON_AddStringToObject(assrtn_method, "controller", ctx->assertion.controller);
    cJSON_AddStringToObject(assrtn_method, "publicKeyPem", ctx->assertion.pkey);
    cJSON_AddItemToObject(did_doc, "assertionMethod", assrtn_method);

    char *did_doc_stream = cJSON_Print(did_doc);
    cJSON_Delete(did_doc);
    return did_doc_stream;

fail:
    cJSON_Delete(did_doc);
    return NULL;
}

static int save_channel(OTT_channel *ch)
{

    FILE *fp = NULL;

    /* open the file in write binary mode */
    fp = fopen("channel.txt", "wb");
    if (fp == NULL)
    {
        return -1;
    }
    /* id */ 
    fwrite(&(ch->id), sizeof(uint16_t), 1, fp);
    /* node */
    fwrite(&(ch->node->tls), sizeof(bool), 1, fp);
    fwrite(&(ch->node->port), sizeof(uint16_t), 1, fp);
    fwrite(ch->node->hostname, sizeof(char), ENDPTNAME_SIZE, fp);

    fwrite(ch->index, sizeof(uint8_t), INDEX_SIZE, fp);
    fwrite(ch->anchor, sizeof(uint8_t), INDEX_SIZE, fp);
    fwrite(ch->keys1.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fwrite(ch->keys1.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);
    fwrite(ch->keys2.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fwrite(ch->keys2.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);

    // sent_msg
    fwrite(&(ch->sent_msg), sizeof(uint16_t), 1, fp);
    // recv_msg
    fwrite(&(ch->recv_msg), sizeof(uint16_t), 1, fp);
    // sent_bytes
    fwrite(&(ch->sent_bytes), sizeof(uint16_t), 1, fp);
    // recv_bytes
    fwrite(&(ch->recv_bytes), sizeof(uint16_t), 1, fp);
    // buff_hex_data
    fwrite(ch->buff_hex_data, sizeof(uint8_t), IOTA_MAX_MSG_SIZE, fp);
    // buff_hex_index
    fwrite(ch->buff_hex_index, sizeof(uint8_t), INDEX_HEX_SIZE, fp);
    fclose(fp);
    return 0;
}

static int load_channel(OTT_channel *ch, IOTA_Endpoint *endpoint)
{
    FILE *fp = NULL;
    // open the file in write binary mode
    fp = fopen("channel.txt", "rb");
    if (fp == NULL)
    {
        return -1;
    }
    // endopint
    ch->node = endpoint;
    // id
    fread(&(ch->id), sizeof(uint16_t), 1, fp);
    // node
    fread(&(ch->node->tls), sizeof(bool), 1, fp);
    fread(&(ch->node->port), sizeof(uint16_t), 1, fp);
    fread(ch->node->hostname, sizeof(char), ENDPTNAME_SIZE, fp);
    fread(ch->index, sizeof(uint8_t), INDEX_SIZE, fp);
    fread(ch->anchor, sizeof(uint8_t), INDEX_SIZE, fp);
    fread(ch->keys1.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fread(ch->keys1.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);
    fread(ch->keys2.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fread(ch->keys2.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);
    // sent_msg
    fread(&(ch->sent_msg), sizeof(uint16_t), 1, fp);
    // recv_msg
    fread(&(ch->recv_msg), sizeof(uint16_t), 1, fp);
    // sent_bytes
    fread(&(ch->sent_bytes), sizeof(uint16_t), 1, fp);
    // recv_bytes
    fread(&(ch->recv_bytes), sizeof(uint16_t), 1, fp);
    // buff_hex_data
    fread(ch->buff_hex_data, sizeof(uint8_t), IOTA_MAX_MSG_SIZE, fp);
    // buff_hex_index
    fread(ch->buff_hex_index, sizeof(uint8_t), INDEX_HEX_SIZE, fp);
    fclose(fp);
    return 0;
}

static int sub_string(const char *input, int offset, int len, char *dest)
{
    size_t input_len = strlen(input);

    if (offset + len > input_len)
    {
        return -1;
    }

    strncpy(dest, input + offset, len);
    dest[len] = '\0';
    return 0;
}

int ott_create_internal(DID_CTX *ctx)
{
    uint8_t *index_bin;
    char index[INDEX_HEX_SIZE];
    uint8_t ret;
    char did[DID_LEN] = "";
    OTT_channel ch_send;
    BIO *authn_pubkey;
    BIO *assrtn_pubkey;
    char id_key[MAX_KEY_ID_LEN];
    char index_key[KEY_INDEX_LEN];
    char msg_id[IOTA_MESSAGE_ID_HEX_BYTES + 1];
    char did_msgid[DID_LEN + IOTA_MESSAGE_ID_HEX_BYTES + 2] = "";

    fprintf(stdout, "CREATE\n");
    
    IOTA_Endpoint testnet0tls = PRIVATE_TANGLE;

    ret = OTT_write_init_channel(&ch_send, 1, &testnet0tls);
    if (ret != OTT_OK)
    {
        return 0;
    }

    /* grab the start index that correspond to the DID */
    index_bin = ch_send.index;
    ret = bin_2_hex(index_bin, INDEX_SIZE, index, INDEX_HEX_SIZE);
    if (ret != 0)
    {
        return 0;
    }
    strncat(did, DID_PREFIX, DID_PREFIX_LEN);
    strncat(did, index, INDEX_HEX_SIZE);

    ctx->id = OPENSSL_strdup(did);

    memset(id_key, 0, MAX_KEY_ID_LEN);
    strncat(id_key, did, DID_LEN);
    strcat(id_key, KEY_ID_PREFIX);
    snprintf(index_key, KEY_INDEX_LEN, "%d", 0);
    strncat(id_key, index_key, KEY_INDEX_LEN);

    ctx->authentication.id = OPENSSL_strdup(id_key);

    authn_pubkey = BIO_new_mem_buf(ctx->authentication.pkey, -1);
    if((ret = get_key_type(PEM_read_bio_PUBKEY(authn_pubkey, NULL, NULL, NULL))) == -1){
        goto fail;
    }

    ctx->authentication.type = OPENSSL_strdup(key_types_to_string(ret));
      
    ctx->authentication.controller = OPENSSL_strdup(did);

    memset(id_key, 0, MAX_KEY_ID_LEN);
    strncat(id_key, did, DID_LEN);
    strcat(id_key, KEY_ID_PREFIX);
    snprintf(index_key, KEY_INDEX_LEN, "%d", 1);
    strncat(id_key, index_key, KEY_INDEX_LEN);

    ctx->assertion.id = OPENSSL_strdup(id_key);

    assrtn_pubkey = BIO_new_mem_buf(ctx->assertion.pkey, -1);
    if((ret = get_key_type(PEM_read_bio_PUBKEY(assrtn_pubkey, NULL, NULL, NULL))) == -1){
        goto fail;
    }

    ctx->assertion.type = OPENSSL_strdup(key_types_to_string(ret));
      
    ctx->assertion.controller = OPENSSL_strdup(did);

    char *did_doc = did_doc_fill(ctx);
    if (did_doc == NULL)
    {
        goto fail;
    }

    ret = OTT_write(&ch_send, (unsigned char *)did_doc, strlen(did_doc), msg_id, false);
    if (ret != OTT_OK)
    {
        goto fail;
    }
    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

    snprintf(did_msgid, sizeof(did_msgid), "%s:%s", ctx->id, msg_id);

    OPENSSL_free(ctx->id);
    ctx->id = NULL;
    ctx->id = OPENSSL_strdup(did_msgid);

    BIO_free(authn_pubkey);
    BIO_free(assrtn_pubkey);
    return 1;
fail:
    BIO_free(authn_pubkey);
    BIO_free(assrtn_pubkey);
    return 0;
}

int ott_resolve_internal(DID_CTX *ctx, char *did)
{
    char hex_index[INDEX_HEX_SIZE];
    char *hex_index1;
    uint8_t index[INDEX_SIZE];
    OTT_channel ch_read;
    uint8_t read_buff[DATA_SIZE];
    uint16_t expected_size = DATA_SIZE;
    uint8_t ret = 0;
    char *msg_id;
    char *token;

    IOTA_Endpoint testnet0tls = PRIVATE_TANGLE;
    
    token = strtok(did, ":");
    if(token == NULL)
        return DID_RESOLVE_ERROR;
    token = strtok(NULL, ":");
    if(token == NULL)
        return DID_RESOLVE_ERROR;
    token = strtok(NULL, ":");
    if(token == NULL)
        return DID_RESOLVE_ERROR;
    hex_index1 = token;

    msg_id = strtok(NULL, ":");
    if(msg_id == NULL)
        return DID_RESOLVE_ERROR;

    ret = OTT_read_init_channel(&ch_read, 1, msg_id, &testnet0tls);
    if (ret != 0)
        return DID_RESOLVE_ERROR;

    ret = hex_2_bin(hex_index1, INDEX_HEX_SIZE, index, INDEX_SIZE);
    if (ret != 0)
        return DID_RESOLVE_ERROR;

    set_channel_index_read(&ch_read, index);

    fprintf(stdout, "---\nDID RESOLVE ...\n");

    ret = OTT_read(&ch_read, read_buff, &expected_size);

    if (ret == OTT_REVOKE)
        return DID_RESOLVE_REVOKED;
    else if (ret != OTT_OK)
        return DID_RESOLVE_NOT_FOUND;

    /* fprintf(stdout, "OTT_read ret:");
    fprintf(stdout, "\n\t val=%d", ret);
    fprintf(stdout, "\n\t expctsize=%d \t", expected_size);
    fprintf(stdout, "\n\t msg_read=%d \t", ch_read.recv_msg);
    fprintf(stdout, "\n\t bytes_read=%d \t", ch_read.recv_bytes); */

    read_buff[ch_read.recv_bytes] = '\0';
    fprintf(stdout, "\nPeer DID document\n");
    fprintf(stdout, "%s\n", read_buff);

    // parsing
    cJSON *did_document_json = cJSON_Parse((const char *)read_buff);
    if (did_document_json == NULL)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL)
        {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }

        return DID_RESOLVE_ERROR;
        ;
    }

    // atContext
    cJSON *atContext_cJSON = NULL;
    atContext_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "@context");
    if (cJSON_IsString(atContext_cJSON) && atContext_cJSON->valuestring != NULL)
    {
        ctx->atContext = OPENSSL_strdup(atContext_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    // id
    cJSON *id_cJSON = NULL;
    id_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "id");
    if (cJSON_IsString(id_cJSON) && id_cJSON->valuestring != NULL)
    {
        ctx->id = OPENSSL_strdup(id_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    // created
    cJSON *created_cJSON = NULL;
    created_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "created");
    if (cJSON_IsString(created_cJSON) && created_cJSON->valuestring != NULL)
    {
        ctx->created = OPENSSL_strdup(created_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    // methods
    cJSON *method_cJSON = NULL;
    cJSON *id_method_cJSON = NULL;
    cJSON *type_cJSON = NULL;
    cJSON *controller_cJSON = NULL;
    cJSON *pk_cJSON = NULL;

    // AuthenticationMethod:
    method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "authenticationMethod");
    if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON))
    {
        return DID_RESOLVE_ERROR;
    }
    id_method_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "id");
    if (cJSON_IsString(id_method_cJSON) && id_method_cJSON->valuestring != NULL)
    {
        ctx->authentication.id = OPENSSL_strdup(id_method_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    type_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL)
    {
        ctx->authentication.type = OPENSSL_strdup(type_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    controller_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "controller");
    if (cJSON_IsString(controller_cJSON) && controller_cJSON->valuestring != NULL)
    {
        ctx->authentication.controller = OPENSSL_strdup(controller_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    pk_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "publicKeyPem");
    if (cJSON_IsString(pk_cJSON) && pk_cJSON->valuestring != NULL)
    {
        ctx->authentication.pkey = OPENSSL_strdup(pk_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    // AssertionMethod
    method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "assertionMethod");
    if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON))
    {
        return DID_RESOLVE_ERROR;
    }

    id_method_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "id");
    if (cJSON_IsString(id_method_cJSON) && id_method_cJSON->valuestring != NULL)
    {
        ctx->assertion.id = OPENSSL_strdup(id_method_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    type_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL)
    {
       ctx->assertion.type = OPENSSL_strdup(id_method_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    controller_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "controller");
    if (cJSON_IsString(controller_cJSON) && controller_cJSON->valuestring != NULL)
    {
        ctx->assertion.controller = OPENSSL_strdup(controller_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    pk_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "publicKeyPem");
    if (cJSON_IsString(pk_cJSON) && pk_cJSON->valuestring != NULL)
    {
        ctx->assertion.pkey = OPENSSL_strdup(pk_cJSON->valuestring);
    }
    else
    {
        return DID_RESOLVE_ERROR;
    }

    cJSON_Delete(did_document_json);

    return DID_RESOLVE_OK;
}

int ott_update_internal(DID_CTX *ctx)
{
    char newdid[DID_LEN] = "";
    uint8_t *index_bin;
    char index_hex[INDEX_HEX_SIZE];
    OTT_channel ch_rev;
    OTT_channel ch_send;
    int ret = 0;
    uint8_t write_buff[REVOKE_MSG_SIZE];
    BIO *authn_pubkey;
    BIO *assrtn_pubkey;
    char id_key[MAX_KEY_ID_LEN];
    char index_key[KEY_INDEX_LEN];
    
    fprintf(stdout, "UPDATE\n");
    
    IOTA_Endpoint testnet0tls = PRIVATE_TANGLE;

    load_channel(&ch_rev, &testnet0tls);
    memset(write_buff, 0, REVOKE_MSG_SIZE);
    ret = OTT_write(&ch_rev, write_buff, REVOKE_MSG_SIZE, NULL, true);
    if (ret != OTT_OK)
    {
        goto fail;
    }

    ret = OTT_write_init_channel(&ch_send, 1, &testnet0tls);
    if (ret != OTT_OK)
    {
        goto fail;
    }

    index_bin = ch_send.index;
    ret = bin_2_hex(index_bin, INDEX_SIZE, index_hex, INDEX_HEX_SIZE);
    if (ret != 0)
    {
        goto fail;
    }

    strncat(newdid, DID_PREFIX, DID_PREFIX_LEN);
    strncat(newdid, index_hex, INDEX_HEX_SIZE);
    
    ctx->id = OPENSSL_strdup(newdid);

    memset(id_key, 0, MAX_KEY_ID_LEN);
    strncat(id_key, newdid, DID_LEN);
    strcat(id_key, KEY_ID_PREFIX);
    snprintf(index_key, KEY_INDEX_LEN, "%d", 0);
    strncat(id_key, index_key, KEY_INDEX_LEN);

    ctx->authentication.id = OPENSSL_strdup(id_key);

    authn_pubkey = BIO_new_mem_buf(ctx->authentication.pkey, -1);
    if((ret = get_key_type(PEM_read_bio_PUBKEY(authn_pubkey, NULL, NULL, NULL))) == -1){
        goto fail;
    }

    ctx->authentication.type = OPENSSL_strdup(key_types_to_string(ret));
      
    ctx->authentication.controller = OPENSSL_strdup(newdid);

    memset(id_key, 0, MAX_KEY_ID_LEN);
    strncat(id_key, newdid, DID_LEN);
    strcat(id_key, KEY_ID_PREFIX);
    snprintf(index_key, KEY_INDEX_LEN, "%d", 1);
    strncat(id_key, index_key, KEY_INDEX_LEN);

    ctx->assertion.id = OPENSSL_strdup(id_key);

    assrtn_pubkey = BIO_new_mem_buf(ctx->assertion.pkey, -1);
    if((ret = get_key_type(PEM_read_bio_PUBKEY(assrtn_pubkey, NULL, NULL, NULL))) == -1){
        goto fail;
    }

    ctx->assertion.type = OPENSSL_strdup(key_types_to_string(ret));
      
    ctx->assertion.controller = OPENSSL_strdup(newdid);

    // create the updated did document
    char *did_doc = did_doc_fill(ctx);
    if (did_doc == NULL)
    {
        goto fail;
    }

    ret = OTT_write(&ch_send, (unsigned char *)did_doc, strlen(did_doc), NULL, false);
    if (ret != OTT_OK)
    {
        goto fail;
    }
    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

    save_channel(&ch_send);

    BIO_free(authn_pubkey);
    BIO_free(assrtn_pubkey);
    return DID_UPDATE_OK;
fail:
    BIO_free(authn_pubkey);
    BIO_free(assrtn_pubkey);
    return DID_UPDATE_ERROR;
}

int ott_revoke_internal(DID_CTX *ctx)
{
    OTT_channel ch_send;
    uint8_t write_buff[REVOKE_MSG_SIZE];
    uint8_t ret = 0;
    uint8_t revoke_index[INDEX_SIZE];
    fprintf(stdout, "REVOKE\n");

    memset(revoke_index, 0, INDEX_SIZE);
    memset(write_buff, 0, REVOKE_MSG_SIZE);

    IOTA_Endpoint testnet0tls = PRIVATE_TANGLE;

    load_channel(&ch_send, &testnet0tls);

    ret = OTT_write(&ch_send, write_buff, REVOKE_MSG_SIZE, NULL, true);
    if (ret != OTT_OK)
    {
        goto fail;
    }

    return 1;

fail:
    return 0;
}


