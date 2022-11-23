#include "did_method.h"

#define KEY \
"-----BEGIN PUBLIC KEY-----\nMIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8pta2RewzPpJ1I/Ir\nxycs1p+gxqVqV32mybVQ011WrUfc4J4ubnRFFfjnlMmXAIWhZANiAAS4PSfpIErh\nA22hFrBh30xz8Tcc2xw0zB7VTVZhIR/YmoenTnOJnLTMGP8LGXWJNz1e7ffq7KR7\nMMDhtk4Wc1I4NGgXuYx54TNt8g15Bn6WJbHt4TZMfeTlod/INe2QgOg=" \
"-----END PUBLIC KEY-----\n"

#define KEY2 \
"PUBLIC KEY 2"

#define KEY3 \
"KEY 3"


#define KEY4 \
"KEY 4"
void did_document_init(did_document *did_doc) {
    memset(did_doc, 0, sizeof(did_document));
}

void did_document_free(did_document *did_doc) {
    context *cur_context;
    context *prv_context;
    method *cur_method;
    method *prv_method;

    if(did_doc == NULL)
        return;

    free(did_doc->atContext.val.p);
    cur_context = did_doc->atContext.next;
    while (cur_context != NULL){
        prv_context = cur_context;
        cur_context = cur_context->next;
        free( prv_context );
    }

    free(did_doc->id.p);
    free(did_doc->created.p);

    free(did_doc->method.id.p);
    free(did_doc->method.controller.p);
    free(did_doc->method.pk_pem.p);

    cur_method = did_doc->method.next;
    while(cur_method != NULL){
        prv_method = cur_method;
        cur_method = cur_method->next;
        free(prv_method->id.p);
        free(prv_method->controller.p);
        free(prv_method->pk_pem.p);
        free(prv_method);
    }

}

char *key_types_to_string(KEY_TYPES type) {
    switch (type) {
        case Ed25519VerificationKey2018:
            return "Ed25519VerificationKey2018";
        case RsaVerificationKey2018:
            return "RsaVerificationKey2018";
        default:
            return NULL;
    }
}

int find_key_type(char *key_type) {
    int type = 0, exit = 0;
    while (!exit) {
        switch (type) {
            case Ed25519VerificationKey2018:
                if (strcmp(key_type, key_types_to_string(Ed25519VerificationKey2018)) == 0) {
                    return Ed25519VerificationKey2018;
                }
                type++;
                break;
            case RsaVerificationKey2018:
                if (strcmp(key_type, key_types_to_string(RsaVerificationKey2018)) == 0) {
                    return RsaVerificationKey2018;
                }
                type++;
                break;
            default:
                exit = 1;
                break;
        }
    }
    return NO_VALID_KEY_TYPE;
}

char * create_did_document(char * did, ott_buf * Abuff, int Atype, ott_buf * Sbuff, int Stype){
    cJSON *method = NULL;
    cJSON *atContext_cJson = NULL;
    char time_buf[100];
    char id_key[MAX_KEY_ID_LEN];
    char index_key[KEY_INDEX_LEN];

    cJSON *did_document = cJSON_CreateObject();
    if(did_document == NULL){
        return NULL;
    }
    //@context
    atContext_cJson = cJSON_AddArrayToObject(did_document, "@context");
    if (atContext_cJson == NULL) {
        goto fail;
    }
    cJSON *ctx = cJSON_CreateString(CONTEXT_DID_V1);
    if(ctx == NULL){
        goto fail;
    }
    cJSON_AddItemToArray(atContext_cJson, ctx);

    //id
    if (cJSON_AddStringToObject(did_document, "id", did) == NULL) {
        goto fail;
    }
    time_t now = time(0);
    strftime(time_buf, 100, " %Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    if (cJSON_AddStringToObject(did_document, "created", time_buf) == NULL) {
        goto fail;
    }
    //AuthenticationMethod
    method = cJSON_CreateObject();
    if(method == NULL){
        goto fail;
    }
    memset(id_key, 0, MAX_KEY_ID_LEN);
    strncat(id_key, did, DID_LEN);
    strcat(id_key, KEY_ID_PREFIX);
    //da rivedere i = 0
    snprintf(index_key, KEY_INDEX_LEN, "%d", 0);
    strncat(id_key, index_key, KEY_INDEX_LEN);
    cJSON_AddStringToObject(method, "id", id_key);

    switch (Atype) {
        case Ed25519VerificationKey2018:
            cJSON_AddStringToObject(method, "type", "Ed25519VerificationKey2018");
            break;
        case RsaVerificationKey2018:
            cJSON_AddStringToObject(method, "type", "RsaVerificationKey2018");
            break;
        default:
            printf("Unrecognised key type");
            goto fail;
    }

    cJSON_AddStringToObject(method, "controller", did);
    cJSON_AddStringToObject(method, "publicKeyPem", (const char *) Abuff->p);
    cJSON_AddItemToObject(did_document, "authenticationMethod", method);

    if(Sbuff != NULL){
        //opzionale?
        //assertionMethod
        method = cJSON_CreateObject();
        if(method == NULL){
            goto fail;
        }
        memset(id_key, 0, MAX_KEY_ID_LEN);
        strncat(id_key, did, DID_LEN);
        strcat(id_key, KEY_ID_PREFIX);
        //da rivedere i = 1
        snprintf(index_key, KEY_INDEX_LEN, "%d", 1);
        strncat(id_key, index_key, KEY_INDEX_LEN);
        cJSON_AddStringToObject(method, "id", id_key);

        switch (Atype) {
            case Ed25519VerificationKey2018:
                cJSON_AddStringToObject(method, "type", "Ed25519VerificationKey2018");
                break;
            case RsaVerificationKey2018:
                cJSON_AddStringToObject(method, "type", "RsaVerificationKey2018");
                break;
            default:
                printf("Unrecognised key type");
                goto fail;
        }
        cJSON_AddStringToObject(method, "controller", did);
        cJSON_AddStringToObject(method, "publicKeyPem", (const char *) Sbuff->p);
        cJSON_AddItemToObject(did_document, "assertionMethod", method);
    }

    char *did_doc = cJSON_Print(did_document);
    cJSON_Delete(did_document);
    return did_doc;

fail:
    cJSON_Delete(did_document);
    return NULL;
}

int save_next_index(IOTA_Index * next, WAM_channel* ch){
    uint8_t *next_index_bin;
    char next_index[INDEX_HEX_SIZE];
    uint8_t *pub_key_index_bin;
    char pub_key_index[ED_PUBLIC_KEY_BYTES*2+1];
    uint8_t *priv_key_index_bin;
    char priv_key_index[ED_PRIVATE_KEY_BYTES*2+1];
    uint8_t *berry_bin;
    char berry[SEED_SIZE*2+1];
    int ret;

    pub_key_index_bin = ch->next_index.keys.pub;
    ret = bin_2_hex(pub_key_index_bin, ED_PUBLIC_KEY_BYTES, pub_key_index, ED_PUBLIC_KEY_BYTES*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->keys.pub, pub_key_index_bin, ED_PUBLIC_KEY_BYTES);

    priv_key_index_bin = ch->next_index.keys.priv;
    ret = bin_2_hex(priv_key_index_bin, ED_PRIVATE_KEY_BYTES, priv_key_index, ED_PRIVATE_KEY_BYTES*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->keys.priv, priv_key_index_bin, ED_PRIVATE_KEY_BYTES);

    berry_bin = ch->next_index.berry;
    ret = bin_2_hex(berry_bin, SEED_SIZE, berry, SEED_SIZE*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->berry, berry_bin,SEED_SIZE);

    next_index_bin = ch->next_index.index;
    ret = bin_2_hex(next_index_bin, INDEX_SIZE, next_index, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->index, next_index_bin, INDEX_SIZE); //here I save the next index for future updates

    return WAM_OK;
fail:
    return -1;
}




int create(method *methods, char* did_new, IOTA_Index * next) {
    uint8_t *index_bin;
    char index[INDEX_HEX_SIZE];
    uint8_t ret;
    char did[DID_LEN] = "";

    uint8_t mykey[] = "supersecretkeyforencryptionalby"; //temporary, I think must be saved somewhere else
    WAM_channel ch_send;
    WAM_AuthCtx a;
    a.type = AUTHS_NONE;
    WAM_Key k;
    k.data = mykey;
    k.data_len = (uint16_t) strlen((char *) mykey);

    fprintf(stdout, "CREATE\n");
    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};

    
    ret = WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
    if(ret != WAM_OK){
        goto fail;
    }

    index_bin = ch_send.start_index.index; //here i grab the start index that is my did
    ret = bin_2_hex(index_bin, INDEX_SIZE, index, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    strncat(did, DID_PREFIX, DID_PREFIX_LEN);
    strncat(did, index, INDEX_HEX_SIZE);

    //printf("%s\n", did);

    //save next index
    ret = save_next_index(next, &ch_send);
    if(ret != WAM_OK){
        goto fail;
    }
    
/*     pub_key_index_bin = ch_send.next_index.keys.pub;
    ret = bin_2_hex(pub_key_index_bin, ED_PUBLIC_KEY_BYTES, pub_key_index, ED_PUBLIC_KEY_BYTES*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->keys.pub, pub_key_index_bin, ED_PUBLIC_KEY_BYTES);

    priv_key_index_bin = ch_send.next_index.keys.priv;
    ret = bin_2_hex(priv_key_index_bin, ED_PRIVATE_KEY_BYTES, priv_key_index, ED_PRIVATE_KEY_BYTES*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->keys.priv, priv_key_index_bin, ED_PRIVATE_KEY_BYTES);

    berry_bin = ch_send.next_index.berry;
    ret = bin_2_hex(berry_bin, SEED_SIZE, berry, SEED_SIZE*2+1);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->berry, berry_bin,SEED_SIZE);

    next_index_bin = ch_send.next_index.index;
    ret = bin_2_hex(next_index_bin, INDEX_SIZE, next_index, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    memcpy(next->index, next_index_bin, INDEX_SIZE); //here I save the next index for future updates */

    char *did_doc = create_did_document(did, &methods[0].pk_pem, methods[0].type, &methods[1].pk_pem, methods[1].type);
    if(did_doc == NULL){
        ret = DID_CREATE_ERROR;
        goto fail;
    }
    //fprintf(stdout, "%s\n", did_doc);
    //fprintf(stdout, "DID Document length = %lu\n", strlen(did_doc));

    //next_index_bin = ch_send.current_index.index; //here i grab the next index for future updates
   // ret = bin_2_hex(next_index_bin, INDEX_SIZE, next_index, INDEX_HEX_SIZE);
    //if(ret != 0){
   //     goto fail;
    //}
   // printf("CURRENT INDEX DOPO LA CHANNEL INIT %s\n", next_index);
    //next_index_bin = ch_send.next_index.index; //here i grab the next index for future updates
   // ret = bin_2_hex(next_index_bin, INDEX_SIZE, next_index, INDEX_HEX_SIZE);
   // if(ret != 0){
    //    goto fail;
    //}
    //printf("NEXT INDEX DOPO LA CHANNEL INIT %s\n", next_index);

    ret = WAM_write(&ch_send, (unsigned char *) did_doc, strlen(did_doc), false);
    if(ret != WAM_OK){
        goto fail;
    }
    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);
    //copy the did
    strcpy(did_new, did);

    return DID_CREATE_OK;
fail:
    return (ret);
}







static int sub_string(const char *input, int offset, int len, char *dest) {
    size_t input_len = strlen(input);

    if (offset + len > input_len) {
        return -1;
    }

    strncpy(dest, input + offset, len);
    dest[len] = '\0';
    return 0;
}

int resolve(did_document *didDocument, char *did) {
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    uint8_t mykey[] = "supersecretkeyforencryptionalby";
    WAM_channel ch_read;
    WAM_AuthCtx a;
    a.type = AUTHS_NONE;
    WAM_Key k;
    k.data = mykey;
    k.data_len = (uint16_t) strlen((char *) mykey);
    uint8_t tmp_buff[DATA_SIZE];
    uint8_t read_buff[DATA_SIZE];
    uint16_t expected_size = DATA_SIZE;
    uint8_t ret = 0;
    uint8_t revoke[INDEX_SIZE];
    int valid_did_doc_found = 0;
    
    memset(revoke,0, INDEX_SIZE);

    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};

    ret = WAM_init_channel(&ch_read, 1, &testnet0tls, &k, &a);
    if( ret != 0)
        return DID_RESOLVE_ERROR;

    //extract hex_index and convert to index
    ret = sub_string(did, DID_PREFIX_LEN - 1, INDEX_HEX_SIZE - 1, hex_index); //len must not include the \0
    if (ret != 0)
        return DID_RESOLVE_ERROR;

    ret = hex_2_bin(hex_index, INDEX_HEX_SIZE, index, INDEX_SIZE);
    if(ret != 0)
        return DID_RESOLVE_ERROR;

    set_channel_index_read(&ch_read, index);

    while((ret = WAM_read(&ch_read, tmp_buff, &expected_size)) == WAM_OK){
        valid_did_doc_found = 1;
       // printf("%s\n",ch_read.next_index.index);
      //  printf("%s\n",revoke);
        if(memcmp(ch_read.current_index.index, revoke, INDEX_SIZE) == 0){
            return DID_RESOLVE_REVOKED;
        }
        memcpy(read_buff, tmp_buff, DATA_SIZE);
        memset(tmp_buff, 0, DATA_SIZE);
    }

    if(valid_did_doc_found == 0)
        return DID_RESOLVE_ERROR;

    fprintf(stdout, "WAM_read ret:");
    fprintf(stdout, "\n\t val=%d", ret);
    fprintf(stdout, "\n\t expctsize=%d \t", expected_size);
    fprintf(stdout, "\n\t msg_read=%d \t", ch_read.recv_msg);
    fprintf(stdout, "\n\t bytes_read=%d \t", ch_read.recv_bytes);

    read_buff[ch_read.recv_bytes] = '\0';
    fprintf(stdout, "\n\nReceived DID Document: \n");
    fprintf(stdout, "%s\n", read_buff);

    //parsing
    cJSON *did_document_json = cJSON_Parse((const char *) read_buff);
    if (did_document_json == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "Error before: %s\n", error_ptr);
        }

        return DID_RESOLVE_ERROR;;
    }

    //atContext

    const cJSON *atContext_array = NULL;
    const cJSON *atContext = NULL;
    context *curr_context = &didDocument->atContext;
    context *prev_context = curr_context;

    atContext_array = cJSON_GetObjectItemCaseSensitive(did_document_json, "@context");
    if (cJSON_IsArray(atContext_array)) {
        cJSON_ArrayForEach(atContext, atContext_array) {
            if (curr_context == NULL) {
                curr_context = calloc(1, sizeof(context));
                if (curr_context == NULL)
                    return ALLOC_FAILED;
                prev_context->next = curr_context;
                prev_context = prev_context->next;
            }

            curr_context->val.len = strlen(cJSON_GetStringValue(atContext));
            curr_context->val.p = (unsigned char *) strdup(cJSON_GetStringValue(atContext));
            curr_context = NULL;
        }
    } else {
        return DID_RESOLVE_ERROR;
    }

    //id

    const cJSON *id_cJSON = NULL;
    id_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "id");
    if (cJSON_IsString(id_cJSON) && id_cJSON->valuestring != NULL) {
        didDocument->id.len = strlen(id_cJSON->valuestring);
        didDocument->id.p = (unsigned char *) strdup(id_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    //created
    const cJSON *created_cJSON = NULL;
    created_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "created");
    if (cJSON_IsString(created_cJSON) && created_cJSON->valuestring != NULL) {
        didDocument->created.len = strlen(created_cJSON->valuestring);
        didDocument->created.p = (unsigned char *) strdup(created_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    //methods
    const cJSON *method_cJSON = NULL;
    const cJSON *id_method_cJSON = NULL;
    const cJSON *type_cJSON = NULL;
    const cJSON *controller_cJSON = NULL;
    const cJSON *pk_cJSON = NULL;

    method *curr_method = &didDocument->method;
    method *prev_method = curr_method;

    int method_type = 0, exit = 0;

    while (!exit) {
        switch (method_type) {
            case AuthenticationMethod:
                method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "authenticationMethod");
                if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON)) {
                    method_type++;
                    continue;
                }
                break;
            case AssertionMethod:
                method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "assertionMethod");
                if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON)) {
                    method_type++;
                    continue;
                }
                break;
            default:
                exit = 1;
                continue;
        }

        if (curr_method == NULL) {
            curr_method = calloc(1, sizeof(method));
            if (curr_method == NULL)
                return ALLOC_FAILED;
            prev_method->next = curr_method;
            prev_method = prev_method->next;
        }

        curr_method->method_type = method_type;
        id_method_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "id");
        if (cJSON_IsString(id_method_cJSON) && id_method_cJSON->valuestring != NULL) {
            curr_method->id.len = strlen(id_method_cJSON->valuestring);
            curr_method->id.p = (unsigned char *) strdup(id_method_cJSON->valuestring);
        } else {
            return DID_RESOLVE_ERROR;
        }

        type_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "type");
        if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL) {
            curr_method->type = find_key_type(type_cJSON->valuestring);
            if (curr_method->type == NO_VALID_KEY_TYPE)
                return DID_RESOLVE_ERROR;
        } else {
            return DID_RESOLVE_ERROR;
        }

        controller_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "controller");
        if (cJSON_IsString(controller_cJSON) && controller_cJSON->valuestring != NULL) {
            curr_method->controller.len = strlen(controller_cJSON->valuestring);
            curr_method->controller.p = (unsigned char *) strdup(controller_cJSON->valuestring);
        } else {
            return DID_RESOLVE_ERROR;
        }

        pk_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "publicKeyPem");
        if (cJSON_IsString(pk_cJSON) && pk_cJSON->valuestring != NULL) {
            curr_method->pk_pem.len = strlen(pk_cJSON->valuestring);
            curr_method->pk_pem.p = (unsigned char *) strdup(pk_cJSON->valuestring);
        } else {
            return DID_RESOLVE_ERROR;
        }

        curr_method = NULL;
        method_type++;
    }

    cJSON_Delete(did_document_json);
    return DID_RESOLVE_OK;
}

int update(method *methods,char * did,  IOTA_Index *next) {
    //FILE *my_did = NULL;
    char newdid[DID_LEN] = "";
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    char next_index_hex[INDEX_HEX_SIZE];
    uint8_t *index_bin;
    uint8_t mykey[] = "supersecretkeyforencryptionalby"; //temporary, I think must be saved somewhere else
    WAM_channel ch_send;
    WAM_AuthCtx a;
    uint8_t write_buff[DATA_SIZE];
    uint8_t tmp_buff[DATA_SIZE];
    a.type = AUTHS_NONE;
    WAM_Key k;
    k.data = mykey;
    k.data_len = (uint16_t) strlen((char *) mykey);
    int ret=0;
    uint16_t expected_size=DATA_SIZE;
    uint8_t revoke_index[INDEX_SIZE];
    memset(revoke_index,0,INDEX_SIZE);

    fprintf(stdout, "UPDATE\n");

    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};

    ret = WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
    if(ret != WAM_OK){
        goto fail;
    }
    memset(write_buff, 0, DATA_SIZE);
    //extract hex_index and convert to index
    ret = sub_string(did, DID_PREFIX_LEN - 1, INDEX_HEX_SIZE - 1, hex_index); //len must not include the \0
    if (ret != 0) {
        goto fail;
    }
    ret = hex_2_bin(hex_index, INDEX_HEX_SIZE, index, INDEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    set_channel_index_read(&ch_send, index);

    //set current index to last next index saved
    //bin_2_hex(next->index, INDEX_HEX_SIZE, next_index_hex, INDEX_SIZE);
    //fprintf(stdout, "next_index: \n");
    //fprintf(stdout, "%s", next_index_hex);


    if(WAM_read(&ch_send, tmp_buff, &expected_size) != WAM_OK) {
        ret = DID_UPDATE_ERROR;
        printf("No valid did document to update found\n");
        goto fail;
    }

    //second read to be sure that is not already revoked or that was passed to the function the last did of the chain
    if(WAM_read(&ch_send, tmp_buff, &expected_size) == WAM_OK) {
        if(memcmp(ch_send.current_index.index, revoke_index, INDEX_SIZE) == 0){
            printf("Did already revoked\n");
            ret = DID_UPDATE_ERROR;
            goto fail;
        } else {
            printf("Did is not the last one of the chain\n");
            ret = DID_UPDATE_ERROR;
            goto fail;
        }
    }

    //set next index as current
    ret = copy_iota_index(&(ch_send.current_index), next);
    if(ret != WAM_OK){
        goto fail;
    }

    index_bin = ch_send.current_index.index; 
    ret = bin_2_hex(index_bin, INDEX_SIZE, next_index_hex, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    strncat(newdid, DID_PREFIX, DID_PREFIX_LEN);
    strncat(newdid, next_index_hex, INDEX_HEX_SIZE);
    strcpy(did, newdid);
    fprintf(stdout, "new did %s\n", did);

    //create the updated did document
    char *did_doc = create_did_document(did, &methods[0].pk_pem, methods[0].type, &methods[1].pk_pem, methods[1].type);
    if(did_doc == NULL){
        goto fail;
    }

    //fprintf(stdout, "%s\n", did_doc);
    //fprintf(stdout, "DID Document length = %lu\n", strlen(did_doc));
    //save the new did

    ret = copy_iota_index(next,&(ch_send.next_index));
    if(ret!= WAM_OK){
        goto fail;
    }
    //ret = save_next_index(next, &ch_send);
    ret = WAM_write(&ch_send, (unsigned char *) did_doc, strlen(did_doc), false);
    if( ret != WAM_OK){
        goto fail;
    }


   // ret = save_next_index(next, &ch_send);
   // if(ret!= WAM_OK){
   //     goto fail;
    //}

    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

    return DID_UPDATE_OK;
    fail:
    return DID_UPDATE_ERROR;


}


int revoke(char * did, IOTA_Index *next){
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    uint8_t mykey[] = "supersecretkeyforencryptionalby"; //temporary, I think must be saved somewhere else
    WAM_channel ch_send;
    WAM_AuthCtx a;
    a.type = AUTHS_NONE;
    WAM_Key k;
    k.data = mykey;
    k.data_len = (uint16_t) strlen((char *) mykey);
    uint8_t write_buff[DATA_SIZE];
    uint8_t tmp_buff[DATA_SIZE];
    uint16_t expected_size=DATA_SIZE;
    uint8_t ret=0;
    uint8_t revoke_index[INDEX_SIZE];
    memset(revoke_index,0,INDEX_SIZE);
    //uint8_t nxt_idx[INDEX_HEX_SIZE];

    fprintf(stdout, "REVOKE\n");

    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};


    ret = WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
    if(ret != WAM_OK){
        goto fail;
    }
    memset(write_buff, 0, DATA_SIZE);
    //extract hex_index and convert to index
    ret = sub_string(did, DID_PREFIX_LEN - 1, INDEX_HEX_SIZE - 1, hex_index); //len must not include the \0
    if (ret != 0) {
        goto fail;
    }
    ret = hex_2_bin(hex_index, INDEX_HEX_SIZE, index, INDEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    set_channel_index_read(&ch_send, index);
    //fprintf(stdout, "index %s\n", hex_index);

    //first read to see if it is a valid did
    if(WAM_read(&ch_send, tmp_buff, &expected_size) != WAM_OK) {
        ret = DID_REVOKE_ERROR;
        printf("No valid did document to revoke found\n");
        goto fail;
    }

    //second read to be sure that is not already revoked or that was passed to the function the last did of the chain
    if(WAM_read(&ch_send, tmp_buff, &expected_size) == WAM_OK) {
        if(memcmp(ch_send.current_index.index, revoke_index, INDEX_SIZE) == 0){
            printf("Did already revoked\n");
            ret = DID_REVOKE_ERROR;
            goto fail;
        } else {
            printf("Did is not the last one of the chain\n");
            ret = DID_REVOKE_ERROR;
            goto fail;
        }
    }
    //printf(" %s\n", tmp_buff);

    //set next index as current
    ret = copy_iota_index(&(ch_send.current_index), next);
    if(ret != WAM_OK){
        goto fail;
    }

    ret = WAM_write(&ch_send, write_buff, DATA_SIZE, true);
    if(ret != WAM_OK){
        goto fail;
    }

    return DID_REVOKE_OK;

fail:
    return (ret);

}
/* 
#define SIZE 2
#define SIZE2 2

int main() {
    did_document *didDocument = NULL;
    char my_did_str[DID_LEN+1];
    int ret = 0;
    method m[SIZE];
    method m2[SIZE2];

    m[0].method_type = AuthenticationMethod;
    m[0].pk_pem.p = (unsigned char *) KEY;
    m[0].pk_pem.len = strlen(KEY);
    m[0].type = RsaVerificationKey2018;

    m[1].method_type = AssertionMethod;
    m[1].pk_pem.p = (unsigned char *) KEY2;
    m[1].pk_pem.len = strlen(KEY2);
    m[1].type = Ed25519VerificationKey2018;

    m2[0].method_type = AuthenticationMethod;
    m2[0].pk_pem.p = (unsigned char *) KEY3;
    m2[0].pk_pem.len = strlen(KEY3);
    m2[0].type = RsaVerificationKey2018;
    
    m2[1].method_type = AssertionMethod;
    m2[1].pk_pem.p = (unsigned char *) KEY2;
    m2[1].pk_pem.len = strlen(KEY2);
    m2[1].type = RsaVerificationKey2018;

    didDocument = calloc(1, sizeof(did_document));
    if (didDocument == NULL) {
        return ALLOC_FAILED;
    }
    did_document_init(didDocument);

    IOTA_Index next;

    //CREATE
    ret = create(m, my_did_str, &next);
    if(ret != DID_CREATE_OK){
        printf("Did Document creation failed\n");
        goto exit;
    }

    //RESOLVE
    ret = resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
        goto exit;
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }


    //UPDATE KEY1
    ret = update(m2,my_did_str, &next);
    if(ret != DID_UPDATE_OK){
        printf("Update failed");
        goto exit;
    }

    //RESOLVE
    ret = resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
        goto exit;
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }
    
    m2[1].method_type = AssertionMethod;
    m2[1].pk_pem.p = (unsigned char *) KEY4;
    m2[1].pk_pem.len = strlen(KEY4);
    m2[1].type = RsaVerificationKey2018;

    //UPDATE KEY2
    ret = update(m2,my_did_str, &next);
    if(ret != DID_UPDATE_OK){
        printf("Update failed");
        goto exit;
    }

    //RESOLVE
    ret = resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
        goto exit;
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }
    printf("%s\n", my_did_str);

    //REVOKE
    ret = revoke(my_did_str, &next);
    if(ret != DID_REVOKE_OK){
        printf("Revoke failed");
        goto exit;
    }

    //RESOLVE
    ret = resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
        goto exit;
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }

exit:
    did_document_free(didDocument);
    free(didDocument);
    return ( ret );
} */