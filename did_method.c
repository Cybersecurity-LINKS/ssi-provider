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

    free(did_doc->authMethod.id.p);
    free(did_doc->authMethod.controller.p);
    free(did_doc->authMethod.pk_pem.p);

    free(did_doc->assertionMethod.id.p);
    free(did_doc->assertionMethod.controller.p);
    free(did_doc->assertionMethod.pk_pem.p);

}
//to be expanded
char *key_types_to_string(KEY_TYPES type) {
    switch (type) {
        case Ed25519VerificationKey2018:
            return "Ed25519VerificationKey2018";
        case RsaVerificationKey2018:
            return "RsaVerificationKey2018";
        case EcdsaSecp256k1VerificationKey2019:
            return "EcdsaSecp256k1VerificationKey2019";
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
            case EcdsaSecp256k1VerificationKey2019:
                if (strcmp(key_type, key_types_to_string(EcdsaSecp256k1VerificationKey2019)) == 0) {
                    return EcdsaSecp256k1VerificationKey2019;
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
    snprintf(index_key, KEY_INDEX_LEN, "%d", 0);
    strncat(id_key, index_key, KEY_INDEX_LEN);
    cJSON_AddStringToObject(method, "id", id_key);

    switch (Atype) {
        case EcdsaSecp256k1VerificationKey2019:
            cJSON_AddStringToObject(method, "type", "EcdsaSecp256k1VerificationKey2019");
            break;
        case RsaVerificationKey2018:
            cJSON_AddStringToObject(method, "type", "RsaVerificationKey2018");
            break;
        case Ed25519VerificationKey2018:
            cJSON_AddStringToObject(method, "type", "Ed25519VerificationKey2018");
            break;
        default:
            printf("Unrecognised key type\n");
            goto fail;
    }

    cJSON_AddStringToObject(method, "controller", did);
    cJSON_AddStringToObject(method, "publicKeyPem", (const char *) Abuff->p);
    cJSON_AddItemToObject(did_document, "authenticationMethod", method);

    if(Sbuff != NULL){
        //assertionMethod
        method = cJSON_CreateObject();
        if(method == NULL){
            goto fail;
        }
        memset(id_key, 0, MAX_KEY_ID_LEN);
        strncat(id_key, did, DID_LEN);
        strcat(id_key, KEY_ID_PREFIX);
        snprintf(index_key, KEY_INDEX_LEN, "%d", 1);
        strncat(id_key, index_key, KEY_INDEX_LEN);
        cJSON_AddStringToObject(method, "id", id_key);
        

        switch (Stype) {
            case EcdsaSecp256k1VerificationKey2019:
                cJSON_AddStringToObject(method, "type", "EcdsaSecp256k1VerificationKey2019");
                break;
            case RsaVerificationKey2018:
                cJSON_AddStringToObject(method, "type", "RsaVerificationKey2018");
                break;
            case Ed25519VerificationKey2018:
                cJSON_AddStringToObject(method, "type", "Ed25519VerificationKey2018");
            break;
            default:
                printf("Unrecognised key type\n");
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

int save_channel(WAM_channel *ch){

    FILE *fp = NULL;
    // open the file in write binary mode

    fp = fopen("channel.txt", "wb");
    if(fp == NULL) {
        return -1;
    }
    //id
    fwrite(&(ch->id), sizeof(uint16_t), 1, fp);
    //node
    fwrite(&(ch->node->tls), sizeof(bool), 1, fp);
    fwrite(&(ch->node->port), sizeof(uint16_t), 1, fp);
    fwrite(ch->node->hostname, sizeof(char), ENDPTNAME_SIZE, fp);
    //start index
    fwrite(ch->first_index.berry, sizeof(uint8_t), SEED_SIZE, fp);
    fwrite(ch->first_index.index, sizeof(uint8_t), INDEX_SIZE, fp);
    fwrite(ch->first_index.keys.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fwrite(ch->first_index.keys.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);//DA RIVEDERE
    //Ccurrent index
    fwrite(ch->second_index.berry, sizeof(uint8_t), SEED_SIZE, fp);
    fwrite(ch->second_index.index, sizeof(uint8_t), INDEX_SIZE, fp);
    fwrite(ch->second_index.keys.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fwrite(ch->second_index.keys.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);//DA RIVEDERE

    //sent_msg
    fwrite(&(ch->sent_msg), sizeof(uint16_t), 1, fp);
    //recv_msg
    fwrite(&(ch->recv_msg), sizeof(uint16_t), 1, fp);
    //sent_bytes
    fwrite(&(ch->sent_bytes), sizeof(uint16_t), 1, fp);
    //recv_bytes
    fwrite(&(ch->recv_bytes), sizeof(uint16_t), 1, fp);
    //buff_hex_data
    fwrite(ch->buff_hex_data, sizeof(uint8_t), IOTA_MAX_MSG_SIZE, fp);
    //buff_hex_index
    fwrite(ch->buff_hex_index, sizeof(uint8_t), INDEX_HEX_SIZE, fp);
    fclose(fp);
    return 0;
}

int load_channel(WAM_channel *ch, IOTA_Endpoint* endpoint){
    FILE *fp = NULL;
    uint16_t sz;
    // open the file in write binary mode
    fp = fopen("channel.txt", "rb");
    if(fp == NULL) {
        return -1;
    }
    //endopint
    ch->node = endpoint;
    //id
    fread(&(ch->id), sizeof(uint16_t), 1, fp);
    //node
    fread(&(ch->node->tls), sizeof(bool), 1, fp);
    fread(&(ch->node->port), sizeof(uint16_t), 1, fp);
    fread(ch->node->hostname, sizeof(char), ENDPTNAME_SIZE, fp);
    //first index
    fread(ch->first_index.berry, sizeof(uint8_t), SEED_SIZE, fp);
    fread(ch->first_index.index, sizeof(uint8_t), INDEX_SIZE, fp);
    fread(ch->first_index.keys.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fread(ch->first_index.keys.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);//DA RIVEDERE
    //second index
    fread(ch->second_index.berry, sizeof(uint8_t), SEED_SIZE, fp);
    fread(ch->second_index.index, sizeof(uint8_t), INDEX_SIZE, fp);
    fwrite(ch->second_index.keys.priv, sizeof(uint8_t), ED_PRIVATE_KEY_BYTES, fp);
    fwrite(ch->second_index.keys.pub, sizeof(uint8_t), ED_PUBLIC_KEY_BYTES, fp);//DA RIVEDERE
    //sent_msg
    fread(&(ch->sent_msg), sizeof(uint16_t), 1, fp);
    //recv_msg
    fread(&(ch->recv_msg), sizeof(uint16_t), 1, fp);
    //sent_bytes
    fread(&(ch->sent_bytes), sizeof(uint16_t), 1, fp);
    //recv_bytes
    fread(ch->recv_bytes, sizeof(uint16_t), 1, fp);
    //buff_hex_data
    fread(ch->buff_hex_data, sizeof(uint8_t), IOTA_MAX_MSG_SIZE, fp);
    //buff_hex_index
    fread(ch->buff_hex_index, sizeof(uint8_t), INDEX_HEX_SIZE, fp);
    fclose(fp);
    return 0;
}

int did_ott_create(method *methods, char* did_new) {
    uint8_t *index_bin;
    char index[INDEX_HEX_SIZE];
    uint8_t ret;
    char did[DID_LEN] = "";
    WAM_channel ch_send;

    fprintf(stdout, "CREATE\n");
    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};

    
    ret = WAM_write_init_channel(&ch_send, 1, &testnet0tls);
    if(ret != WAM_OK){
        goto fail;
    }

    index_bin = ch_send.second_index.index; //here i grab the start index that is my did
    ret = bin_2_hex(index_bin, INDEX_SIZE, index, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    strncat(did, DID_PREFIX, DID_PREFIX_LEN);
    strncat(did, index, INDEX_HEX_SIZE);

    char *did_doc = create_did_document(did, &methods[0].pk_pem, methods[0].type, &methods[1].pk_pem, methods[1].type);
    if(did_doc == NULL){
        ret = DID_CREATE_ERROR;
        goto fail;
    }

    ret = WAM_write(&ch_send, (unsigned char *) did_doc, strlen(did_doc), false);
    if(ret != WAM_OK){
        goto fail;
    }
    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);
    //copy the did
    strcpy(did_new, did);
    
    
    save_channel(&ch_send);

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


int did_ott_resolve(did_document *didDocument, char *did) {
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    WAM_channel ch_read;
    uint8_t tmp_buff[DATA_SIZE];
    uint8_t read_buff[DATA_SIZE];
    uint16_t expected_size = DATA_SIZE;
    uint8_t ret = 0;
    uint8_t revoke[INDEX_SIZE];
    
    memset(revoke,0, INDEX_SIZE);

    IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};
    fprintf(stdout, "RESOLVE\n");

    ret = WAM_read_init_channel(&ch_read, 1, &testnet0tls);
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
    if((ret = WAM_read(&ch_read, tmp_buff, &expected_size)) == WAM_OK){
    //while((ret = WAM_read(&ch_read, tmp_buff, &expected_size)) == WAM_OK){
       // printf("%s\n",ch_read.next_index.index);
      //  printf("%s\n",revoke);
   //     if(memcmp(ch_read.current_index.index, revoke, INDEX_SIZE) == 0){
      //      return DID_RESOLVE_REVOKED;
     //   }
  //   printf("DSADSDS\n");
        memcpy(read_buff, tmp_buff, DATA_SIZE);
        memset(tmp_buff, 0, DATA_SIZE);
    }
    else
        return DID_RESOLVE_NOT_FOUND;

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

    //AuthenticationMethod:
    method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "authenticationMethod");
    if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON)) {
        return DID_RESOLVE_ERROR;
    }
    id_method_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "id");
    if (cJSON_IsString(id_method_cJSON) && id_method_cJSON->valuestring != NULL) {
        didDocument->authMethod.id.len = strlen(id_method_cJSON->valuestring);
        didDocument->authMethod.id.p = (unsigned char *) strdup(id_method_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    type_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL) {
        didDocument->authMethod.type = find_key_type(type_cJSON->valuestring);
        if (didDocument->authMethod.type == NO_VALID_KEY_TYPE)
            return DID_RESOLVE_ERROR;
    } else {
        return DID_RESOLVE_ERROR;
    }

    controller_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "controller");
    if (cJSON_IsString(controller_cJSON) && controller_cJSON->valuestring != NULL) {
        didDocument->authMethod.controller.len = strlen(controller_cJSON->valuestring);
        didDocument->authMethod.controller.p = (unsigned char *) strdup(controller_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    pk_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "publicKeyPem");
    if (cJSON_IsString(pk_cJSON) && pk_cJSON->valuestring != NULL) {
        didDocument->authMethod.pk_pem.len = strlen(pk_cJSON->valuestring);
        didDocument->authMethod.pk_pem.p = (unsigned char *) strdup(pk_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    //AssertionMethod
    method_cJSON = cJSON_GetObjectItemCaseSensitive(did_document_json, "assertionMethod");
    if (method_cJSON == NULL || !cJSON_IsObject(method_cJSON)) {
        return DID_RESOLVE_ERROR;
    }

    id_method_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "id");
    if (cJSON_IsString(id_method_cJSON) && id_method_cJSON->valuestring != NULL) {
        didDocument->assertionMethod.id.len = strlen(id_method_cJSON->valuestring);
        didDocument->assertionMethod.id.p = (unsigned char *) strdup(id_method_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    type_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "type");
    if (cJSON_IsString(type_cJSON) && type_cJSON->valuestring != NULL) {
        didDocument->assertionMethod.type = find_key_type(type_cJSON->valuestring);
        if (didDocument->assertionMethod.type == NO_VALID_KEY_TYPE)
            return DID_RESOLVE_ERROR;
    } else {
        return DID_RESOLVE_ERROR;
    }

    controller_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "controller");
    if (cJSON_IsString(controller_cJSON) && controller_cJSON->valuestring != NULL) {
        didDocument->assertionMethod.controller.len = strlen(controller_cJSON->valuestring);
        didDocument->assertionMethod.controller.p = (unsigned char *) strdup(controller_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    pk_cJSON = cJSON_GetObjectItemCaseSensitive(method_cJSON, "publicKeyPem");
    if (cJSON_IsString(pk_cJSON) && pk_cJSON->valuestring != NULL) {
        didDocument->assertionMethod.pk_pem.len = strlen(pk_cJSON->valuestring);
        didDocument->assertionMethod.pk_pem.p = (unsigned char *) strdup(pk_cJSON->valuestring);
    } else {
        return DID_RESOLVE_ERROR;
    }

    cJSON_Delete(did_document_json);
    return DID_RESOLVE_OK;
}

int did_ott_update(method *methods,char * did) {
    //FILE *my_did = NULL;
    char newdid[DID_LEN] = "";
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    char next_index_hex[INDEX_HEX_SIZE];
    uint8_t *index_bin;
    char index_hex[INDEX_HEX_SIZE];
    WAM_channel ch_send;
    uint8_t write_buff[DATA_SIZE];

    int ret=0;
    //uint16_t expected_size=DATA_SIZE;
    uint8_t revoke_index[INDEX_SIZE];
    memset(revoke_index,0,INDEX_SIZE);

    fprintf(stdout, "UPDATE\n");

     IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
            .port = 443,
            .tls = true};

    //load_channel(&ch_send,&a, &k, &testnet0tls);
    memset(write_buff, 0, DATA_SIZE);

    //TODO: DA TOGLIERE
//    //extract hex_index and convert to index
//    ret = sub_string(did, DID_PREFIX_LEN - 1, INDEX_HEX_SIZE - 1, hex_index); //len must not include the \0
//    if (ret != 0) {
//        goto fail;
//    }
//    ret = hex_2_bin(hex_index, INDEX_HEX_SIZE, index, INDEX_SIZE);
//    if(ret != 0){
//        goto fail;
//    }
   

    index_bin = ch_send.second_index.index; 
    ret = bin_2_hex(index_bin, INDEX_SIZE, index_hex, INDEX_HEX_SIZE);
    if(ret != 0){
        goto fail;
    }
    
    strncat(newdid, DID_PREFIX, DID_PREFIX_LEN);
    strncat(newdid, index_hex, INDEX_HEX_SIZE);
    strcpy(did, newdid);
 
    //create the updated did document
    char *did_doc = create_did_document(did, &methods[0].pk_pem, methods[0].type, &methods[1].pk_pem, methods[1].type);
    if(did_doc == NULL){
        goto fail;
    }

    //fprintf(stdout, "%s\n", did_doc);
    //fprintf(stdout, "DID Document length = %lu\n", strlen(did_doc));
    //save the new did

    ret = WAM_write(&ch_send, (unsigned char *) did_doc, strlen(did_doc), false);
    if( ret != WAM_OK){
        goto fail;
    }

    save_channel(&ch_send);
    fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

    return DID_UPDATE_OK;
    fail:
    return DID_UPDATE_ERROR;


}


int did_ott_revoke(char * did){
    char hex_index[INDEX_HEX_SIZE];
    uint8_t index[INDEX_SIZE];
    WAM_channel ch_send;

    uint8_t write_buff[REVOKE_MSG_SIZE];
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

    //load_channel(&ch_send,&a, &k, &testnet0tls);

    memset(write_buff, 0, REVOKE_MSG_SIZE);

    ret = WAM_write(&ch_send, write_buff, REVOKE_MSG_SIZE, true);
    if(ret != WAM_OK){
        goto fail;
    }

    save_channel(&ch_send);

    return DID_REVOKE_OK;

fail:
    return (ret);
    

}


#define SIZE 2
#define SIZE2 2

int main() {
    did_document *didDocument = NULL;
    char my_did_str[DID_LEN+1];
    int ret = 0;
    method m[SIZE];
    method m2[SIZE2];

    m[0].method_type = AuthenticationMethod;
    m[0].pk_pem.p = (unsigned char *) KEY2;
    m[0].pk_pem.len = strlen(KEY);
    m[0].type = RsaVerificationKey2018;

    m[1].method_type = AssertionMethod;
    m[1].pk_pem.p = (unsigned char *) KEY;
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
     ret = did_ott_create(m, my_did_str);
    if(ret != DID_CREATE_OK){
        printf("Did Document creation failed\n");
        
    }
    //RESOLVE
    printf("%s\n", my_did_str);
    //getc(stdin);
    ret = did_ott_resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
       
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }

/*     //CREATE
    ret = create(m, my_did_str);
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
    ret = update(m2,my_did_str);
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
    ret = update(m2,my_did_str);
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
    ret = revoke(my_did_str);
    if(ret != DID_REVOKE_OK){
        printf("Revoke failed");
        goto exit;
    }

//    //REVOKE
//    ret = revoke(my_did_str);
//    if(ret != DID_REVOKE_OK){
//        printf("Revoke failed");
//        goto exit;
//    }

    //RESOLVE
    ret = resolve(didDocument, my_did_str);
    if(ret == DID_RESOLVE_REVOKED){
        printf("Did Document Revoked\n");
        ret = 0;
        goto exit;
    } else if( ret == DID_RESOLVE_OK){
        printf("Did Document OK\n");
    }
  */
//exit:
   // did_document_free(didDocument);
   // free(didDocument);
   // return ( ret );
}
//*/