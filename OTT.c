/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <string.h>
#include "OTT.h"



const uint8_t ott_tag[OTT_TAG_SIZE] = {
    0x3c, 0xab, 0x78, 0xb6, 0x2, 0x64, 0x47, 0xe9, 0x30, 0x26, 0xd4, 0x1f, 0xad, 0x68, 0x22, 0x27,
    0x41, 0xa4, 0x32, 0xba, 0xbe, 0x54, 0x83, 0xee, 0xab, 0x6b, 0x62, 0xce, 0xf0, 0x5c, 0x7, 0x91
};

const uint8_t ott_tag_revoked[OTT_TAG_SIZE] = {
    0x41, 0xa4, 0x32, 0xba, 0xbe, 0x54, 0x83, 0xee, 0xab, 0x6b, 0x62, 0xce, 0xf0, 0x5c, 0x7, 0x91,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

uint8_t create_ott_msg(OTT_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len, bool finalize);
uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len);
uint16_t get_messages_number(uint16_t len);
uint8_t reset_index(IOTA_Index* index);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
bool is_null_index(uint8_t* idx);
uint8_t generate_iota_index(OTT_channel* channel);
uint8_t send_ott_message(OTT_channel* ch, uint8_t* raw_data, uint16_t raw_data_size, char * msg_id);
uint8_t convert_ott_endpoint(IOTA_Endpoint* ott_ep, iota_client_conf_t *ep);
uint8_t find_ott_msg(find_msg_t* msg_id_list, OTT_channel* channel, uint8_t* msg, uint16_t* msg_len);
uint8_t is_ott_valid_msg(uint8_t* msg, uint16_t* msg_len, OTT_channel* channel);
uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index, uint8_t* anchor);
uint8_t get_msg_from_id(OTT_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint16_t* msg_bin_len);
uint8_t get_msg_id_list(OTT_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len);
uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk);
void print_raw_hex(uint8_t* array, uint16_t array_len);


uint8_t OTT_write_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint) {
	if((channel == NULL) || (endpoint == NULL)) return OTT_ERR_NULL; 
	if(id < 0) return OTT_ERR_CH_INIT;
	uint8_t ret;
	// Clear buffers
	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	// Init Keypair and Index
	ret = generate_iota_index(channel);
	if(ret != OTT_OK)
		return ret;

	// Set fields
	channel->id = id;
	channel->node = endpoint;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	
	return(OTT_OK);
}

uint8_t OTT_read_init_channel(OTT_channel* channel, uint16_t id, char * msg_id, IOTA_Endpoint* endpoint) {
	if((channel == NULL) || (endpoint == NULL)) return OTT_ERR_NULL; 
	if(id < 0) return OTT_ERR_CH_INIT;

	// Clear buffers
	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	// Set fields
	channel->id = id;
	channel->msg_id = msg_id;
	channel->node = endpoint;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	channel->number_ott_msg = 0;
	channel->revoked = 0;
	channel->valid_msg_found = 0;
	return(OTT_OK);
}

uint8_t OTT_read(OTT_channel* channel, uint8_t* outData, uint16_t *outDataSize) {
	uint8_t msg_to_read[OTT_CREATE_MSG_SIZE]; uint16_t msg_len = 0;
	uint16_t i = 0, expected_size = *outDataSize;
	find_msg_t* msg_id_list = NULL; uint32_t msg_id_list_len = 0;
	size_t s = 0; //, recv_data = 0;
	char **msg_id = NULL; // list pointer
	//uint8_t* d = outData;
	res_find_msg_t* response;
	res_message_t *response_msg = NULL;
    uint8_t ret = 0;

	if((channel == NULL) || (outData == NULL)) return OTT_ERR_NULL;


/* 	response = res_find_msg_new();
	if((ret = get_msg_id_list(channel, response, &msg_id_list, &msg_id_list_len)) != OTT_OK) {
		return OTT_NOT_FOUND;
	}	 */

	//printf("Received %d msgs\n", msg_id_list_len);
	//channel->number_ott_msg = msg_id_list_len;
	//for(i = 0; i < msg_id_list_len; i++) {
		//msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
		// leggi lista msg_id at channel->read_index  <= response, count, LISTA
		response_msg = res_message_new();
		if(get_msg_from_id(channel, channel->msg_id, response_msg, msg_to_read, &msg_len) == OTT_OK) {
			ret = is_ott_valid_msg(msg_to_read, &msg_len, channel);
/* 			if(ret == OTT_ERR_CRYPTO_SIGN){
				printf("Invalid sign\n");
			} else if(ret == OTT_OK){
				printf("Valid msg\n");
			} */
 			if(ret == OTT_REVOKE && channel->valid_msg_found == 1 ){
				res_message_free(response_msg);
				return(ret);
			} 
		}
		else{
			res_message_free(response_msg);
			return OTT_NOT_FOUND;
		}
	//}
	// trova il msg_ott nella lista  <= MSG
	// se trovato => update: buffer with msg, offset, next index, channel counters
	// se non trovato => ritorna err (unexpected_end, notfound)
	if(s + msg_len > expected_size) {
		// does not fit
		memcpy(outData + s, msg_to_read, (*outDataSize - s));  // copy only what fits
		channel->recv_msg++;
		channel->recv_bytes += (*outDataSize - s);
		res_find_msg_free(response);
		return(OTT_BUFF_FULL);   // no need to continue
	} else {
		memcpy(outData + s, msg_to_read, msg_len);   // update buffer with msg
		s += msg_len;   // update offset	
	}			
	//DA CONTROLLARE
	channel->recv_msg++;   // update counter msg
	channel->recv_bytes += msg_len;   // update counter bytes
    return ret;
}

// se i check vanno a buon fine, aggiorno msg e msg_len con solo i dati
uint8_t is_ott_valid_msg(uint8_t* msg, uint16_t* msg_len, OTT_channel* channel) {
	uint8_t create_tmp_data[OTT_CREATE_MSG_PLAIN_SIZE];
	uint8_t create_plaintext[OTT_CREATE_MSG_PLAIN_SIZE];
	uint8_t revoke_tmp_data[OTT_RVK_MSG_PLAIN_SIZE];
	uint8_t revoke_plaintext[OTT_RVK_MSG_PLAIN_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t pubk[PUBK_SIZE];
	uint8_t anchor[OTT_ANCHOR_SIZE];
	size_t plain_len = 0;
	uint16_t data_len = 0;
	uint8_t ret;
	bool finalize = false;
	if((msg == NULL) || (channel == NULL)) return(OTT_BROKEN_MESSAGE);
	if(*msg_len < OTT_RVK_MSG_HEADER_SIZE) return OTT_BROKEN_MESSAGE;
	
	plain_len = ((size_t) *msg_len) - OTT_TAG_SIZE;
	//printf("MSg\n", msg); print_raw_hex(msg, msg_len);

	//TAG or REVOKE TAG check
	if(memcmp(msg, ott_tag, OTT_TAG_SIZE) != 0) {
		if (memcmp(msg, ott_tag_revoked, OTT_TAG_SIZE) != 0)
			return OTT_BROKEN_MESSAGE;
		else
			finalize = true;
	}


	//Revoke msg
	if(finalize){
		// init
		memset(revoke_tmp_data, 0, OTT_RVK_MSG_PLAIN_SIZE);
		memset(revoke_plaintext, 0, OTT_RVK_MSG_PLAIN_SIZE);
		memset(signature, 0, SIGN_SIZE);
		memset(pubk, 0, PUBK_SIZE);

		memcpy(revoke_plaintext, msg + OTT_TAG_SIZE, plain_len);

		// unpack data
		_GET16(revoke_plaintext, OTT_RVK_OFFSET_DLEN, data_len);
		_GET256(revoke_plaintext, OTT_RVK_OFFSET_PUBK, pubk);
		_GET512(revoke_plaintext, OTT_RVK_OFFSET_SIGN, signature);
		memcpy(revoke_tmp_data, revoke_plaintext + OTT_RVK_OFFSET_DATA, data_len);

		//fprintf(stdout, "RECV RVK - PUBK:\n"); print_raw_hex(pubk, PUBK_SIZE);
		//fprintf(stdout, "RECV - NIDX:\n"); print_raw_hex(next_index, INDEX_SIZE);
		//fprintf(stdout, "RECV - AUTH:\n"); print_raw_hex(AuthSign, AUTH_SIZE);
		//fprintf(stdout, "RECV - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
		//fprintf(stdout, "RECV - DATA:\n"); print_raw_hex(tmp_data, data_len);

		// check signature (consider almost whole msg)
		memcpy(revoke_tmp_data, revoke_plaintext, OTT_RVK_OFFSET_SIGN); // copy msg until authsign
		memcpy(revoke_tmp_data + OTT_RVK_OFFSET_SIGN, revoke_plaintext + OTT_RVK_OFFSET_DATA, data_len);  // copy app data
		if(sign_hash_check(revoke_tmp_data, OTT_RVK_OFFSET_SIGN + data_len, signature, pubk) != OTT_OK) return(( uint8_t) OTT_ERR_CRYPTO_SIGN);

		//print_raw_hex(pubk, PUBK_SIZE);
		//print_raw_hex(channel->read_idx, INDEX_SIZE);

		//Case 3: previously received valid create msg => check h(pk2|H(pk1)) == index
		if(channel->valid_msg_found == 1){
			iota_blake2b_sum(pubk, PUBK_SIZE, anchor, BLAKE2B_HASH_SIZE);
			ret = ownership_check(channel->keys2.pub, channel->read_idx, anchor);
			if  (ret == OTT_OK){
				channel->revoked = 1;
				return OTT_REVOKE;
			} else
				return OTT_BROKEN_MESSAGE;
		}
		//Case 4: first msg is a revoke msg => save pk1 and wait for other msg to validate it
		else if (channel->valid_msg_found == 0 && channel->number_ott_msg > 1){
			memcpy(channel->keys1.pub, pubk, PUBK_SIZE);
			channel->revoked = 1;
			return OTT_OK;
		} else return(OTT_ERR_RECV);
		//ret = ownership_check(pubk, channel->read_idx, finalize);
	/* 	if(ret == OTT_REVOKE) return(OTT_REVOKE);
		else if(ret != OTT_OK)  */

/* 		memset(msg, 0, OTT_RVK_MSG_SIZE);   // clean msg
		memcpy(msg, revoke_plaintext + OTT_RVK_OFFSET_DATA, data_len);   // copy only application data
		*msg_len = data_len;   // set size of application data */


	}else{//Create msg
		// init
		memset(create_tmp_data, 0, OTT_CREATE_MSG_PLAIN_SIZE);
		memset(create_plaintext, 0, OTT_CREATE_MSG_PLAIN_SIZE);
		memset(signature, 0, SIGN_SIZE);
		memset(pubk, 0, PUBK_SIZE);

		memcpy(create_plaintext, msg + OTT_TAG_SIZE, plain_len);

		// unpack data
		_GET16(create_plaintext, OTT_MSG_OFFSET_DLEN, data_len);
		_GET256(create_plaintext, OTT_MSG_OFFSET_PUBK, pubk);
		_GET256(create_plaintext, OTT_MSG_OFFSET_ANCHOR, anchor);

		if(channel->number_ott_msg > 1){
			//Save data in the channel in case of a revoke message
			memcpy(channel->anchor, anchor, OTT_ANCHOR_SIZE);
			memcpy(channel->keys2.pub, pubk, PUBK_SIZE);
		}


		_GET512(create_plaintext, OTT_MSG_OFFSET_SIGN, signature);
		memcpy(create_tmp_data, create_plaintext + OTT_MSG_OFFSET_DATA, data_len);

		//fprintf(stdout, "RECV MSG - PUBK:\n"); print_raw_hex(pubk, PUBK_SIZE);
		//fprintf(stdout, "RECV - NIDX:\n"); print_raw_hex(next_index, INDEX_SIZE);
		//fprintf(stdout, "RECV MSG - ACHOR:\n"); print_raw_hex(anchor, OTT_ANCHOR_SIZE);
		//fprintf(stdout, "RECV - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
		//fprintf(stdout, "RECV - DATA:\n"); print_raw_hex(tmp_data, data_len);

		// check signature (consider almost whole msg)
		memcpy(create_tmp_data, create_plaintext, OTT_MSG_OFFSET_SIGN); // copy msg until authsign
		memcpy(create_tmp_data + OTT_MSG_OFFSET_SIGN, create_plaintext + OTT_MSG_OFFSET_DATA, data_len);  // copy app data
		if(sign_hash_check(create_tmp_data, OTT_MSG_OFFSET_SIGN + data_len, signature, pubk) != OTT_OK) return(OTT_ERR_CRYPTO_SIGN);
		
		//Case 1: only one msg or first received msg is a create msg => check h(pk2|anchor) == index
		if(channel->revoked == 0){
			ret = ownership_check(pubk, channel->read_idx, anchor);
			if  (ret == OTT_OK){
				channel->valid_msg_found = 1;
			} else
				return OTT_BROKEN_MESSAGE;
		}
		//Case 2: previously received a valid revoke msg => check h(pk2|H(pk1)) == index
		else if(channel->revoked == 1){
			iota_blake2b_sum(channel->keys1.pub, PUBK_SIZE, anchor, BLAKE2B_HASH_SIZE);
			ret = ownership_check(pubk, channel->read_idx, anchor);
			if  (ret == OTT_OK){
				channel->valid_msg_found = 1;
				return OTT_REVOKE;
			}
			else
				return OTT_BROKEN_MESSAGE;
			
		} else return OTT_ERR_RECV;

		memset(msg, 0, OTT_CREATE_MSG_SIZE);   // clean msg
		memcpy(msg, create_plaintext + OTT_MSG_OFFSET_DATA, data_len);   // copy only application data
		*msg_len = data_len;   // set size of application data

	}
	

	return(OTT_OK);
}


uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index, uint8_t* anchor) {
	uint8_t hash[BLAKE2B_HASH_SIZE * 2];
	uint8_t buff[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE * 2);

	memcpy(hash, pubk, BLAKE2B_HASH_SIZE);
	memcpy(hash + BLAKE2B_HASH_SIZE, anchor, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(hash, BLAKE2B_HASH_SIZE * 2, buff, BLAKE2B_HASH_SIZE);

	if(memcmp(buff, current_index, INDEX_SIZE) != 0){
		return(OTT_ERR_CRYPTO_OWNERSHIP);
	}
		return(OTT_OK);
}


uint8_t get_msg_from_id(OTT_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint16_t* msg_bin_len) {
	iota_client_conf_t iota_node;
	payload_index_t *indexation_msg = NULL;
	char *msg_data = NULL;
	char msg_string[2*OTT_MSG_HEX_SIZE] = {0};
	int32_t ret = OTT_ERR_RECV;
	
	if((channel == NULL) || (msg_id == NULL)) return(OTT_ERR_NULL);

	// convert IOTA Endpoint
	convert_ott_endpoint(channel->node, &iota_node);

	// download hex message from tangle
	ret = get_message_by_id(&iota_node, msg_id, response_info);
	if(ret != 0) return(OTT_ERR_RECV_API);

	if((response_info->is_error == false) && (response_info->u.msg->type == MSG_PAYLOAD_INDEXATION)) {
		indexation_msg = (payload_index_t *)response_info->u.msg->payload;
		msg_data = (char *)indexation_msg->data->data;
		if(strlen(msg_data) <= 2*OTT_MSG_HEX_SIZE) {
			hex2string(msg_data, msg_string, OTT_MSG_HEX_SIZE);
			//print_raw_hex(msg_string, OTT_MSG_HEX_SIZE);
			hex_2_bin(msg_string, strlen(msg_string), (byte_t *)msg_bin, OTT_CREATE_MSG_SIZE);
			*msg_bin_len = strlen(msg_string) / 2;
			return(OTT_OK);
		}
	}

	return(OTT_ERR_RECV);
}


uint8_t get_msg_id_list(OTT_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len) {
	iota_client_conf_t iota_node;
	int32_t ret = OTT_ERR_RECV;
	//char** p = NULL;

	if(channel == NULL) return OTT_ERR_NULL;

	if(is_null_index(channel->read_idx)) return(OTT_NO_MESSAGES);
	
	// convert index to ASCII-HEX
	//bin_2_hex(channel->current_index.index, INDEX_SIZE, (char *) (channel->buff_hex_index), INDEX_HEX_SIZE);
	bin_2_hex(channel->read_idx, INDEX_SIZE, (char *) (channel->buff_hex_index), INDEX_HEX_SIZE);

	// convert IOTA Endpoint
	convert_ott_endpoint(channel->node, &iota_node);

	// get list of message IDs
	ret = find_message_by_index(&iota_node, (char *) channel->buff_hex_index, response_info);
	if(ret != 0) return(OTT_ERR_RECV_API);

	if(response_info->is_error == false) {
		*list = response_info->u.msg_ids;
		*list_len = response_info->u.msg_ids->count;
		//printf("%d msg count\n",response_info->u.msg_ids->count);
		return(OTT_OK);
	} else {
		return(OTT_ERR_RECV);
	}

}


uint8_t OTT_write(OTT_channel* channel, uint8_t* inData, uint16_t inDataSize, char * msg_id, bool finalize) {
	uint8_t msg_to_send[OTT_CREATE_MSG_SIZE];
	uint16_t msg_len = 0, i = 0, messages = 0;
	size_t s = 0, sent_data = 0;
	uint8_t* d = inData;
	uint8_t ret = OTT_OK;
	if((channel == NULL) || (inData == NULL)) return OTT_ERR_NULL;

	messages = get_messages_number(inDataSize);
	for(i = 0; i < messages; i++) {
		s = (inDataSize - sent_data) > (DATA_SIZE) ? (DATA_SIZE) : (inDataSize - sent_data);

		if((ret = create_ott_msg(channel, d, s, msg_to_send, &msg_len, finalize)) != OTT_OK) break;  

		if((ret = send_ott_message(channel, msg_to_send, msg_len, msg_id)) == OTT_OK) {
			d += s;
			sent_data += s;
			channel->sent_bytes += s;
			channel->sent_msg++;
		}
		else 
			break;
	}

	return(ret);
}


uint8_t create_ott_msg(OTT_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len, bool finalize) {
	uint8_t create_tmp_data[OTT_CREATE_MSG_PLAIN_SIZE];
	uint8_t revoke_tmp_data[OTT_RVK_MSG_PLAIN_SIZE];
	uint8_t create_plaintext[OTT_CREATE_MSG_PLAIN_SIZE];
	uint8_t revoke_plaintext[OTT_RVK_MSG_PLAIN_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0;

	if (finalize){
		
		//revoke msg -> pub1
		memset(revoke_tmp_data, 0, OTT_RVK_MSG_PLAIN_SIZE);
		memset(revoke_plaintext, 0, OTT_RVK_MSG_PLAIN_SIZE);
		memset(signature, 0, SIGN_SIZE);

		// copy data fields
		_SET16(revoke_plaintext, OTT_RVK_OFFSET_DLEN, data_len);

		_SET256(revoke_plaintext, OTT_RVK_OFFSET_PUBK, channel->keys1.pub);
		// compute signature
		memcpy(revoke_tmp_data, revoke_plaintext, OTT_RVK_OFFSET_SIGN);
		memcpy(revoke_tmp_data + OTT_RVK_OFFSET_SIGN, data, data_len);
		//err == sign_hash_do(revoke_tmp_data, OTT_RVK_OFFSET_SIGN + data_len, channel->keys1.priv, 64, signature, SIGN_SIZE);
		if(sign_hash_do(revoke_tmp_data, OTT_RVK_OFFSET_SIGN + data_len, channel->keys1.priv, 64, signature, SIGN_SIZE) != 0){
			printf("ERROR sign_hash_do revoke\n");
			return err;
		}
		_SET512(revoke_plaintext, OTT_RVK_OFFSET_SIGN, signature);		
		memcpy(revoke_plaintext + OTT_RVK_OFFSET_DATA, data, data_len);
		plain_len = data_len + OTT_RVK_MSG_HEADER_SIZE;
		// build message
		memcpy(msg, ott_tag_revoked, OTT_TAG_SIZE);
		memcpy(msg + OTT_TAG_SIZE, revoke_plaintext, plain_len);
		*msg_len = plain_len + OTT_TAG_SIZE ;

	}else{
		//Create msg
		memset(create_tmp_data, 0, OTT_CREATE_MSG_PLAIN_SIZE);
		memset(create_plaintext, 0, OTT_CREATE_MSG_PLAIN_SIZE);
		memset(signature, 0, SIGN_SIZE);

		// copy data fields
		_SET16(create_plaintext, OTT_MSG_OFFSET_DLEN, data_len);

		_SET256(create_plaintext, OTT_MSG_OFFSET_PUBK, channel->keys2.pub);
		_SET256(create_plaintext, OTT_MSG_OFFSET_ANCHOR, channel->anchor);
		// compute signature
		memcpy(create_tmp_data, create_plaintext, OTT_MSG_OFFSET_SIGN);
		memcpy(create_tmp_data + OTT_MSG_OFFSET_SIGN, data, data_len);
		if(sign_hash_do(create_tmp_data, OTT_MSG_OFFSET_SIGN + data_len, channel->keys2.priv, 64, signature, SIGN_SIZE) != 0){
			printf("ERROR sign_hash_do\n");
			return err;
		}
		_SET512(create_plaintext, OTT_MSG_OFFSET_SIGN, signature);
		memcpy(create_plaintext + OTT_MSG_OFFSET_DATA, data, data_len);
		plain_len = data_len + OTT_CREATE_MSG_HEADER_SIZE;
		// build message
		memcpy(msg, ott_tag, OTT_TAG_SIZE);
		memcpy(msg + OTT_TAG_SIZE, create_plaintext, plain_len);
		*msg_len = plain_len + OTT_TAG_SIZE ;
	}
	



//fprintf(stdout, "SENT - PUBK:\n"); print_raw_hex(channel->current_index.keys.pub, PUBK_SIZE);
//fprintf(stdout, "SENT - NIDX:\n"); print_raw_hex(channel->next_index.index, INDEX_SIZE);
//fprintf(stdout, "SENT - AUTH:\n"); print_raw_hex(AuthSign, AUTH_SIZE);
//fprintf(stdout, "SENT - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
//fprintf(stdout, "SENT - DATA:\n"); print_raw_hex(data, data_len);

	return(err);
}

uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE);
//fprintf(stdout, "HASHDO - DATA:\n"); print_raw_hex(data, data_len);
//fprintf(stdout, "HASHDO - HASH:\n"); print_raw_hex(hash, BLAKE2B_HASH_SIZE);
	if(crypto_sign_ed25519_verify_detached(recv_sign, hash, BLAKE2B_HASH_SIZE, recv_pubk) != 0) {
		return(OTT_ERR_CRYPTO_VERSIGN);
	}
	return(OTT_OK);
}

// sig_len seems useless; key_len seems useless
uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len) {
	int ret;
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);
										   
	if ((ret = iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE)) != 0 ) ret = OTT_ERR_CRYPTO_BLACKE2B;
//fprintf(stdout, "HASHDO - DATA:\n"); print_raw_hex(data, data_len);
//fprintf(stdout, "HASHDO - HASH:\n"); print_raw_hex(hash, BLAKE2B_HASH_SIZE);
	if ((ret = iota_crypto_sign(key, hash, BLAKE2B_HASH_SIZE, signature)) != 0 ) ret = OTT_ERR_CRYPTO_BLACKE2B;
	
	return(ret);
}


uint16_t get_messages_number(uint16_t len) {
	uint16_t nblocks = len / DATA_SIZE;
    if (len % DATA_SIZE != 0) {
		nblocks++;
	}
    return nblocks;
}


// copy into start and curr idx the index to read from (0 to next index)
uint8_t set_channel_index_read(OTT_channel* channel, uint8_t* start_index_bin) {

	memcpy(channel->read_idx, start_index_bin, INDEX_SIZE);

	return(OTT_OK);
}


//uint8_t set_channel_current_index(OTT_channel* channel, uint8_t* index_bin) {

/* 	memcpy(channel->current_index.index, index_bin, INDEX_SIZE);
	memcpy(channel->read_idx, index_bin, INDEX_SIZE); */

	//return(OTT_OK);
//}


uint8_t reset_index(IOTA_Index* index){
	if(index == NULL) return OTT_ERR_NULL;

	memset(index->berry, 0, SEED_SIZE);
	memset(index->index, 0, INDEX_SIZE);
	memset(index->keys.pub, 0, PUBK_SIZE);
	memset(index->keys.priv, 0, PRIK_SIZE);

	return OTT_OK;
}

uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex) {
	if((srcIndex == NULL) || (dstIndex == NULL)) return OTT_ERR_NULL;

	memcpy(dstIndex->index, srcIndex->index, INDEX_SIZE);
	memcpy(dstIndex->berry, srcIndex->berry, SEED_SIZE);
	memcpy(dstIndex->keys.pub, srcIndex->keys.pub, ED_PUBLIC_KEY_BYTES);
	memcpy(dstIndex->keys.priv, srcIndex->keys.priv, ED_PRIVATE_KEY_BYTES);

	return(OTT_OK);
}


// type of args is wrong. Should be uint8_t*
bool is_null_index(uint8_t* idx) {
	uint8_t a = 0, i = 0;

	if(idx == NULL) return OTT_ERR_NULL;

	for(i=0; i<INDEX_SIZE; i++) a |= idx[i];
	
	return( (a==0) ? true : false);
}


uint8_t generate_iota_index(OTT_channel* channel) {
	int ret;
	uint8_t berry1[SEED_SIZE];
	uint8_t berry2[SEED_SIZE];
	uint8_t buff[SEED_SIZE * 2];
	if(channel == NULL) return OTT_ERR_NULL;
	
	// generate first random seed
	iota_crypto_randombytes(berry1, SEED_SIZE);
	// generate second random seed
	iota_crypto_randombytes(berry2, SEED_SIZE);
	//generate the firstkeypair from random 
	iota_crypto_keypair(berry1, &(channel->keys1));
	//fprintf(stdout, "PUBK1:\n"); print_raw_hex(channel->keys1.pub, PUBK_SIZE);
	//generate the second keypair from random 
	iota_crypto_keypair(berry2, &(channel->keys2));
	//fprintf(stdout, "PUBK2:\n"); print_raw_hex(channel->keys2.pub, PUBK_SIZE);
	//Create the anchor -> H(pub key1)
	if ((ret = address_from_ed25519_pub(channel->keys1.pub, channel->anchor)) != 0) return OTT_ERR_CRYPTO_E25519;
	//printf("Anchor: \n"); print_raw_hex(channel->anchor, INDEX_SIZE);
	//pub key2|anchor
	memcpy(buff, channel->keys2.pub, ED25519_ADDRESS_BYTES);
	memcpy(buff + ED25519_ADDRESS_BYTES, channel->anchor, SEED_SIZE);
	//create the index -> H(pub key2|anchor)
	if ((ret = iota_blake2b_sum(buff, SEED_SIZE * 2, channel->index, BLAKE2B_HASH_SIZE)) != 0 ) ret = OTT_ERR_CRYPTO_BLACKE2B;
	//printf("iNDEX: \n"); print_raw_hex(channel->index, INDEX_SIZE);
	return(OTT_OK);
}


uint8_t send_ott_message(OTT_channel* ch, uint8_t* raw_data, uint16_t raw_data_size, char * msg_id) {
	int32_t ret = OTT_ERR_SEND;
	res_send_message_t response;
	iota_client_conf_t iota_node;

	if(raw_data_size > OTT_CREATE_MSG_SIZE) return OTT_ERR_SIZE_EXCEEDED;

	// Convert Data and Index to ASCII-HEX
	bin_2_hex(raw_data, raw_data_size, (char *) (ch->buff_hex_data), IOTA_MAX_MSG_SIZE);
	bin_2_hex(ch->index, INDEX_SIZE, (char *) (ch->buff_hex_index), INDEX_HEX_SIZE);
	
	// convert IOTA Endpoint
	convert_ott_endpoint(ch->node, &iota_node);
	
	// Init response struct
	memset(&response, 0, sizeof(res_send_message_t));

	// Send
	ret = send_indexation_msg(&iota_node, (char *) (ch->buff_hex_index), (char *) (ch->buff_hex_data), &response);
	if(ret == 0) {
		if (!response.is_error) {
			//Copy Message ID
			memcpy(msg_id, response.u.msg_id, (IOTA_MESSAGE_ID_HEX_BYTES + 1));
			fprintf(stdout, "Sent message - ID: %s\n", response.u.msg_id);
			fprintf(stdout, "Sent message - index: %s\n", ch->buff_hex_index);
			//print_raw_hex(ch->buff_hex_data, OTT_MSG_HEX_SIZE);
			return(OTT_OK);
			//memcpy(msg_id, response.u.msg_id, MSGID_HEX_SIZE);
		} else {
			fprintf(stderr, "Node response: %s\n", response.u.error->msg);
			res_err_free(response.u.error);
			return(OTT_ERR_SEND_API);
		}
	} else {
		fprintf(stderr, "function [%s]: returned %d\n", __func__, ret);
		return(OTT_ERR_SEND);
	}

	return(ret);
}


uint8_t convert_ott_endpoint(IOTA_Endpoint* ott_ep, iota_client_conf_t *ep) {
	if ((ott_ep == NULL) || (ep == NULL)) return OTT_ERR_NULL;

	memcpy(ep->host, ott_ep->hostname, IOTA_ENDPOINT_MAX_LEN);
	ep->port = ott_ep->port;
	ep->use_tls = ott_ep->tls;

	return(OTT_OK);
}



void print_raw_hex(uint8_t* array, uint16_t array_len) {

	for(int i = 0; i < array_len; i++)
    	fprintf(stdout, "%#x ", array[i]);
	
	fprintf(stdout, "\n");
}


void dummy_print(uint8_t* str_hello) {
	fprintf(stdout, "This is C!\n");
	if(str_hello != NULL) fprintf(stdout, "%s\n", str_hello);
}
