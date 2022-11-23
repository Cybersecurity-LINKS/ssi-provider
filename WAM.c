/*
 * WAM.c
 *
 */


#include <string.h>
#include "WAM.h"



const uint8_t wam_tag[WAM_TAG_SIZE] = {
    0x3c, 0xab, 0x78, 0xb6, 0x2, 0x64, 0x47, 0xe9, 0x30, 0x26, 0xd4, 0x1f, 0xad, 0x68, 0x22, 0x27,
    0x41, 0xa4, 0x32, 0xba, 0xbe, 0x54, 0x83, 0xee, 0xab, 0x6b, 0x62, 0xce, 0xf0, 0x5c, 0x7, 0x91
};


uint8_t create_wam_msg(WAM_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len);
uint8_t sign_auth_do(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* signature, size_t sig_len);
uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len);
uint16_t get_messages_number(uint16_t len);
uint8_t reset_index(IOTA_Index* index);
uint8_t update_channel_indexes(WAM_channel* channel);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
bool is_null_index(uint8_t* idx);
uint8_t generate_iota_index(IOTA_Index* idx);
uint8_t send_wam_message(WAM_channel* ch, uint8_t* raw_data, uint16_t raw_data_size);
uint8_t convert_wam_endpoint(IOTA_Endpoint* wam_ep, iota_client_conf_t *ep);

uint8_t find_wam_msg(find_msg_t* msg_id_list, WAM_channel* channel, uint8_t* msg, uint16_t* msg_len, uint8_t* next_idx);
bool is_wam_valid_msg(uint8_t* msg, uint16_t* msg_len, WAM_channel* channel, uint8_t* next_idx);
uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index);
uint8_t get_msg_from_id(WAM_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint16_t* msg_bin_len);
uint8_t get_msg_id_list(WAM_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len);
uint8_t sign_auth_check(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* recv_signature, size_t recv_sig_len);
uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk);
//uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);
uint8_t set_channel_current_index(WAM_channel* channel, uint8_t* index_bin);
void print_raw_hex(uint8_t* array, uint16_t array_len);


uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint, WAM_Key* PSK, WAM_AuthCtx* auth) {
	if((channel == NULL) || (endpoint == NULL) || (PSK == NULL) || (auth == NULL)) return WAM_ERR_NULL; 
	if(id < 0) return WAM_ERR_CH_INIT;


	// Clear buffers
	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	// Init Index
	generate_iota_index(&(channel->start_index));
	generate_iota_index(&(channel->next_index));
	copy_iota_index(&(channel->current_index), &(channel->start_index));

	// Set fields
	channel->id = id;
	channel->node = endpoint;
	channel->PSK = PSK;
	channel->auth = auth;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	

	return(WAM_OK);
}


uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint16_t *outDataSize) {
	uint8_t msg_to_read[WAM_MSG_SIZE]; uint16_t msg_len = 0;
	uint8_t next_index[INDEX_SIZE];
	uint16_t i = 0, messages = 0, expected_size = *outDataSize;
	find_msg_t* msg_id_list = NULL; uint32_t msg_id_list_len = 0;
	size_t s = 0; //, recv_data = 0;
	//uint8_t* d = outData;
	res_find_msg_t* response;
    uint8_t ret = 0;

	if((channel == NULL) || (outData == NULL)) return WAM_ERR_NULL;

	messages = get_messages_number(expected_size);
	for(i = 0; i < messages; i++) {
		response = res_find_msg_new();
		// leggi lista msg_id at channel->curr_index  <= response, count, LISTA
		if((ret = get_msg_id_list(channel, response, &msg_id_list, &msg_id_list_len)) != WAM_OK) {
			break;
		}

		// trova il msg_wam nella lista  <= MSG
		// se trovato => update: buffer with msg, offset, next index, channel counters
		// se non trovato => ritorna err (unexpected_end, notfound)
		if((ret = find_wam_msg(msg_id_list, channel, msg_to_read, &msg_len, next_index)) == WAM_OK){
			if(s + msg_len > expected_size) {
				// does not fit
				memcpy(outData + s, msg_to_read, (*outDataSize - s));  // copy only what fits
				channel->recv_msg++;
				channel->recv_bytes += (*outDataSize - s);
				res_find_msg_free(response);
				return(WAM_BUFF_FULL);   // no need to continue
			} else {
				memcpy(outData + s, msg_to_read, msg_len);   // update buffer with msg
				s += msg_len;   // update offset
			}			
			set_channel_current_index(channel, next_index);   // update index

			channel->recv_msg++;   // update counter msg
			channel->recv_bytes += msg_len;   // update counter bytes

		} else {
            if(i > 0){
                ret = WAM_BROKEN_MESSAGE;
            }
            res_find_msg_free(response);
            break;
        }
		res_find_msg_free(response);
		//if(read_wam_msg(channel, msg_to_read, &msg_len) == WAM_OK) {
		//	if(is_wam_message(msg_to_read))
		//	spacchetta_il_msg(channel, msg_to_read, msg_len, outData, &outDataSize);
		//}
	}

	//*outDataSize = s;
	//return(WAM_NOT_FOUND);

    return ( ret );
	//return(WAM_OK);
}


uint8_t find_wam_msg(find_msg_t* msg_id_list, WAM_channel* channel, uint8_t* msg, uint16_t* msg_len, uint8_t* next_idx) {
	char **msg_id = NULL; // list pointer
	res_message_t *response_msg = NULL;

	if((msg_id_list == NULL) || (channel == NULL) || (msg == NULL)) return(WAM_ERR_NULL);


	// get msg data from msg_id-list 1-by-1
	msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	while (msg_id != NULL) {
		response_msg = res_message_new();
		if(get_msg_from_id(channel, *msg_id, response_msg, msg, msg_len) == WAM_OK) {
			if(is_wam_valid_msg(msg, msg_len, channel, next_idx)){
				res_message_free(response_msg);
				return(WAM_OK);
			}
		}
		res_message_free(response_msg);

		msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	}
	return(WAM_NOT_FOUND);
	//p = (char**) utarray_next(response_info->u.msg_ids->msg_ids, p);
	//while (p != NULL) {
	//	WAM_read_msg_by_id(); //(channel, *p, index, next_index, pub_authkey);
	//	p = (char**) utarray_next(response_info->u.msg_ids->msg_ids, p);
	//}
}


// se i check vanno a buon fine, aggiorno msg e msg_len con solo i dati
bool is_wam_valid_msg(uint8_t* msg, uint16_t* msg_len, WAM_channel* channel, uint8_t* next_idx) {
	uint8_t tmp_data[WAM_MSG_PLAIN_SIZE];
	uint8_t plaintext[WAM_MSG_PLAIN_SIZE];
	uint8_t ciphertext[WAM_MSG_CIPH_SIZE];
	uint8_t AuthSign[AUTH_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t next_index[INDEX_SIZE];
	uint8_t pubk[PUBK_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0, cipher_len = 0;
	uint16_t data_len = 0;

	if((msg == NULL) || (channel == NULL)) return(false);
	if(*msg_len < WAM_MSG_HEADER_SIZE) return false;

	// init
	memset(tmp_data, 0, WAM_MSG_PLAIN_SIZE);
	memset(plaintext, 0, WAM_MSG_PLAIN_SIZE);
	memset(ciphertext, 0, WAM_MSG_CIPH_SIZE);
	memset(AuthSign, 0, AUTH_SIZE);
	memset(signature, 0, SIGN_SIZE);
	memset(next_index, 0, INDEX_SIZE);
	memset(pubk, 0, PUBK_SIZE);

	cipher_len = ((size_t) *msg_len) - WAM_TAG_SIZE - NONCE_SIZE;

	if(memcmp(msg, wam_tag, WAM_TAG_SIZE) != 0) return false;
	memcpy(nonce, msg + WAM_TAG_SIZE, NONCE_SIZE);
	memcpy(ciphertext, msg + WAM_TAG_SIZE + NONCE_SIZE, cipher_len);

	plain_len = cipher_len - ENCMAC_SIZE;
	// decryption
#if 1
	////err |= crypto_secretbox_easy(ciphertext, plaintext, plain_len, nonce, channel->PSK);
	err |= crypto_secretbox_open_easy(plaintext, ciphertext, cipher_len, nonce, channel->PSK->data);
	if(err) {fprintf(stdout, "\n\n ERROR DECRYPT.\nKey is:\n"); print_raw_hex(channel->PSK->data, PSK_SIZE);}
	if(err) return(false);
#else
	uint8_t tmp_nonce[NONCE_SIZE];   memset(tmp_nonce, 1, NONCE_SIZE);
	uint8_t tmp_encmac[ENCMAC_SIZE];   memset(tmp_encmac, 0x40, ENCMAC_SIZE);
	if(memcmp(nonce, tmp_nonce, NONCE_SIZE) != 0) return false;
	if(memcmp(ciphertext + plain_len, tmp_encmac, ENCMAC_SIZE) != 0) return false;
	memcpy(plaintext, ciphertext, plain_len);
#endif

	// unpack data
	_GET16(plaintext, WAM_OFFSET_DLEN, data_len);
	_GET256(plaintext, WAM_OFFSET_PUBK, pubk);
	_GET256(plaintext, WAM_OFFSET_NIDX, next_index);
	_GET512(plaintext, WAM_OFFSET_AUTH, AuthSign);
	_GET512(plaintext, WAM_OFFSET_SIGN, signature);
	memcpy(tmp_data, plaintext + WAM_OFFSET_DATA, data_len);

//fprintf(stdout, "RECV - PUBK:\n"); print_raw_hex(pubk, PUBK_SIZE);
//fprintf(stdout, "RECV - NIDX:\n"); print_raw_hex(next_index, INDEX_SIZE);
//fprintf(stdout, "RECV - AUTH:\n"); print_raw_hex(AuthSign, AUTH_SIZE);
//fprintf(stdout, "RECV - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
//fprintf(stdout, "RECV - DATA:\n"); print_raw_hex(tmp_data, data_len);




	// check AuthSign (consider only application data)
	if(sign_auth_check(tmp_data, data_len, channel->auth, AuthSign, AUTH_SIZE) != WAM_OK) return(false);

	// check signature (consider almost whole msg)
	memcpy(tmp_data, plaintext, WAM_OFFSET_SIGN); // copy msg until authsign
	memcpy(tmp_data + WAM_OFFSET_SIGN, plaintext + WAM_OFFSET_DATA, data_len);  // copy app data
	if(sign_hash_check(tmp_data, WAM_OFFSET_SIGN + data_len, signature, pubk) != WAM_OK) return(false);

	

	// check ownership (hash(pubk) == index)
	//if(ownership_check(pubk, channel->current_index.index) != WAM_OK) return(false);
	if(ownership_check(pubk, channel->read_idx) != WAM_OK) return(false);


	if(err != WAM_OK){ // redundant  
		return(false);
	} else {
		memset(msg, 0, WAM_MSG_SIZE);   // clean msg
		memcpy(msg, plaintext + WAM_OFFSET_DATA, data_len);   // copy only application data
		*msg_len = data_len;   // set size of application data
		memcpy(next_idx, next_index, INDEX_SIZE);   // next_index
		return(true);
	}

}


uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(pubk, PUBK_SIZE, hash, BLAKE2B_HASH_SIZE);   // h= b2b(recv_pubk)
	if(memcmp(hash, current_index, INDEX_SIZE) != 0){
		return(WAM_ERR_CRYPTO_OWNERSHIP);
	}
	return(WAM_OK);
}


uint8_t get_msg_from_id(WAM_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint16_t* msg_bin_len) {
	iota_client_conf_t iota_node;
	payload_index_t *indexation_msg = NULL;
	char *msg_data = NULL;
	char msg_string[2*WAM_MSG_HEX_SIZE] = {0};
	int32_t ret = WAM_ERR_RECV;
	
	if((channel == NULL) || (msg_id == NULL)) return(WAM_ERR_NULL);

	// convert IOTA Endpoint
	convert_wam_endpoint(channel->node, &iota_node);

	// download hex message from tangle
	ret = get_message_by_id(&iota_node, msg_id, response_info);
	if(ret != 0) return(WAM_ERR_RECV_API);

	if((response_info->is_error == false) && (response_info->u.msg->type == MSG_PAYLOAD_INDEXATION)) {
		indexation_msg = (payload_index_t *)response_info->u.msg->payload;
		msg_data = (char *)indexation_msg->data->data;
		if(strlen(msg_data) <= 2*WAM_MSG_HEX_SIZE) {
			hex2string(msg_data, msg_string, WAM_MSG_HEX_SIZE);
			//print_raw_hex(msg_string, WAM_MSG_HEX_SIZE);
			hex_2_bin(msg_string, strlen(msg_string), (byte_t *)msg_bin, WAM_MSG_SIZE);
			*msg_bin_len = strlen(msg_string) / 2;
			// hex_2_bin(msg_data, strlen(msg_data), (byte_t *)msg_bin, WAM_MSG_SIZE);
			// *msg_bin_len = strlen(msg_data) / 2;
			//fprintf(stdout, "Hex: %s\n", msg_data);
			return(WAM_OK);
		}
	}

	return(WAM_ERR_RECV);
}


uint8_t get_msg_id_list(WAM_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len) {
	iota_client_conf_t iota_node;
	int32_t ret = WAM_ERR_RECV;
	//char** p = NULL;

	if(channel == NULL) return WAM_ERR_NULL;
	//if(is_null_index(&(channel->current_index))) return(WAM_NO_MESSAGES);
	if(is_null_index(channel->read_idx)) return(WAM_NO_MESSAGES);
	
	// convert index to ASCII-HEX
	//bin_2_hex(channel->current_index.index, INDEX_SIZE, (char *) (channel->buff_hex_index), INDEX_HEX_SIZE);
	bin_2_hex(channel->read_idx, INDEX_SIZE, (char *) (channel->buff_hex_index), INDEX_HEX_SIZE);

	// convert IOTA Endpoint
	convert_wam_endpoint(channel->node, &iota_node);

	// get list of message IDs
	ret = find_message_by_index(&iota_node, (char *) channel->buff_hex_index, response_info);
	if(ret != 0) return(WAM_ERR_RECV_API);

	if(response_info->is_error == false) {
		*list = response_info->u.msg_ids;
		*list_len = response_info->u.msg_ids->count;
		return(WAM_OK);
		//if(response_info->u.msg_ids->count > 1) return(WAM_ERR_RECV_MANYMSG);
		//p = (char**) utarray_next(response_info->u.msg_ids->msg_ids, p);
		//while (p != NULL) {
		//	WAM_read_msg_by_id(); //(channel, *p, index, next_index, pub_authkey);
		//	p = (char**) utarray_next(response_info->u.msg_ids->msg_ids, p);
		//}
	} else {
		return(WAM_ERR_RECV);
	}

}


uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint16_t inDataSize, bool finalize) {
	uint8_t msg_to_send[WAM_MSG_SIZE];
	uint16_t msg_len = 0, i = 0, messages = 0;
	size_t s = 0, sent_data = 0;
	uint8_t* d = inData;

	if((channel == NULL) || (inData == NULL)) return WAM_ERR_NULL;


	messages = get_messages_number(inDataSize);
	for(i = 0; i < messages; i++) {
		s = (inDataSize - sent_data) > (DATA_SIZE) ? (DATA_SIZE) : (inDataSize - sent_data);

		if((finalize == true) && (i == messages - 1)) {
			reset_index(&(channel->next_index));
		}

		create_wam_msg(channel, d, s, msg_to_send, &msg_len);  // == wrap

		if(send_wam_message(channel, msg_to_send, msg_len) == WAM_OK) {
			update_channel_indexes(channel);
			d += s;
			sent_data += s;
			channel->sent_bytes += s;
			channel->sent_msg++;
		}
	}


	return(WAM_OK);
}


uint8_t create_wam_msg(WAM_channel* channel, uint8_t* data, size_t data_len, uint8_t* msg, uint16_t* msg_len) {
	uint8_t tmp_data[WAM_MSG_PLAIN_SIZE];
	uint8_t plaintext[WAM_MSG_PLAIN_SIZE];
	uint8_t ciphertext[WAM_MSG_CIPH_SIZE];
	uint8_t AuthSign[AUTH_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t nonce[NONCE_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0, cipher_len = 0;


	// init
	memset(tmp_data, 0, WAM_MSG_PLAIN_SIZE);
	memset(plaintext, 0, WAM_MSG_PLAIN_SIZE);
	memset(ciphertext, 0, WAM_MSG_CIPH_SIZE);
	memset(AuthSign, 0, AUTH_SIZE);
	memset(signature, 0, SIGN_SIZE);
	
	// copy data fields
	_SET16(plaintext, WAM_OFFSET_DLEN, data_len);
	_SET256(plaintext, WAM_OFFSET_PUBK, channel->current_index.keys.pub);
	_SET256(plaintext, WAM_OFFSET_NIDX, channel->next_index.index);

	// compute authentication signature
	err |= sign_auth_do(data, data_len, channel->auth, AuthSign, AUTH_SIZE);
	_SET512(plaintext, WAM_OFFSET_AUTH, AuthSign);

	// compute signature
	memcpy(tmp_data, plaintext, WAM_OFFSET_SIGN);
	memcpy(tmp_data + WAM_OFFSET_SIGN, data, data_len);
	err |= sign_hash_do(tmp_data, WAM_OFFSET_SIGN + data_len, 
					   channel->current_index.keys.priv, 64, signature, SIGN_SIZE);
	_SET512(plaintext, WAM_OFFSET_SIGN, signature);

	memcpy(plaintext + WAM_OFFSET_DATA, data, data_len);
	plain_len = data_len + WAM_MSG_HEADER_SIZE;

	// encryption
#if 1
	iota_crypto_randombytes(nonce, NONCE_SIZE);
	err |= crypto_secretbox_easy(ciphertext, plaintext, plain_len, nonce, channel->PSK->data);
#else
	memset(nonce, 1, NONCE_SIZE);
	memcpy(ciphertext, plaintext, plain_len);
	memset(ciphertext + plain_len, 0x40, ENCMAC_SIZE);
#endif
	cipher_len = plain_len + ENCMAC_SIZE;

	// build message
	memcpy(msg, wam_tag, WAM_TAG_SIZE);
	memcpy(msg + WAM_TAG_SIZE, nonce, NONCE_SIZE);
	memcpy(msg + WAM_TAG_SIZE + NONCE_SIZE, ciphertext, cipher_len);
	*msg_len = cipher_len + WAM_TAG_SIZE + NONCE_SIZE;

//fprintf(stdout, "SENT - PUBK:\n"); print_raw_hex(channel->current_index.keys.pub, PUBK_SIZE);
//fprintf(stdout, "SENT - NIDX:\n"); print_raw_hex(channel->next_index.index, INDEX_SIZE);
//fprintf(stdout, "SENT - AUTH:\n"); print_raw_hex(AuthSign, AUTH_SIZE);
//fprintf(stdout, "SENT - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
//fprintf(stdout, "SENT - DATA:\n"); print_raw_hex(data, data_len);

	return(err);
}


uint8_t sign_auth_check(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* recv_signature, size_t recv_sig_len) {
	uint8_t tmp_sig[AUTH_SIZE];

	if(a->type == AUTHS_KEY) {
		if(sign_hash_check(data, data_len, recv_signature, a->data) != 0) {
			return(WAM_ERR_CRYPTO_VERAUTHSIGN);
		}
	}
	if(a->type == AUTHS_NONE) {   // AuthSign Verification is performed at upper level;
		memset(tmp_sig, 0xFF, AUTH_SIZE);
		if(memcmp(tmp_sig, recv_signature, AUTH_SIZE) != 0) {
			return(WAM_ERR_CRYPTO_VERAUTHSIGN);
		}   
	}
	return(WAM_OK);
}


uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);

	iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE);
//fprintf(stdout, "HASHDO - DATA:\n"); print_raw_hex(data, data_len);
//fprintf(stdout, "HASHDO - HASH:\n"); print_raw_hex(hash, BLAKE2B_HASH_SIZE);

	if(crypto_sign_ed25519_verify_detached(recv_sign, hash, BLAKE2B_HASH_SIZE, recv_pubk) != 0) {
		return(WAM_ERR_CRYPTO_VERSIGN);
	}
	return(WAM_OK);
}


// sig_len seems useless
uint8_t sign_auth_do(uint8_t* data, size_t data_len, WAM_AuthCtx* a, uint8_t* signature, size_t sig_len) {
	if(a->type==AUTHS_KEY) {
		sign_hash_do(data, data_len, a->data, a->data_len, signature, sig_len);
	}
	if(a->type == AUTHS_NONE) {
		memset(signature, 0xFF, sig_len);   // AuthSign is performed at upper level and embedded in the data;
	}
	return(WAM_OK);
}

// sig_len seems useless; key_len seems useless
uint8_t sign_hash_do(uint8_t* data, size_t data_len, uint8_t* key, uint16_t key_len, uint8_t* signature, size_t sig_len) {
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);
										   // TODO check if sig_len must be a var! Seems no;
	iota_blake2b_sum(data, data_len, hash, BLAKE2B_HASH_SIZE);
//fprintf(stdout, "HASHDO - DATA:\n"); print_raw_hex(data, data_len);
//fprintf(stdout, "HASHDO - HASH:\n"); print_raw_hex(hash, BLAKE2B_HASH_SIZE);

	iota_crypto_sign(key, hash, BLAKE2B_HASH_SIZE, signature);

	return(WAM_OK);
}


uint16_t get_messages_number(uint16_t len) {
	uint16_t nblocks = len / DATA_SIZE;
    if (len % DATA_SIZE != 0) {
		nblocks++;
	}
    return nblocks;
}


// copy into start and curr idx the index to read from (0 to next index)
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin) {
	// set_start_read_idx(start=idx, curr=idx, next=0)
	/*reset_index(&(channel->start_index));
	memcpy(channel->start_index.index, start_index_bin, INDEX_SIZE);
	copy_iota_index(&(channel->current_index), &(channel->start_index));
	reset_index(&(channel->next_index));*/
	
	memcpy(channel->read_idx, start_index_bin, INDEX_SIZE);

	return(WAM_OK);
}


uint8_t set_channel_current_index(WAM_channel* channel, uint8_t* index_bin) {

	memcpy(channel->current_index.index, index_bin, INDEX_SIZE);
	memcpy(channel->read_idx, index_bin, INDEX_SIZE);

	return(WAM_OK);
}


uint8_t reset_index(IOTA_Index* index){
	if(index == NULL) return WAM_ERR_NULL;

	memset(index->berry, 0, SEED_SIZE);
	memset(index->index, 0, INDEX_SIZE);
	memset(index->keys.pub, 0, PUBK_SIZE);
	memset(index->keys.priv, 0, PRIK_SIZE);

	return WAM_OK;
}


uint8_t update_channel_indexes(WAM_channel* channel) {
	if(channel == NULL) return(WAM_ERR_NULL);

	copy_iota_index(&(channel->current_index), &(channel->next_index));
	generate_iota_index(&(channel->next_index));

	return(WAM_OK);
}


uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex) {
	if((srcIndex == NULL) || (dstIndex == NULL)) return WAM_ERR_NULL;

	memcpy(dstIndex->index, srcIndex->index, INDEX_SIZE);
	memcpy(dstIndex->berry, srcIndex->berry, SEED_SIZE);
	memcpy(dstIndex->keys.pub, srcIndex->keys.pub, ED_PUBLIC_KEY_BYTES);
	memcpy(dstIndex->keys.priv, srcIndex->keys.priv, ED_PRIVATE_KEY_BYTES);

	return(WAM_OK);
}


// type of args is wrong. Should be uint8_t*
bool is_null_index(uint8_t* idx) {
	uint8_t a = 0, i = 0;

	if(idx == NULL) return WAM_ERR_NULL;

	for(i=0; i<INDEX_SIZE; i++) a |= idx[i];
	
	return( (a==0) ? true : false);
}


uint8_t generate_iota_index(IOTA_Index* idx) {
	if(idx == NULL) return WAM_ERR_NULL;

	iota_crypto_randombytes(idx->berry, SEED_SIZE);   // generate random
	iota_crypto_keypair(idx->berry, &(idx->keys));   // generate keypair from random
	address_from_ed25519_pub(idx->keys.pub, idx->index);   // index = HashB2B(PubK)

	return(WAM_OK);
}


uint8_t send_wam_message(WAM_channel* ch, uint8_t* raw_data, uint16_t raw_data_size) {
	//uint8_t msg_id[MSGID_HEX_SIZE];
	int32_t ret = WAM_ERR_SEND;
	res_send_message_t response;
	iota_client_conf_t iota_node;

	if(raw_data_size > WAM_MSG_SIZE) return WAM_ERR_SIZE_EXCEEDED;

	// Convert Data and Index to ASCII-HEX
	bin_2_hex(raw_data, raw_data_size, (char *) (ch->buff_hex_data), IOTA_MAX_MSG_SIZE);
	bin_2_hex(ch->current_index.index, INDEX_SIZE, (char *) (ch->buff_hex_index), INDEX_HEX_SIZE);

	// convert IOTA Endpoint
	convert_wam_endpoint(ch->node, &iota_node);
	
	// Init response struct
	memset(&response, 0, sizeof(res_send_message_t));

	// Send
	ret = send_indexation_msg(&iota_node, (char *) (ch->buff_hex_index), (char *) (ch->buff_hex_data), &response);
	if(ret == 0) {
		if (!response.is_error) {
			fprintf(stdout, "Sent message - ID: %s\n", response.u.msg_id);
			fprintf(stdout, "Sent message - index: %s\n", ch->buff_hex_index);
			//print_raw_hex(ch->buff_hex_data, WAM_MSG_HEX_SIZE);
			return(WAM_OK);
			//update_channel_indexes(ch);
			//memcpy(msg_id, response.u.msg_id, MSGID_HEX_SIZE);
		} else {
			fprintf(stderr, "Node response: %s\n", response.u.error->msg);
			res_err_free(response.u.error);
			return(WAM_ERR_SEND_API);
		}
	} else {
		fprintf(stderr, "function [%s]: returned %d\n", __func__, ret);
		return(WAM_ERR_SEND);
	}

	return(ret);
}


uint8_t convert_wam_endpoint(IOTA_Endpoint* wam_ep, iota_client_conf_t *ep) {
	if ((wam_ep == NULL) || (ep == NULL)) return WAM_ERR_NULL;

	memcpy(ep->host, wam_ep->hostname, IOTA_ENDPOINT_MAX_LEN);
	ep->port = wam_ep->port;
	ep->use_tls = wam_ep->tls;
	//(wam_ep->tls == false) ? (ep->use_tls = false) : (ep->use_tls = true);

	return(WAM_OK);
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

void test_write_read_enc_largemsg() {
	uint8_t mykey[]="supersecretkeyforencryptionalby";
	WAM_channel ch_send, ch_read;
	WAM_AuthCtx a; a.type = AUTHS_NONE;
	WAM_Key k; k.data = mykey; k.data_len = (uint16_t) strlen((char*)mykey);
	uint8_t mylargemsg[DATA_SIZE+14];
	uint8_t read_buff[2000];
	uint16_t expected_size = 2000;
	uint8_t ret = 0;
	
	IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
							 .port = 443,
							 .tls = true};

	// write 2 msg
	WAM_init_channel(&ch_send, 1, &testnet0tls, &k, &a);
	WAM_write(&ch_send, mylargemsg, DATA_SIZE+14, false);
	fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

	// read 2 msg
	WAM_init_channel(&ch_read, 1, &testnet0tls, &k, &a);
	set_channel_index_read(&ch_read, ch_send.start_index.index);
	ret = WAM_read(&ch_read, read_buff, &expected_size);
	fprintf(stdout, "WAM_read ret:");
	fprintf(stdout, "\n\t val=%d", ret);
	fprintf(stdout, "\n\t expctsize=%d \t", expected_size);
	fprintf(stdout, "\n\t msg_read=%d \t", ch_read.recv_msg);
	fprintf(stdout, "\n\t bytes_read=%d \t", ch_read.recv_bytes);
	fprintf(stdout, "\n\t cmpbuff=%s \n", (memcmp(mylargemsg, read_buff, DATA_SIZE+14)==0) ? "success" : "failure");
}
