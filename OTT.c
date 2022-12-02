/*
 * OTT.c
 *
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
uint8_t generate_iota_index(IOTA_Index* idx1, IOTA_Index* idx2);
uint8_t send_ott_message(OTT_channel* ch, uint8_t* raw_data, uint16_t raw_data_size);
uint8_t convert_ott_endpoint(IOTA_Endpoint* ott_ep, iota_client_conf_t *ep);
uint8_t find_ott_msg(find_msg_t* msg_id_list, OTT_channel* channel, uint8_t* msg, uint16_t* msg_len);
uint8_t is_ott_valid_msg(uint8_t* msg, uint16_t* msg_len, OTT_channel* channel);
uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index, bool finalize);
uint8_t get_msg_from_id(OTT_channel* channel, char* msg_id, res_message_t* response_info, uint8_t* msg_bin, uint16_t* msg_bin_len);
uint8_t get_msg_id_list(OTT_channel* channel, res_find_msg_t* response_info, find_msg_t** list, uint32_t *list_len);
uint8_t sign_hash_check(uint8_t* data, uint16_t data_len, uint8_t* recv_sign, uint8_t* recv_pubk);
void print_raw_hex(uint8_t* array, uint16_t array_len);


uint8_t OTT_write_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint) {
	if((channel == NULL) || (endpoint == NULL)) return OTT_ERR_NULL; 
	if(id < 0) return OTT_ERR_CH_INIT;

	// Clear buffers
	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	// Init Indexes
	generate_iota_index(&(channel->first_index), &(channel->second_index));

	// Set fields
	channel->id = id;
	channel->node = endpoint;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	
	return(OTT_OK);
}

uint8_t OTT_read_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint) {
	if((channel == NULL) || (endpoint == NULL)) return OTT_ERR_NULL; 
	if(id < 0) return OTT_ERR_CH_INIT;

	// Clear buffers
	memset(channel->buff_hex_data, 0, IOTA_MAX_MSG_SIZE);
	memset(channel->buff_hex_index, 0, INDEX_HEX_SIZE);
	
	// Set fields
	channel->id = id;
	channel->node = endpoint;
	channel->sent_msg = 0;
	channel->recv_msg = 0;
	channel->sent_bytes = 0;
	channel->recv_bytes = 0;
	
	return(OTT_OK);
}

uint8_t OTT_read(OTT_channel* channel, uint8_t* outData, uint16_t *outDataSize) {
	uint8_t msg_to_read[OTT_MSG_SIZE]; uint16_t msg_len = 0;
	uint16_t i = 0, expected_size = *outDataSize;
	find_msg_t* msg_id_list = NULL; uint32_t msg_id_list_len = 0;
	size_t s = 0; //, recv_data = 0;
	char **msg_id = NULL; // list pointer
	//uint8_t* d = outData;
	res_find_msg_t* response;
	res_message_t *response_msg = NULL;
    uint8_t ret = 0;

	if((channel == NULL) || (outData == NULL)) return OTT_ERR_NULL;

	response = res_find_msg_new();
	if((ret = get_msg_id_list(channel, response, &msg_id_list, &msg_id_list_len)) != OTT_OK) {
		return OTT_NOT_FOUND;
	}	

	for(i = 0; i < msg_id_list_len; i++) {
		msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
		// leggi lista msg_id at channel->read_index  <= response, count, LISTA
		response_msg = res_message_new();
		if(get_msg_from_id(channel, *msg_id, response_msg, msg_to_read, &msg_len) == OTT_OK) {
			ret = is_ott_valid_msg(msg_to_read, &msg_len, channel);
			if(ret == OTT_REVOKE){
				res_message_free(response_msg);
				return(ret);
			}
		}
		else{
			res_message_free(response_msg);
			return OTT_NOT_FOUND;
		}
	}
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


/* uint8_t OTT_read(OTT_channel* channel, uint8_t* outData, uint16_t *outDataSize) {
	uint8_t msg_to_read[OTT_MSG_SIZE]; uint16_t msg_len = 0;
	uint16_t i = 0, messages = 0, expected_size = *outDataSize;
	find_msg_t* msg_id_list = NULL; uint32_t msg_id_list_len = 0;
	size_t s = 0; //, recv_data = 0;
	//uint8_t* d = outData;
	res_find_msg_t* response;
    uint8_t ret = 0;

	if((channel == NULL) || (outData == NULL)) return OTT_ERR_NULL;

	messages = get_messages_number(expected_size);
	printf("messages %d\n", messages);
	for(i = 0; i < messages; i++) {
		response = res_find_msg_new();
		// leggi lista msg_id at channel->read_index  <= response, count, LISTA
		printf("for messaggi1\n");
		if((ret = get_msg_id_list(channel, response, &msg_id_list, &msg_id_list_len)) != OTT_OK) {
			break;
		}

		// trova il msg_ott nella lista  <= MSG
		// se trovato => update: buffer with msg, offset, next index, channel counters
		// se non trovato => ritorna err (unexpected_end, notfound)
		ret = find_ott_msg(msg_id_list, channel, msg_to_read, &msg_len);
		printf("for messaggi2\n");
		if (ret == OTT_REVOKE){
			res_find_msg_free(response);
			return(OTT_REVOKE);
		}
		if(ret == OTT_OK){
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

		} else {
            if(i > 0){
                ret = OTT_BROKEN_MESSAGE;
            }
            res_find_msg_free(response);
            break;
        }
		res_find_msg_free(response);
	}

    return ret;
} */




/* uint8_t find_ott_msg(find_msg_t* msg_id_list, OTT_channel* channel, uint8_t* msg, uint16_t* msg_len) {
	char **msg_id = NULL; // list pointer
	res_message_t *response_msg = NULL;
	uint8_t ret;
	if((msg_id_list == NULL) || (channel == NULL) || (msg == NULL)) return(OTT_ERR_NULL);


	// get msg data from msg_id-list 1-by-1
	msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	//printf("msgid %s\n", *msg_id);
	while (msg_id != NULL) {
		//printf("msg id\n"); print_raw_hex(msg_id, msg_len);
		printf("msgid %s\n", *msg_id);
		response_msg = res_message_new();
		if(get_msg_from_id(channel, *msg_id, response_msg, msg, msg_len) == OTT_OK) {
			ret = is_ott_valid_msg(msg, msg_len, channel);
			if(ret == OTT_OK || ret == OTT_REVOKE){
				res_message_free(response_msg);
				return(ret);
			}
		}
		res_message_free(response_msg);

		msg_id = (char**) utarray_next(msg_id_list->msg_ids, msg_id);
	}

	return(OTT_NOT_FOUND);
} */


// se i check vanno a buon fine, aggiorno msg e msg_len con solo i dati
uint8_t is_ott_valid_msg(uint8_t* msg, uint16_t* msg_len, OTT_channel* channel) {
	uint8_t tmp_data[OTT_MSG_PLAIN_SIZE];
	uint8_t plaintext[OTT_MSG_PLAIN_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t pubk[PUBK_SIZE];
	size_t plain_len = 0;
	uint16_t data_len = 0;
	uint8_t ret;
	bool finalize = false;
	if((msg == NULL) || (channel == NULL)) return(false);
	if(*msg_len < OTT_MSG_HEADER_SIZE) return false;
	;
	// init
	memset(tmp_data, 0, OTT_MSG_PLAIN_SIZE);
	memset(plaintext, 0, OTT_MSG_PLAIN_SIZE);
	memset(signature, 0, SIGN_SIZE);
	//memset(next_index, 0, INDEX_SIZE);
	memset(pubk, 0, PUBK_SIZE);

	plain_len = ((size_t) *msg_len) - OTT_TAG_SIZE;
	//printf("MSg\n", msg); print_raw_hex(msg, msg_len);

	if(memcmp(msg, ott_tag, OTT_TAG_SIZE) != 0) {
		if (memcmp(msg, ott_tag_revoked, OTT_TAG_SIZE) != 0)
			return false;
		else
			finalize = true;
	}
	
	memcpy(plaintext, msg + OTT_TAG_SIZE, plain_len);
	// unpack data
	_GET16(plaintext, OTT_OFFSET_DLEN, data_len);
	_GET256(plaintext, OTT_OFFSET_PUBK, pubk);
	_GET512(plaintext, OTT_OFFSET_SIGN, signature);
	memcpy(tmp_data, plaintext + OTT_OFFSET_DATA, data_len);

//fprintf(stdout, "RECV - PUBK:\n"); print_raw_hex(pubk, PUBK_SIZE);
//fprintf(stdout, "RECV - NIDX:\n"); print_raw_hex(next_index, INDEX_SIZE);
//fprintf(stdout, "RECV - AUTH:\n"); print_raw_hex(AuthSign, AUTH_SIZE);
//fprintf(stdout, "RECV - SIGN:\n"); print_raw_hex(signature, SIGN_SIZE);
//fprintf(stdout, "RECV - DATA:\n"); print_raw_hex(tmp_data, data_len);

	// check signature (consider almost whole msg)
	memcpy(tmp_data, plaintext, OTT_OFFSET_SIGN); // copy msg until authsign
	memcpy(tmp_data + OTT_OFFSET_SIGN, plaintext + OTT_OFFSET_DATA, data_len);  // copy app data
	if(sign_hash_check(tmp_data, OTT_OFFSET_SIGN + data_len, signature, pubk) != OTT_OK) return(false);
	
	//check ownership (hash(pubk) == index)
	//print_raw_hex(pubk, PUBK_SIZE);
	//print_raw_hex(channel->read_idx, INDEX_SIZE);
	ret = ownership_check(pubk, channel->read_idx, finalize);
	if(ret == OTT_REVOKE) return(OTT_REVOKE);
	else if(ret != OTT_OK) return(OTT_ERR_RECV);

	memset(msg, 0, OTT_MSG_SIZE);   // clean msg
	memcpy(msg, plaintext + OTT_OFFSET_DATA, data_len);   // copy only application data
	*msg_len = data_len;   // set size of application data
	return(OTT_OK);
}


uint8_t ownership_check(uint8_t* pubk, uint8_t* current_index, bool finalize) {
	iota_keypair_t keypair;
	uint8_t hash[BLAKE2B_HASH_SIZE];
	memset(hash, 0, BLAKE2B_HASH_SIZE);
	//TODO REVOKE CONTROLLARE PRIV1 HASH
	iota_blake2b_sum(pubk, PUBK_SIZE, hash, BLAKE2B_HASH_SIZE);   // h= b2b(recv_pubk)
	//print_raw_hex(hash, BLAKE2B_HASH_SIZE);
	
	if (finalize){
		//hash(pub1)-> pub2 -> hash(pub2) = index
		iota_crypto_keypair(hash, &keypair);
		//printf("pub2");print_raw_hex(hash, BLAKE2B_HASH_SIZE);
		iota_blake2b_sum(keypair.pub, PUBK_SIZE, hash, BLAKE2B_HASH_SIZE);
		//print_raw_hex(hash, BLAKE2B_HASH_SIZE);
	}
	
	if(memcmp(hash, current_index, INDEX_SIZE) != 0){
		return(OTT_ERR_CRYPTO_OWNERSHIP);
	}
	if (finalize)
		return(OTT_REVOKE);
	else	
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
			hex_2_bin(msg_string, strlen(msg_string), (byte_t *)msg_bin, OTT_MSG_SIZE);
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
		printf("%d msg count\n",response_info->u.msg_ids->count);
		return(OTT_OK);
	} else {
		return(OTT_ERR_RECV);
	}

}


uint8_t OTT_write(OTT_channel* channel, uint8_t* inData, uint16_t inDataSize, bool finalize) {
	uint8_t msg_to_send[OTT_MSG_SIZE];
	uint16_t msg_len = 0, i = 0, messages = 0;
	size_t s = 0, sent_data = 0;
	uint8_t* d = inData;
	uint8_t ret = OTT_OK;
	if((channel == NULL) || (inData == NULL)) return OTT_ERR_NULL;

	messages = get_messages_number(inDataSize);
	for(i = 0; i < messages; i++) {
		s = (inDataSize - sent_data) > (DATA_SIZE) ? (DATA_SIZE) : (inDataSize - sent_data);

		if((ret = create_ott_msg(channel, d, s, msg_to_send, &msg_len, finalize)) != OTT_OK) break;  

		if((ret = send_ott_message(channel, msg_to_send, msg_len)) == OTT_OK) {
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
	uint8_t tmp_data[OTT_MSG_PLAIN_SIZE];
	uint8_t plaintext[OTT_MSG_PLAIN_SIZE];
	uint8_t signature[SIGN_SIZE];
	uint8_t err = 0;
	size_t plain_len = 0;


	// init
	memset(tmp_data, 0, OTT_MSG_PLAIN_SIZE);
	memset(plaintext, 0, OTT_MSG_PLAIN_SIZE);
	memset(signature, 0, SIGN_SIZE);
	
	// copy data fields
	_SET16(plaintext, OTT_OFFSET_DLEN, data_len);
	//revoke -> pub1
	if (finalize)
		_SET256(plaintext, OTT_OFFSET_PUBK, channel->first_index.keys.pub);
	else
		_SET256(plaintext, OTT_OFFSET_PUBK, channel->second_index.keys.pub);
	
	// compute signature
	memcpy(tmp_data, plaintext, OTT_OFFSET_SIGN);
	memcpy(tmp_data + OTT_OFFSET_SIGN, data, data_len);
	if (finalize)
		err |= sign_hash_do(tmp_data, OTT_OFFSET_SIGN + data_len, 
					   channel->first_index.keys.priv, 64, signature, SIGN_SIZE);
	else
		err |= sign_hash_do(tmp_data, OTT_OFFSET_SIGN + data_len, 
					   channel->second_index.keys.priv, 64, signature, SIGN_SIZE);
	_SET512(plaintext, OTT_OFFSET_SIGN, signature);

	memcpy(plaintext + OTT_OFFSET_DATA, data, data_len);
	plain_len = data_len + OTT_MSG_HEADER_SIZE;

	// build message
	if (finalize)
		memcpy(msg, ott_tag_revoked, OTT_TAG_SIZE);
	else
		memcpy(msg, ott_tag, OTT_TAG_SIZE);
	memcpy(msg + OTT_TAG_SIZE, plaintext, plain_len);
	*msg_len = plain_len + OTT_TAG_SIZE ;


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
	
	return(OTT_OK);
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


uint8_t generate_iota_index(IOTA_Index* idx1, IOTA_Index* idx2) {
	int ret;
	if(idx1 == NULL || idx2 == NULL) return OTT_ERR_NULL;
	// generate first random seed
	iota_crypto_randombytes(idx1->berry, SEED_SIZE);
	// generate the first keypair from random 
	iota_crypto_keypair(idx1->berry, &(idx1->keys));
	// first index = HashB2B(PubK1) = second random seed
	if ((ret = address_from_ed25519_pub(idx1->keys.pub, idx1->index)) != 0) return OTT_ERR_CRYPTO_E25519;
	//printf("idx1 index \n"); print_raw_hex(idx1->index, INDEX_SIZE);
	//copy berry DA CONTROLLARE
	memcpy(idx2->berry, idx1->index, SEED_SIZE);
	//printf("idx2 berry \n", idx2->berry);print_raw_hex(idx2->berry, SEED_SIZE);
	// generate the second keypair from second random 
	iota_crypto_keypair(idx2->berry, &(idx2->keys));
	// second index = HashB2B(PubK2)
	if ((ret = address_from_ed25519_pub(idx2->keys.pub, idx2->index)) != 0) return OTT_ERR_CRYPTO_E25519;
	//printf("idx2 index \n");print_raw_hex(idx2->index, INDEX_SIZE);
	return(OTT_OK);
}


uint8_t send_ott_message(OTT_channel* ch, uint8_t* raw_data, uint16_t raw_data_size) {
	int32_t ret = OTT_ERR_SEND;
	res_send_message_t response;
	iota_client_conf_t iota_node;

	if(raw_data_size > OTT_MSG_SIZE) return OTT_ERR_SIZE_EXCEEDED;

	// Convert Data and Index to ASCII-HEX
	bin_2_hex(raw_data, raw_data_size, (char *) (ch->buff_hex_data), IOTA_MAX_MSG_SIZE);
	bin_2_hex(ch->second_index.index, INDEX_SIZE, (char *) (ch->buff_hex_index), INDEX_HEX_SIZE);
	
	// convert IOTA Endpoint
	convert_ott_endpoint(ch->node, &iota_node);
	
	// Init response struct
	memset(&response, 0, sizeof(res_send_message_t));

	// Send
	ret = send_indexation_msg(&iota_node, (char *) (ch->buff_hex_index), (char *) (ch->buff_hex_data), &response);
	if(ret == 0) {
		if (!response.is_error) {
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

void test_write_read_enc_largemsg() {
	OTT_channel ch_send, ch_read;
	uint8_t mylargemsg[DATA_SIZE-14];
	uint8_t read_buff[DATA_SIZE];
	uint16_t expected_size = 2000;
	uint8_t ret = 0;
	
	IOTA_Endpoint testnet0tls = {.hostname = "api.lb-0.h.chrysalis-devnet.iota.cafe\0",
							 .port = 443,
							 .tls = true};

	// write 2 msg
	OTT_write_init_channel(&ch_send, 1, &testnet0tls);
	OTT_write(&ch_send, mylargemsg, DATA_SIZE-14, false);
	fprintf(stdout, "[CH-id=%d] Messages sent: %d (%d bytes)\n", ch_send.id, ch_send.sent_msg, ch_send.sent_bytes);

	// read 2 msg
	OTT_read_init_channel(&ch_read, 1, &testnet0tls);
	set_channel_index_read(&ch_read, ch_send.second_index.index);
	ret = OTT_read(&ch_read, read_buff, &expected_size);
	fprintf(stdout, "OTT_read ret:");
	fprintf(stdout, "\n\t val=%d", ret);
	fprintf(stdout, "\n\t expctsize=%d \t", expected_size);
	fprintf(stdout, "\n\t msg_read=%d \t", ch_read.recv_msg);
	fprintf(stdout, "\n\t bytes_read=%d \t", ch_read.recv_bytes);
	fprintf(stdout, "\n\t cmpbuff=%s \n", (memcmp(mylargemsg, read_buff, DATA_SIZE-14)==0) ? "success" : "failure");
}
