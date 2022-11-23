#include "WAM.h"

/*
//#include <stdlib.h>
//#include <stddef.h>
//#include <stdbool.h>
//#include "WAM.h"
uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint, WAM_Key* PSK, WAM_AuthCtx* auth);
uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint16_t inDataSize, bool finalize);
uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint16_t *outDataSize);
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);
void dummy_print(uint8_t* str_hello);
*/

WAM_channel* wam_channel_alloc() {
	return (WAM_channel*)calloc(1, sizeof(WAM_channel));
}

IOTA_Endpoint* wam_iota_ep_alloc() {
	return (IOTA_Endpoint*)calloc(1, sizeof(IOTA_Endpoint));
}

WAM_Key* wam_key_alloc() {
	return (WAM_Key*)calloc(1, sizeof(WAM_Key));
}

WAM_AuthCtx* wam_authctx_alloc() {
	return (WAM_AuthCtx*)calloc(1, sizeof(WAM_AuthCtx));
}

void wam_free(void* p) {
	free(p);
}



/* Key */
void wam_key_set_data(WAM_Key* k, unsigned int data_size, unsigned char* data) {
	k->data_len = (uint16_t)data_size;
	k->data = data;
}

unsigned char* wam_key_get_data(WAM_Key* k) {
	return k->data;
}

unsigned int wam_key_get_data_size(WAM_Key* k) {
	return (unsigned int)k->data_len;
}



/* AuthCtx */
void wam_auth_set_data(WAM_AuthCtx* a, unsigned int authtype, unsigned int data_size, unsigned char* data) {
	a->type = (uint8_t)authtype;   // !!!!!!
	a->data_len = (uint16_t)data_size;
	a->data = data;
}



/* Enpoint */
void wam_endpoint_set(IOTA_Endpoint* ep, unsigned int name_size, unsigned char* name, unsigned int port_no, bool secure) {
	if (name_size > ENDPTNAME_SIZE)
		name_size = ENDPTNAME_SIZE;
	ep->port = (uint16_t)port_no;
	ep->tls = secure;
	memcpy(ep->hostname, name, name_size);
}


void wam_channel_get_read_idx(WAM_channel* channel, unsigned char* outIdx_bin) {
	memcpy(outIdx_bin, channel->read_idx, INDEX_SIZE);
}

// TODO: modify func name in WAM.c to avoid this wrapper in late refactoring
void wam_channel_set_read_idx(WAM_channel* channel, unsigned char* idx_bin_start_read) {
	memcpy(channel->read_idx, idx_bin_start_read, INDEX_SIZE);
	//set_channel_current_index(channel, idx_bin_start_read);
}

void wam_channel_get_write_curr_idx(WAM_channel* channel, unsigned char* outIdx_bin) {
	memcpy(outIdx_bin, channel->current_index.index, INDEX_SIZE);
}

void wam_channel_get_write_start_idx(WAM_channel* channel, unsigned char* outIdx_bin) {
	memcpy(outIdx_bin, channel->start_index.index, INDEX_SIZE);
}

void wam_channel_get_write_next_idx(WAM_channel* channel, unsigned char* outIdx_bin) {
	memcpy(outIdx_bin, channel->next_index.index, INDEX_SIZE);
}

