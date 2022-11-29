#include "OTT.h"

/* 
OTT_channel* wam_channel_alloc() {
	return (OTT_channel*)calloc(1, sizeof(WAM_channel));
}

IOTA_Endpoint* wam_iota_ep_alloc() {
	return (IOTA_Endpoint*)calloc(1, sizeof(IOTA_Endpoint));
}

void wam_free(void* p) {
	free(p);
}

  /// Enpoint 
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

 */
