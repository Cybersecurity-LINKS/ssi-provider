#ifndef WAM_H
#define WAM_H



#include <stdint.h>
#include "WAM_def.h"



/* --------------------------------------------------------------------- */
/* -### PROTOTYPES ###- */
/* --------------------------------------------------------------------- */

uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint);
uint8_t WAM_write(WAM_channel* channel, uint8_t* inData, uint16_t inDataSize, bool finalize);
uint8_t WAM_read(WAM_channel* channel, uint8_t* outData, uint16_t *outDataSize);
uint8_t set_channel_index_read(WAM_channel* channel, uint8_t* start_index_bin);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
void dummy_print(uint8_t* str_hello);
void test_write_read_enc_largemsg();

/* uint8_t WAM_init_channel(WAM_channel* channel, uint16_t id, IOTA_Endpoint* endpoint);
uint8_t WAM_write(WAM_channel *channel, uint8_t *data, uint16_t data_size, uint8_t *authkey);
uint8_t WAM_read(WAM_channel* channel, uint8_t* pub_authkey);
uint8_t set_channel_hex_index(WAM_channel* channel, char* index);
uint8_t meta(WAM_channel* channel, char* msg_id); */


#endif