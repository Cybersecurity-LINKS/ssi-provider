#ifndef OTT_H
#define OTT_H



#include <stdint.h>
#include "OTT_def.h"



/* --------------------------------------------------------------------- */
/* -### PROTOTYPES ###- */
/* --------------------------------------------------------------------- */

uint8_t OTT_write_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint);
uint8_t OTT_read_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint);
uint8_t OTT_write(OTT_channel* channel, uint8_t* inData, uint16_t inDataSize, bool finalize);
uint8_t OTT_read(OTT_channel* channel, uint8_t* outData, uint16_t *outDataSize);
uint8_t set_channel_index_read(OTT_channel* channel, uint8_t* start_index_bin);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
void dummy_print(uint8_t* str_hello);
void test_write_read_enc_largemsg();

#endif