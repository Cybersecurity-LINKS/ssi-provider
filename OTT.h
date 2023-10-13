/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OTT_H
#define OTT_H

#include <stdint.h>
#include "OTT_def.h"

/* --------------------------------------------------------------------- */
/* -### PROTOTYPES ###- */
/* --------------------------------------------------------------------- */

uint8_t OTT_write_init_channel(OTT_channel* channel, uint16_t id, IOTA_Endpoint* endpoint);
uint8_t OTT_read_init_channel(OTT_channel* channel, uint16_t id, char * msg_id, IOTA_Endpoint* endpoint);
uint8_t OTT_write(OTT_channel* channel, uint8_t* inData, uint16_t inDataSize, char * msg_id, bool finalize);
uint8_t OTT_read(OTT_channel* channel, uint8_t* outData, uint16_t *outDataSize);
uint8_t set_channel_index_read(OTT_channel* channel, uint8_t* start_index_bin);
uint8_t copy_iota_index(IOTA_Index* dstIndex, IOTA_Index* srcIndex);
void dummy_print(uint8_t* str_hello);
void test_write_read_enc_largemsg();

#endif