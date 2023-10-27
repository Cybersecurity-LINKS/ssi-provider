/*
 * Copyright 2023 Fondazione Links. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef OTT_PRIMITIVES_H
#define OTT_PRIMITIVES_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include "sodium.h"
#include "core/address.h"
#include "crypto/iota_crypto.h"
#include "core/utils/byte_buffer.h"
#include "client/api/v1/send_message.h"
#include "client/api/v1/get_message.h"
#include "client/api/v1/find_message.h"
#include "client/client_service.h"



/* --------------------------------------------------------------------- */
/* -### MACROS ###- */
/* --------------------------------------------------------------------- */
#define _SET512(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 64); }while(0)
#define _SET256(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 32); }while(0)
#define _SET128(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 16); }while(0)
#define _SET64(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 8); }while(0)
#define _SET32(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 4); }while(0)
#define _SET16(x, pos, val) do{ memcpy(((uint8_t*)(x))+pos, (void*)&(val), 2); }while(0)
#define _GET512(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 64); }while(0)
#define _GET256(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 32); }while(0)
#define _GET128(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 16); }while(0)
#define _GET64(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 8); }while(0)
#define _GET32(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 4); }while(0)
#define _GET16(x, pos, val) do{ memcpy((void*)&(val), ((uint8_t*)(x))+pos, 2); }while(0)



/* --------------------------------------------------------------------- */
/* -### SIZES ###- */
/* --------------------------------------------------------------------- */
#define IOTA_MAX_MSG_SIZE    (31777)

// Fields
#define DATA_SIZE            (3000)   // =customizable (MUST BE < IOTA_MAX_MSG_SIZE)
#define DLEN_SIZE              (2)   // =sizeof(uint16_t)
#define INDEX_SIZE            (32)   // =ED25519_ADDRESS_BYTES
#define PUBK_SIZE             (32)   // =ED_PUBLIC_KEY_BYTES
#define SIGN_SIZE             (64)   // =ED_SIGNATURE_BYTES

// Utils
#define SEED_SIZE             (32)   // =IOTA_SEED_BYTES, =ED25519_ADDRESS_BYTES
#define PRIK_SIZE             (64)   // =ED_PRIVATE_KEY_BYTES
#define ENCMAC_SIZE           (16)   // =crypto_secretbox_MACBYTES
#define OTT_TAG_SIZE          (32)   // =customizable
#define OTT_ANCHOR_SIZE       (32)   // ==SEED_SIZE, =ED25519_ADDRESS_BYTES
#define BLAKE2B_HASH_SIZE     (32)   // =CRYPTO_BLAKE2B_HASH_BYTES

// Message
#define OTT_RVK_MSG_HEADER_SIZE         (INDEX_SIZE + PUBK_SIZE + SIGN_SIZE  + DLEN_SIZE)
#define OTT_CREATE_MSG_HEADER_SIZE      (INDEX_SIZE + PUBK_SIZE + SIGN_SIZE  + DLEN_SIZE + OTT_ANCHOR_SIZE)
#define OTT_RVK_MSG_PLAIN_SIZE        	(OTT_RVK_MSG_HEADER_SIZE + DATA_SIZE)
#define OTT_CREATE_MSG_PLAIN_SIZE       (OTT_CREATE_MSG_HEADER_SIZE + DATA_SIZE)
#define OTT_RVK_MSG_SIZE              	(OTT_RVK_MSG_PLAIN_SIZE + OTT_TAG_SIZE)
#define OTT_CREATE_MSG_SIZE             (OTT_CREATE_MSG_PLAIN_SIZE + OTT_TAG_SIZE)

// Others
#define INDEX_HEX_SIZE           (1 + 2 * INDEX_SIZE)
#define MSGID_HEX_SIZE           (64)   // =IOTA_MESSAGE_ID_HEX_BYTES
#define ENDPTNAME_SIZE           (64)   // =0.25*IOTA_ENDPOINT_MAX_LEN
#define OTT_MSG_HEX_SIZE         (1 + 2 * OTT_CREATE_MSG_SIZE)





/* --------------------------------------------------------------------- */
/* -### ERRORS ###- */
/* --------------------------------------------------------------------- */
enum {
	OTT_REVOKE = 1,
	OTT_OK = 0,
    OTT_BROKEN_MESSAGE = 0x33,
	OTT_NOT_FOUND = 0x44,
	OTT_BUFF_FULL = 0x55,
	OTT_NO_MESSAGES = 0xE3,

	OTT_ERR_CH_INIT = 0xF1,
	OTT_ERR_NULL = 0xF2,
	OTT_ERR_SIZE_EXCEEDED = 0xF3,
	OTT_ERR_MAX_RETRY_EXCEEDED = 0xF4,
	OTT_ERR_SEND = 0xF5,
	OTT_ERR_SEND_API = 0xF6,
	OTT_ERR_RECV = 0xF7,
	OTT_ERR_RECV_API = 0xF8,
	OTT_ERR_RECV_MANYMSG = 0xF9,
	OTT_ERR_CRYPTO_E25519 = 0xFA,
	OTT_ERR_CRYPTO_DEC = 0xFB,
	OTT_ERR_CRYPTO_MAC = 0xFC,
	OTT_ERR_CRYPTO_VERSIGN = 0xFD,
	OTT_ERR_CRYPTO_VERAUTHSIGN = 0xFE,
	OTT_ERR_CRYPTO_OWNERSHIP = 0xFF,
	OTT_ERR_CRYPTO_BLACKE2B = 0x100,
	OTT_ERR_CRYPTO_SIGN = 0x101
};

/* enum {
	OTT_OFFSET_DLEN = 0,     // + 2 (DLEN_SIZE)
	OTT_OFFSET_PUBK = 2,     // +32 (PUBK_SIZE)
	OTT_OFFSET_SIGN = 34,    // +64 (SIGN_SIZE)
	OTT_OFFSET_DATA = 98,
};
 */
enum {
	//Revoke MSG offesets
	OTT_RVK_OFFSET_DLEN = 0,     // + 2 (DLEN_SIZE)
	OTT_RVK_OFFSET_PUBK = 2,     // +32 (PUBK_SIZE)
	OTT_RVK_OFFSET_SIGN = 34,    // +64 (SIGN_SIZE)
	OTT_RVK_OFFSET_DATA = 98,
	//OTT MSG offesets
	OTT_MSG_OFFSET_DLEN = 0,     // + 2 (DLEN_SIZE)
	OTT_MSG_OFFSET_PUBK = 2,     // +32 (PUBK_SIZE)
	OTT_MSG_OFFSET_ANCHOR = 34,  // +32 (BLAKE2B_HASH_SIZE)
	OTT_MSG_OFFSET_SIGN = 66,    // +64 (SIGN_SIZE)
	OTT_MSG_OFFSET_DATA = 130,
};

/* --------------------------------------------------------------------- */
/* -### CONST ###- */
/* --------------------------------------------------------------------- */

#define OTT_MAX_RETRY     (5)

#define DEVNET00_HOSTNAME     "api.lb-0.h.chrysalis-devnet.iota.cafe\0"
#define DEVNET00_PORT         (443)
#define DEVNET00_USETLS       (true)

#define DEVNET01_HOSTNAME     "api.lb-1.h.chrysalis-devnet.iota.cafe\0"
#define DEVNET01_PORT         (443)
#define DEVNET01_USETLS       (true)

#define MAINNET00_HOSTNAME    "chrysalis-nodes.iota.org\0"
#define MAINNET00_PORT        (443)
#define MAINNET00_USETLS      (true)

#define MAINNET01_HOSTNAME    "chrysalis-nodes.iota.cafe\0"
#define MAINNET01_PORT        (443)
#define MAINNET01_USETLS      (true)





/* --------------------------------------------------------------------- */
/* -### STRUCTS ###- */
/* --------------------------------------------------------------------- */

typedef struct IOTA_Endpoint_t {
	char hostname[ENDPTNAME_SIZE];
	uint16_t port;
	bool tls;
} IOTA_Endpoint;


typedef struct IOTA_index_t {
	uint8_t index[INDEX_SIZE];
	uint8_t berry[SEED_SIZE];   // random
	iota_keypair_t keys;        // keypair generated from berry
} IOTA_Index;

/* typedef struct OTT_Key_t {
	uint8_t *data;
	uint16_t data_len;
} OTT_Key;
 */

typedef struct OTT_channel_t {
	uint16_t id;
	
	IOTA_Endpoint* node;
	
	uint8_t index[INDEX_SIZE];
	uint8_t anchor[INDEX_SIZE];

	iota_keypair_t keys1; //Create msg
	iota_keypair_t keys2; //Revoke msg

	uint8_t read_idx[INDEX_SIZE];
	int number_ott_msg; // 1 only create, 2+ probably revoke too so save data
	int revoked; //used in the read
	int valid_msg_found;
	uint16_t sent_msg;
	uint16_t recv_msg;
	uint16_t sent_bytes;
	uint16_t recv_bytes;

	char * msg_id;

    uint8_t buff_hex_data[IOTA_MAX_MSG_SIZE];
    uint8_t buff_hex_index[INDEX_HEX_SIZE];
} OTT_channel;


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