#ifndef WAM_DEF_H
#define WAM_DEF_H



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
#define AUTH_SIZE             (64)   // =2*STSAFEA_XYRS_ECDSA_SHA256_LENGTH

// Utils
#define SEED_SIZE             (32)   // =IOTA_SEED_BYTES, =ED25519_ADDRESS_BYTES
#define PRIK_SIZE             (64)   // =ED_PRIVATE_KEY_BYTES
#define PSK_SIZE              (32)   // =crypto_secretbox_KEYBYTES
#define NONCE_SIZE            (24)   // =crypto_secretbox_NONCEBYTES
#define ENCMAC_SIZE           (16)   // =crypto_secretbox_MACBYTES
#define WAM_TAG_SIZE          (32)   // =customizable

#define BLAKE2B_HASH_SIZE     (32)   // =CRYPTO_BLAKE2B_HASH_BYTES

// Message
#define WAM_MSG_HEADER_SIZE       (INDEX_SIZE + PUBK_SIZE + SIGN_SIZE + AUTH_SIZE + DLEN_SIZE)
#define WAM_MSG_PLAIN_SIZE        (WAM_MSG_HEADER_SIZE + DATA_SIZE)
#define WAM_MSG_CIPH_SIZE         (WAM_MSG_PLAIN_SIZE + ENCMAC_SIZE)
#define WAM_MSG_SIZE              (WAM_MSG_CIPH_SIZE + NONCE_SIZE + WAM_TAG_SIZE)

/* #define WAM_MSG_ENCRYPTED_SIZE    (WAM_MSG_HEADER_SIZE + DATA_SIZE + ENCMAC_SIZE + NONCE_SIZE)
#define WAM_MSG_SIZE          (INDEX_SIZE + PUBK_SIZE + SIGN_SIZE + AUTH_SIZE + DLEN_SIZE + DATA_SIZE)
#define WAM_MSG_ENC_SIZE      (WAM_MSG_SIZE + ENCMAC_SIZE)
#define XXXX                  (MSG_ENC_SIZE + NONCE_SIZE)
#define YYYY                  (XXXX + WAM_TAG_SIZE) */

// Others
#define INDEX_HEX_SIZE           (1 + 2 * INDEX_SIZE)
#define MSGID_HEX_SIZE           (64)   // =IOTA_MESSAGE_ID_HEX_BYTES
#define ENDPTNAME_SIZE           (64)   // =0.25*IOTA_ENDPOINT_MAX_LEN
#define WAM_MSG_HEX_SIZE         (1 + 2 * WAM_MSG_SIZE)





/* --------------------------------------------------------------------- */
/* -### ERRORS ###- */
/* --------------------------------------------------------------------- */
enum {
	WAM_OK = 0,
    WAM_BROKEN_MESSAGE = 0x33,
	WAM_NOT_FOUND = 0x44,
	WAM_BUFF_FULL = 0x55,
	WAM_NO_MESSAGES = 0xE3,

	WAM_ERR_CH_INIT = 0xF1,
	WAM_ERR_NULL = 0xF2,
	WAM_ERR_SIZE_EXCEEDED = 0xF3,
	WAM_ERR_MAX_RETRY_EXCEEDED = 0xF4,
	WAM_ERR_SEND = 0xF5,
	WAM_ERR_SEND_API = 0xF6,
	WAM_ERR_RECV = 0xF7,
	WAM_ERR_RECV_API = 0xF8,
	WAM_ERR_RECV_MANYMSG = 0xF9,
	WAM_ERR_CRYPTO_ENC = 0xFA,
	WAM_ERR_CRYPTO_DEC = 0xFB,
	WAM_ERR_CRYPTO_MAC = 0xFC,
	WAM_ERR_CRYPTO_VERSIGN = 0xFD,
	WAM_ERR_CRYPTO_VERAUTHSIGN = 0xFE,
	WAM_ERR_CRYPTO_OWNERSHIP = 0xFF,
};


enum {
	WAM_OFFSET_DLEN = 0,     // + 2 (DLEN_SIZE)
	WAM_OFFSET_PUBK = 2,     // +32 (PUBK_SIZE)
	WAM_OFFSET_NIDX = 34,    // +32 (INDEX_SIZE)
	WAM_OFFSET_AUTH = 66,    // +64 (AUTH_SIZE)
	WAM_OFFSET_SIGN = 130,   // +64 (SIGN_SIZE)
	WAM_OFFSET_DATA = 194,
};


/* --------------------------------------------------------------------- */
/* -### CONST ###- */
/* --------------------------------------------------------------------- */
#define WAM_PSK "AC88DFA4DEAAE33E0135DFF4A6BB678FA7FFDC10869ADC6E6D38DDCBC90CAC88"
#define WAM_MAX_RETRY     (5)

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


typedef enum {AUTHS_KEY, AUTHS_NONE} AuthType;

typedef struct WAM_AuthCtx_t {
	uint8_t* data;         // Key data
	uint16_t data_len;     // Key lenght
	AuthType type;
} WAM_AuthCtx;

typedef struct WAM_Key_t {
	uint8_t *data;
	uint16_t data_len;
} WAM_Key;


typedef struct WAM_channel_t {
	uint16_t id;
	
	IOTA_Endpoint* node;

	IOTA_Index start_index;
	IOTA_Index current_index;
	IOTA_Index next_index;
	
	uint8_t read_idx[INDEX_SIZE];

	WAM_Key *PSK;
	WAM_AuthCtx *auth;
    
	uint16_t sent_msg;
	uint16_t recv_msg;
	uint16_t sent_bytes;
	uint16_t recv_bytes;

    uint8_t buff_hex_data[IOTA_MAX_MSG_SIZE];
    uint8_t buff_hex_index[INDEX_HEX_SIZE];
} WAM_channel;


#endif