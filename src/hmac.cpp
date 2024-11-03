#include "sha256.h"
#include "common.h"
#include "hmac.h"

/*
    Output:
        Pointer to tag
        HMAC_OUTPUT_LEN_BYTES = 32
*/
uint8_t* hmac_sha256(const uint8_t* key, size_t key_len_byte, const uint8_t* message, size_t message_len_byte) 
{
    uint8_t *tag = new uint8_t[HMAC_OUTPUT_LEN_BYTES];   
    /* Your code Here! */
    uint8_t opad[BLOCK_SIZE];
    uint8_t ipad[BLOCK_SIZE];

    for (int i = 0; i < BLOCK_SIZE; ++i) {
        opad[i] = 0x5c;
        ipad[i] = 0x36;
    }

    uint8_t *key_block= new uint8_t[BLOCK_SIZE];
    if (key_len_byte > BLOCK_SIZE){
        uint8_t *hashed_result = sha_256(key, key_len_byte);
        memcpy(key_block,hashed_result,HMAC_OUTPUT_LEN_BYTES);
        delete[] hashed_result;
        memset(key_block+HMAC_OUTPUT_LEN_BYTES,0,BLOCK_SIZE-HMAC_OUTPUT_LEN_BYTES);
    } 
    else {
        memcpy(key_block, key, key_len_byte);
        memset(key_block + key_len_byte, 0, BLOCK_SIZE - key_len_byte);
    }

    
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        opad[i] ^= key_block[i];
        ipad[i] ^= key_block[i];
    }
    delete[] key_block;
    
    uint8_t *inner_data=new uint8_t[BLOCK_SIZE + message_len_byte];
    memcpy(inner_data, ipad, BLOCK_SIZE);
    memcpy(inner_data + BLOCK_SIZE, message, message_len_byte);
    uint8_t *inner_hash = sha_256(inner_data, 0ll+BLOCK_SIZE + message_len_byte);
    
    delete[] inner_data;
    
    uint8_t *outer_data=new uint8_t[BLOCK_SIZE + HMAC_OUTPUT_LEN_BYTES];
    memcpy(outer_data, opad, BLOCK_SIZE);
    memcpy(outer_data + BLOCK_SIZE, inner_hash, HMAC_OUTPUT_LEN_BYTES);
    
    delete[] inner_hash;
    tag = sha_256(outer_data, 0ll+BLOCK_SIZE + HMAC_OUTPUT_LEN_BYTES);
    delete[] outer_data;
    
    return tag;
}
