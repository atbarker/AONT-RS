#include "cauchy_rs.h"
#include "aont.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <kcapi.h>
#include <sys/random.h>

#define HASH_SIZE 32 

static int calc_hash(const uint8_t *data, size_t datalen, uint8_t *digest) {
    int ret = 0;
    ret = kcapi_md_sha256(data, datalen, digest, HASH_SIZE);
    return ret;
}


/*
 *Because the Linux kernel crypto API is a place of nightmares
 *
 *Should operate of a 256 bit key to match the hash length
 */
int encrypt_payload(uint8_t *data, const size_t datasize, uint8_t *key, size_t keylength, int enc) {
    struct kcapi_handle *handle;
    struct iovec iov;
    int ret = 0;
    int i;
    uint8_t iv[KEY_SIZE];
    uint8_t *ciphertext = malloc(datasize);

    memset(iv, 0, KEY_SIZE);
    if (enc) {
        kcapi_cipher_enc_aes_cbc(key, keylength, data, datasize, iv, ciphertext, datasize);
    } else {
        kcapi_cipher_dec_aes_cbc(key, keylength, data, datasize, iv, ciphertext, datasize);
    } 

    memcpy(data, ciphertext, datasize);

    return ret;
}

//TODO change sizes here
int encode_aont_package(const uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[KEY_SIZE];
    uint8_t hash[HASH_SIZE];
    cauchy_encoder_params params;
    uint8_t *encode_buffer = malloc(encrypted_payload_size);
    int i = 0;
    int ret = 0;
    
    //TODO Compute canary of the data block (small hash?)
    memset(canary, 0, CANARY_SIZE);
    memcpy(encode_buffer, data, data_length);
    memcpy(encode_buffer, canary, CANARY_SIZE);

    //generate key and IV
    ret = getrandom(key, sizeof(key), 0); 
    encrypt_payload(encode_buffer, cipher_size, key, KEY_SIZE, 1);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    calc_hash(encode_buffer, cipher_size, hash);

    for (i = 0; i < KEY_SIZE; i++) {
        encode_buffer[cipher_size + i] = key[i] ^ hash[i];
    }

    //TODO eliminate these memcpy operations, do everything in place
    for (i = 0; i < data_blocks; i++) {
        memcpy(shares[i], &encode_buffer[rs_block_size * i], rs_block_size);
    }
    
    cauchy_rs_encode(params, shares, &shares[data_blocks]);
    
    free(encode_buffer);
    return 0;
}

int decode_aont_package(uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint8_t *erasures, uint8_t num_erasures){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[KEY_SIZE];
    uint8_t hash[HASH_SIZE];
    cauchy_encoder_params params;
    uint8_t *encode_buffer = malloc(encrypted_payload_size);
    int ret;
    int i;

    memset(canary, 0, CANARY_SIZE);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    ret = cauchy_rs_decode(params, shares, &shares[data_blocks], erasures, num_erasures);

    for(i = 0; i < data_blocks; i++){
        memcpy(&encode_buffer[rs_block_size * i], shares[i], rs_block_size);
    }

    calc_hash(encode_buffer, cipher_size, hash);

    for(i = 0; i < KEY_SIZE; i++){
        key[i] = encode_buffer[cipher_size + i] ^ hash[i];
    }

    encrypt_payload(encode_buffer, cipher_size, key, KEY_SIZE, 0);
    if(memcmp(canary, &encode_buffer[data_length], CANARY_SIZE)){
        return -1;
    }
    memcpy(data, encode_buffer, data_length);

    free(encode_buffer);
    return 0;
}
