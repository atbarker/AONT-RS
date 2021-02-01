#include "cauchy_rs.h"
#include "aont.h"
#include "speck.h"
#include "sha3.c"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/random.h>

#define HASH_SIZE 32 

//TODO change sizes here
int encode_aont_package(uint8_t *difference, const uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint64_t *nonce){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint64_t key[4];
    uint64_t hash[4];
    //uint64_t difference[4];
    cauchy_encoder_params params;
    int i = 0;
    int ret = 0;
    uint8_t *plaintext_buffer = NULL;
    uint8_t *ciphertext_buffer = NULL;

    plaintext_buffer = malloc(encrypted_payload_size);
    if(plaintext_buffer == NULL) return -1;
    ciphertext_buffer = malloc(encrypted_payload_size);
    if(ciphertext_buffer == NULL) return -1;

    //TODO Compute canary of the data block (small hash?)
    memset(canary, 0, CANARY_SIZE);
    memcpy(plaintext_buffer, data, data_length);
    memcpy(&plaintext_buffer[data_length], canary, CANARY_SIZE);
    
    //generate key and IV
    ret = getrandom(key, KEY_SIZE, 0);

    speck_ctr((uint64_t*)plaintext_buffer, (uint64_t*)ciphertext_buffer, cipher_size, key, nonce);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    sha3_256(ciphertext_buffer, cipher_size, (uint8_t*)hash);

    for (i = 0; i < 4; i++) {
        ((uint64_t*)difference)[i] = key[i] ^ hash[i];
    }

    memcpy(&ciphertext_buffer[cipher_size], difference, KEY_SIZE);

    //TODO eliminate these memcpy operations, do everything in place
    for (i = 0; i < data_blocks; i++) {
        memcpy(shares[i], &ciphertext_buffer[rs_block_size * i], rs_block_size);
    }
    
    cauchy_rs_encode(params, shares, &shares[data_blocks]);
    
    free(plaintext_buffer);
    free(ciphertext_buffer);
    return ret;
}

int decode_aont_package(uint8_t *difference, uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint64_t *nonce, uint8_t *erasures, uint8_t num_erasures){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint64_t key[4];
    uint64_t hash[4];
    //uint64_t difference[4];
    cauchy_encoder_params params;
    uint8_t *ciphertext_buffer = NULL;
    uint8_t *plaintext_buffer = NULL;
    int ret = 0;
    int i = 0;

    plaintext_buffer = malloc(encrypted_payload_size);
    if(plaintext_buffer == NULL) return -1;
    ciphertext_buffer = malloc(encrypted_payload_size);
    if(ciphertext_buffer == NULL) return -1;

    memset(canary, 0, CANARY_SIZE);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    ret = cauchy_rs_decode(params, shares, &shares[data_blocks], erasures, num_erasures);

    for(i = 0; i < data_blocks; i++){
        memcpy(&ciphertext_buffer[rs_block_size * i], shares[i], rs_block_size);
    }

    sha3_256(ciphertext_buffer, cipher_size, (uint8_t*)hash);

    memcpy(difference, &ciphertext_buffer[cipher_size], KEY_SIZE);

    for(i = 0; i < 4; i++){
        key[i] = ((uint64_t*)difference)[i] ^ hash[i];
    }

    speck_ctr((uint64_t*)ciphertext_buffer, (uint64_t*)plaintext_buffer, cipher_size, key, nonce);
    
    if(memcmp(canary, &plaintext_buffer[data_length], CANARY_SIZE)){
        return -1;
    }
    memcpy(data, plaintext_buffer, data_length);

    free(ciphertext_buffer);
    free(plaintext_buffer);
    return ret;
}
