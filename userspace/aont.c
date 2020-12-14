#include "cauchy_rs.h"
#include "aont.h"
#include "speck.h"
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

    if(ciphertext != NULL){
        memcpy(data, ciphertext, datasize);
    }else{
        return -1;
    }

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
    int i = 0;
    int ret = 0;
    uint8_t *plaintext_buffer = NULL;
    uint8_t *ciphertext_buffer = NULL;
    uint64_t nonce[2];

    plaintext_buffer = malloc(encrypted_payload_size);
    if(plaintext_buffer == NULL) return -1;
    ciphertext_buffer = malloc(encrypted_payload_size);
    if(ciphertext_buffer == NULL) return -1;

    nonce[0] = 0;
    nonce[1] = 0;
    
    //TODO Compute canary of the data block (small hash?)
    memset(canary, 0, CANARY_SIZE);
    memcpy(plaintext_buffer, data, data_length);
    memcpy(plaintext_buffer, canary, CANARY_SIZE);

    //generate key and IV
    ret = getrandom(key, sizeof(key), 0);
    //speck_ctr((uint64_t*)plaintext_buffer, (uint64_t*)ciphertext_buffer, cipher_size, (uint64_t*)key, nonce); 
    //encrypt_payload(encode_buffer, cipher_size, key, KEY_SIZE, 1);
    memcpy(ciphertext_buffer, plaintext_buffer, cipher_size);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    calc_hash(ciphertext_buffer, cipher_size, hash);

    for (i = 0; i < KEY_SIZE; i++) {
        ciphertext_buffer[cipher_size + i] = key[i] ^ hash[i];
    }

    //TODO eliminate these memcpy operations, do everything in place
    for (i = 0; i < data_blocks; i++) {
        memcpy(shares[i], &ciphertext_buffer[rs_block_size * i], rs_block_size);
    }
    
    cauchy_rs_encode(params, shares, &shares[data_blocks]);
    
    
    free(plaintext_buffer);
    free(ciphertext_buffer);
    return ret;
}

int decode_aont_package(uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint8_t *erasures, uint8_t num_erasures){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[KEY_SIZE];
    uint8_t hash[HASH_SIZE];
    cauchy_encoder_params params;
    uint8_t *ciphertext_buffer = malloc(encrypted_payload_size);
    uint8_t *plaintext_buffer = malloc(encrypted_payload_size);
    int ret;
    int i;
    uint64_t nonce[2];
    nonce[0] = 0;
    nonce[1] = 1;

    memset(canary, 0, CANARY_SIZE);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    ret = cauchy_rs_decode(params, shares, &shares[data_blocks], erasures, num_erasures);

    for(i = 0; i < data_blocks; i++){
        memcpy(&ciphertext_buffer[rs_block_size * i], shares[i], rs_block_size);
    }

    calc_hash(ciphertext_buffer, cipher_size, hash);

    for(i = 0; i < KEY_SIZE; i++){
        key[i] = ciphertext_buffer[cipher_size + i] ^ hash[i];
    }

    //encrypt_payload(encode_buffer, cipher_size, key, KEY_SIZE, 0);
    //speck_ctr((uint64_t*)ciphertext_buffer, (uint64_t*)plaintext_buffer, cipher_size, (uint64_t*)key, nonce);
    memcpy(plaintext_buffer, ciphertext_buffer, cipher_size);
    
    if(memcmp(canary, &plaintext_buffer[data_length], CANARY_SIZE)){
        return -1;
    }
    memcpy(data, plaintext_buffer, data_length);

    free(ciphertext_buffer);
    free(plaintext_buffer);
    return ret;
}
