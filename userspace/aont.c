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
    ret = kcapi_md_sha256(data, datalen, digest, 32);
    return ret;
}

void hexdump (const char * desc, const void * addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;

    // Output description if given.

    if (desc != NULL)
        printf ("%s:\n", desc);

    // Length checks.

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }

    // Process every byte in the data.

    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.

            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.

            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And buffer a printable ASCII character for later.

        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII buffer.

    printf ("  %s\n", buff);
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
int encode_aont_package(const uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint64_t *nonce){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint64_t key[4];
    uint64_t hash[4];
    uint64_t difference[4];
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

    calc_hash(ciphertext_buffer, cipher_size, (uint8_t*)hash);

    for (i = 0; i < 4; i++) {
        difference[i] = key[i] ^ hash[i];
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

int decode_aont_package(uint8_t *data, size_t data_length, uint8_t **shares, size_t data_blocks, size_t parity_blocks, uint64_t *nonce, uint8_t *erasures, uint8_t num_erasures){
    uint8_t canary[CANARY_SIZE];
    size_t cipher_size = data_length + CANARY_SIZE;
    size_t encrypted_payload_size = cipher_size + KEY_SIZE;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint64_t key[4];
    uint64_t hash[4];
    uint64_t difference[4];
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

    calc_hash(ciphertext_buffer, cipher_size, (uint8_t*)hash);

    memcpy(difference, &ciphertext_buffer[cipher_size], KEY_SIZE);

    for(i = 0; i < 4; i++){
        key[i] = difference[i] ^ hash[i];
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
