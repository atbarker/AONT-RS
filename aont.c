#include <linux/random.h>
#include <linux/types.h>
#include "cauchy_rs.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>


struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};

/* Callback function */
static void test_skcipher_cb(struct crypto_async_request *req, int error)
{
    struct tcrypt_result *result = req->data;

    if (error == -EINPROGRESS)
        return;
    result->err = error;
    complete(&result->completion);
    pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
                     int enc)
{
    int rc = 0;

    if (enc)
        rc = crypto_skcipher_encrypt(sk->req);
    else
        rc = crypto_skcipher_decrypt(sk->req);

    switch (rc) {
    case 0:
        break;
    case -EINPROGRESS:
    case -EBUSY:
        rc = wait_for_completion_interruptible(
            &sk->result.completion);
        if (!rc && !sk->result.err) {
            reinit_completion(&sk->result.completion);
            break;
        }
    default:
        pr_info("skcipher encrypt returned with %d result %d\n",
            rc, sk->result.err);
        break;
    }
    init_completion(&sk->result.completion);

    return rc;
}


//TODO, eliminate memcpy and do things in place
/*
 *Because the Linux kernel interface is a place of nightmares
 *
 *Should operate of a 256 bit key to match the hash length
 */
static int encrypt_payload(uint8_t *data, const size_t datasize, uint8_t *key, size_t keylength, int enc) {
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    uint8_t ivdata[16];
    int ret = -EFAULT;

    skcipher = crypto_alloc_skcipher("cbc-aes-aesni", 0, 0);
    if (IS_ERR(skcipher)) {
        pr_info("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_info("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                      test_skcipher_cb,
                      &sk.result);

    if (crypto_skcipher_setkey(skcipher, key, 32)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    //get_random_bytes(ivdata, 16);
    memset(ivdata, 0, 16);

    sk.tfm = skcipher;
    sk.req = req;

    /* We encrypt one block */
    sg_init_one(&sk.sg, data, datasize);
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, 16, ivdata);
    init_completion(&sk.result.completion);

    /* encrypt data */
    ret = test_skcipher_encdec(&sk, enc);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    return ret;
}

//TODO change sizes here
int encode_aont_package(const uint8_t *data, size_t data_length, uint8_t **carrier_blocks, size_t data_blocks, size_t parity_blocks){
    uint8_t canary[16];
    size_t cipher_size = data_length + 16;
    size_t encrypted_payload_size = cipher_size + 16;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t hash[16];
    cauchy_encoder_params params;
    uint8_t *encode_buffer = kmalloc(encrypted_payload_size, GFP_KERNEL);
    int i = 0;
    
    //TODO Compute canary of the data block (small hash?)
    memset(canary, 0, 16);
    memset(iv, 0, 16);
    memcpy(encode_buffer, data, data_length);
    memcpy(encode_buffer, canary, data_length);

    //generate key and IV
    //TODO figure out something else for the IV
    get_random_bytes(key, sizeof(key)); 
    encrypt_payload(encode_buffer, cipher_size, key, 16, 1);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    //replace this with an actual cryptographic hash of the data and canary
    memset(hash, 0, 16);    

    for (i = 0; i < 16; i++) {
        encode_buffer[cipher_size + i] = key[i] ^ hash[i];
    }

    for (i = 0; i < data_blocks; i++) {
        memcpy(carrier_blocks[i], &encode_buffer[rs_block_size * i], rs_block_size);
    }
    
    cauchy_rs_encode(params, carrier_blocks, &carrier_blocks[data_blocks * rs_block_size]);
    
    kfree(encode_buffer);
    return 0;
}

int decode_aont_package(uint8_t **carrier_blocks, uint8_t *data, size_t data_length, size_t data_blocks, size_t parity_blocks, uint8_t *erasures, uint8_t num_erasures){
    uint8_t canary[16];
    size_t cipher_size = data_length + 16;
    size_t encrypted_payload_size = cipher_size + 16;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[16];
    uint8_t hash[16];
    cauchy_encoder_params params;
    uint8_t *encode_buffer = kmalloc(encrypted_payload_size, GFP_KERNEL);
    int ret;
    int i;

    memset(canary, 0, 16);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;

    ret = cauchy_rs_decode(params, carrier_blocks, &carrier_blocks[data_blocks * rs_block_size], erasures, num_erasures);

    for(i = 0; i < data_blocks; i++){
        memcpy(&encode_buffer[rs_block_size * i], carrier_blocks[i], rs_block_size);
    }

    //TODO hash algorithm here
    memset(hash, 0, 16);

    //Extract key
    for(i = 0; i < 16; i++){
        key[i] = encode_buffer[cipher_size + i] ^ hash[i];
    }

    encrypt_payload(encode_buffer, cipher_size, key, 16, 0);
    if(memcmp(canary, &encode_buffer[data_length], 16)){
        return -1;
    }
    memcpy(data, encode_buffer, data_length);
    kfree(encode_buffer);
    return 0;
}
