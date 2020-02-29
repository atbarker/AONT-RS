#include <linux/random.h>
#include <linux/types.h>

/*
 *Because the Linux kernel interface is a place of nightmares
 *
 *Should operate of a 256 bit key to match the hash length
 */
static int encrypt_payload(uint8_t *data, const size_t datasize, uint8_t key, size_t keylength) {
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    u8 iv[16];  /* AES-256-XTS takes a 16-byte IV */
    //u8 key[64]; /* AES-256-XTS takes a 64-byte key */
    int err;

    /*
     * Allocate a tfm (a transformation object) and set the key.
     *
     * In real-world use, a tfm and key are typically used for many
     * encryption/decryption operations.  But in this example, we'll just do a
     * single encryption operation with it (which is not very efficient).
     */

    tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, sizeof(key));
    if (err) {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        err = -ENOMEM;
        goto out;
    }

    /* Initialize the IV */
    get_random_bytes(iv, sizeof(iv));

    /*
     * Encrypt the data in-place.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
     * crypto_skcipher_decrypt().
     */
    sg_init_one(&sg, data, datasize);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, iv);
    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err) {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

    pr_debug("Encryption was successful\n");
out:
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    kfree(data);
    return err;
}

//TODO change sizes here
int encode_aont_package(uint8_t *data, size_t data_length, size_t data_blocks, size_t parity_blocks){
    uint8_t canary[16];
    uint8_t difference[16];
    size_t cipher_size = data_length + 16;
    size_t encrypted_payload_size = cipher_size + 16;
    size_t rs_block_size = encrypted_payload_size / data_blocks;
    uint8_t key[16];
    uint8_t iv[16];
    cauchy_encoder_params params;
    
    //TODO Compute canary of the data block (small hash?)
    memset(canary, 0, 16);

    //generate key and IV
    //TODO figure out something else for the IV
    get_random_bytes(key, sizeof(key);
    memset(iv, 0, 16);
    
    encrypt_payload(data, encrypted_payload_size, key, 16);

    params.BlockBytes = rs_block_size;
    params.OriginalCount = data_blocks;
    params.RecoveryCount = parity_blocks;
    
    cauchy_rs_encode(params, );
}

uint8_t* decode_aont_package(){

}
