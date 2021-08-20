/* Austen Barker (2019) */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/fs.h>
#include "cauchy_rs.h"
#include "aont.h"
#include "speck.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AUSTEN BARKER");

//Just do 4MB
#define DATA_BLOCK 4096
#define FILE_SIZE 32768

/**
 * Helper function for opening a file in the kernel
 */
struct file* file_open(char* path, int flags, int rights){
    struct file *filp = NULL;
    filp = filp_open(path, flags, rights);
    return filp;
}

/**
 * Closing a file in the kernel
 */
void file_close(struct file* file){
    filp_close(file, NULL);
}

static int read_file(uint8_t *data, size_t data_size, char* path){
    struct file* file = NULL;
    int ret = 0;
    loff_t offset = 0;
    
    file = file_open(path, O_RDONLY, 0);
    ret = kernel_read(file, data, data_size, &offset);
    if (ret < 0){
        printk(KERN_INFO "Kernel Read Failed: %d\n", ret);
    }
    file_close(file);
    return ret;
}

static int write_file(uint8_t *data, size_t data_size, char* path){
    struct file* file = NULL;
    int ret = 0;
    loff_t offset = 0;

    file = file_open(path, O_CREAT|O_WRONLY, 0);
    ret = kernel_write(file, data, data_size, &offset);
    if (ret < 0){
        printk(KERN_INFO "Kernel Read Failed: %d\n", ret);
    }
    file_close(file);
    return ret;
}

static int test_aont(void){
    uint8_t *data = kmalloc(DATA_BLOCK, GFP_KERNEL);
    size_t data_blocks = 32;
    size_t parity_blocks = 32;
    size_t data_length = DATA_BLOCK;
    uint8_t **shares = kmalloc(sizeof(uint8_t*) * (data_blocks + parity_blocks), GFP_KERNEL);
    int i = 0;
    struct timespec64 timespec1, timespec2;
    uint8_t erasures[0] = {};
    uint8_t num_erasures = 0;
    size_t share_size = get_share_size(data_length, data_blocks);
    uint64_t nonce[2] = {0, 0};
    uint8_t difference[32];


    get_random_bytes(data, 4096);

    //For this example each share is the size of the original AONT payload
    for(i = 0; i < data_blocks + parity_blocks; i++) shares[i] = kmalloc(share_size, GFP_KERNEL);

    ktime_get_real_ts64(&timespec1); 
    encode_aont_package(difference, data, data_length, shares, data_blocks, parity_blocks, nonce);
    ktime_get_real_ts64(&timespec2);
    printk(KERN_INFO "Encode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    ktime_get_real_ts64(&timespec1);
    decode_aont_package(difference, data, data_length, shares, data_blocks, parity_blocks, nonce, erasures, num_erasures);
    ktime_get_real_ts64(&timespec2);
    printk(KERN_INFO "Decode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    kfree(data);
    kfree(shares);
    return 0; 
}

int test_aont_v_enc(void){
    char* input_file[] = {"/home/austen/AONT-RS/cauchy_rs.c"};
    char* output_file[] = {"/home/encoded.txt"};
    char* output_encrypted_file[] = {"/home/austen/encrypted.txt"};
    size_t data_blocks = 1;
    size_t parity_blocks = 2;
    size_t data_length = DATA_BLOCK;
    uint8_t **shares = kmalloc(sizeof(uint8_t*) * (data_blocks + parity_blocks), GFP_KERNEL);
    int i = 0, j = 0;
    uint64_t key[4];
    uint8_t total_shares = 0;
    size_t share_size = get_share_size(data_length, data_blocks);
    uint8_t *read_buffer = kmalloc(FILE_SIZE, GFP_KERNEL);
    uint8_t *write_buffer = kmalloc((data_blocks + parity_blocks) * share_size * (FILE_SIZE / DATA_BLOCK), GFP_KERNEL);
    uint8_t iv[32];
    uint64_t nonce[2] = {0, 0};
    uint8_t difference[32];

    for(i = 0; i < data_blocks + parity_blocks; i++) shares[i] = kmalloc(share_size, GFP_KERNEL);


    read_file(read_buffer, FILE_SIZE, input_file[0]);

    for(i = 0; i < FILE_SIZE/DATA_BLOCK; i++) {
        encode_aont_package(difference, &read_buffer[i * DATA_BLOCK], data_length, shares, data_blocks, parity_blocks, nonce);
        for(j = 0; j < data_blocks + parity_blocks; j++){
            memcpy(&write_buffer[total_shares * share_size], shares[j], share_size);
            total_shares++;
        }
    }

    write_file(write_buffer, (data_blocks + parity_blocks)* share_size * (FILE_SIZE / DATA_BLOCK), output_file[0]);

    get_random_bytes(key, 32);
    memset(iv, 0, 32);
    for(i = 0; i < FILE_SIZE / DATA_BLOCK; i++){
	speck_ctr((uint64_t*)&read_buffer[i * DATA_BLOCK], (uint64_t*)&write_buffer[i * DATA_BLOCK], DATA_BLOCK, key, nonce);
	//encrypt_payload(&read_buffer[i*DATA_BLOCK], DATA_BLOCK, key, 32, 1);
        //memcpy(&write_buffer[i * DATA_BLOCK], &read_buffer[i*DATA_BLOCK], DATA_BLOCK);
    }

    write_file(write_buffer, FILE_SIZE, output_encrypted_file[0]);

    kfree(read_buffer);
    kfree(write_buffer);
    kfree(shares);
    return 0;
}

static int __init km_template_init(void){
    test_aont();
    printk(KERN_INFO "Kernel Module inserted");
    return 0;
}

static void __exit km_template_exit(void){
    printk(KERN_INFO "Removing kernel module\n");
}

module_init(km_template_init);
module_exit(km_template_exit);
