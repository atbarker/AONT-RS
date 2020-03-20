/* Austen Barker (2019) */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/types.h>
#include "cauchy_rs.h"
#include "aont.h"
#include "read_file.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AUSTEN BARKER");

//Just do 4MB
#define FILE_SIZE 131072
#define DATA_BLOCK 4096

char* input_file[] = {"/home/austen/linux-4.15.tar.gz"};
char* encrypt_input_file[] = {"/home/austen/Documents/io-cs111-s19.pdf"};
char* output_file[] = {"/home/austen/linux-encoded.txt"};
char* encrypt_output_file[] = {"/home/austen/Documents/io-cs111-s19-encrypted.txt"};

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
    struct timespec timespec1, timespec2;
    uint8_t erasures[0] = {};
    uint8_t num_erasures = 0;
    uint8_t key[32];
    size_t share_size = get_share_size(data_length, data_blocks);
    uint8_t *read_buffer = vmalloc(FILE_SIZE);
    uint8_t *write_buffer = vmalloc((data_blocks + parity_blocks) * share_size);

    uint8_t *encrypt_buffer = vmalloc(FILE_SIZE);

    //get_random_bytes(data, 4096);

    //For this example each share is the size of the original AONT payload
    for(i = 0; i < data_blocks + parity_blocks; i++) shares[i] = kmalloc(share_size, GFP_KERNEL);

    printk(KERN_INFO "Reading data");
    read_file(read_buffer, FILE_SIZE, input_file[0]);
    for(i = 0; i < data_blocks; i++){
        memcpy(shares[i], &read_buffer[i * DATA_BLOCK], DATA_BLOCK);
    }    

    getnstimeofday(&timespec1); 
    encode_aont_package(data, data_length, shares, data_blocks, parity_blocks);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Encode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    for(i = 0; i < data_blocks + parity_blocks; i++){
        memcpy(&write_buffer[i * share_size], shares[i], share_size);
    }
    write_file(write_buffer, share_size, output_file[0]);

    getnstimeofday(&timespec1);
    decode_aont_package(data, data_length, shares, data_blocks, parity_blocks, erasures, num_erasures);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Decode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    /*read_file(encrypt_buffer, FILE_SIZE, encrypt_input_file[0]);
    get_random_bytes(key, 32);
    for(i = 0; i < data_blocks; i++){
        encrypt_payload(encrypt_buffer[i * DATA_BLOCK], DATA_BLOCK, key, 32, 1);
    }
    write_file(encrypt_buffer, FILE_SIZE, encrypt_output_file[0]);
    */

    kfree(data);
    kfree(shares);
    vfree(read_buffer);
    vfree(write_buffer);
    vfree(encrypt_buffer);
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
