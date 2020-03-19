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
#define FILE_SIZE 4194303

char* input_file[] = {"/home/austen/Documents/course-cs111-s19.pdf"};
char* encrypt_input_file[] = {"/home/austen/Documents/io-cs111-s19.pdf"};
char* output_file[] = {"/home/austen/Documents/course-cs111-s19-encoded.txt"};
char* encrypt_output_file[] = {"/home/austen/Documents/io-cs111-s19-encrypted.txt"};

static int read_file(uint8_t **data, size_t data_blocks, char* path){
    struct file* file = NULL;
    int ret = 0;
    int i;
    loff_t offset = 0;
    
    file = file_open(path, O_RDONLY, 0);
    for(i = 0; i < data_blocks; i++){
	offset = i * 4096;
        ret = kernel_read(file, data[i], 4096, &offset);
    }
    if (ret < 0){
        printk(KERN_INFO "Kernel Read Failed: %d\n", ret);
    }
    file_close(file);
    return ret;
}

static int write_file(uint8_t **data, size_t data_blocks, size_t share_size, char* path){
    struct file* file = NULL;
    int ret = 0;
    int i;
    loff_t offset = 0;

    file = file_open(path, O_CREAT|O_WRONLY|O_TRUNC, 0);
    for(i = 0; i < data_blocks; i++){
	offset = i * 4096;
        ret = kernel_write(file, data[i], 4096, &offset);
    }
    if (ret < 0){
        printk(KERN_INFO "Kernel Read Failed: %d\n", ret);
    }
    file_close(file);
    return ret;
}

static int test_aont(void){
    uint8_t *data = kmalloc(4096, GFP_KERNEL);
    size_t data_blocks = 1024;
    size_t parity_blocks = 1024;
    size_t data_length = 4096;
    uint8_t **shares = kmalloc(sizeof(uint8_t*) * (data_blocks + parity_blocks), GFP_KERNEL);
    int i = 0;
    struct timespec timespec1, timespec2;
    uint8_t erasures[0] = {};
    uint8_t num_erasures = 0;
    size_t share_size = get_share_size(data_length, data_blocks);

    //get_random_bytes(data, 4096);

    //For this example each share is the size of the original AONT payload
    for(i = 0; i < data_blocks + parity_blocks; i++) shares[i] = kmalloc(share_size, GFP_KERNEL);

    read_file(shares, data_blocks, input_file[0]);    

    getnstimeofday(&timespec1); 
    encode_aont_package(data, data_length, shares, data_blocks, parity_blocks);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Encode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    write_file(shares, data_blocks, share_size, output_file[0]);

    getnstimeofday(&timespec1);
    decode_aont_package(data, data_length, shares, data_blocks, parity_blocks, erasures, num_erasures);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Decode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));
 
    kfree(data);
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
