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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("AUSTEN BARKER");

#define BLOCK_BYTES 4096
#define ORIGINAL_COUNT 4
#define RECOVERY_COUNT 4

struct input_blocks{
    uint8_t dataBlocks[ORIGINAL_COUNT][BLOCK_BYTES];
    uint8_t dataBlocksCopy[ORIGINAL_COUNT][BLOCK_BYTES];
    uint8_t parityBlocks[RECOVERY_COUNT][BLOCK_BYTES]; 
};

static inline void twodtopointer(uint8_t array[][BLOCK_BYTES], int size, uint8_t* output[BLOCK_BYTES]){
    int i = 0;
    for(i = 0; i < size; i++){
        output[i] = array[i];   
    }
}

static int test_aont(void){
    uint8_t *data = kmalloc(4096, GFP_KERNEL);
    size_t data_blocks = 1;
    size_t parity_blocks = 3;
    size_t data_length = 4096;
    uint8_t **carrier_blocks = kmalloc(sizeof(uint8_t*) * (data_blocks + parity_blocks), GFP_KERNEL);
    int i = 0;
    struct timespec timespec1, timespec2;
    uint8_t erasures[0] = {};
    uint8_t num_erasures = 0;

    get_random_bytes(data, 4096);

    for(i = 0; i < data_blocks + parity_blocks; i++) carrier_blocks[i] = kmalloc(4096 + 16 + 16, GFP_KERNEL);

    getnstimeofday(&timespec1); 
    encode_aont_package(data, data_length, carrier_blocks, data_blocks, parity_blocks);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Encode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));

    getnstimeofday(&timespec1);
    decode_aont_package(carrier_blocks, data, data_length, data_blocks, parity_blocks, erasures, num_erasures);
    getnstimeofday(&timespec2);
    printk(KERN_INFO "Decode took: %ld nanoseconds",
(timespec2.tv_sec - timespec1.tv_sec) * 1000000000 + (timespec2.tv_nsec - timespec1.tv_nsec));
 
    kfree(data);
    kfree(carrier_blocks);
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
