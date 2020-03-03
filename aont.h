#ifndef AONT_H
#define AONT_H

#include <linux/random.h>
#include <linux/types.h>
#include "cauchy_rs.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>
#include <crypto/hash.h>

#define CANARY_SIZE 16

int encode_aont_package(const uint8_t *data, size_t data_length, uint8_t **carrier_blocks, size_t data_blocks, size_t parity_blocks);

int decode_aont_package(uint8_t **carrier_blocks, uint8_t *data, size_t data_length, size_t data_blocks, size_t parity_blocks, uint8_t *erasures, uint8_t num_erasures);

#endif
