/*
 * Galois Field operations necessary for Rabin's Information Dispersal Algorithm
 *
 * Currently based off the functions found here https://github.com/HelenNeigel/Rabin-IDA-implementation/blob/master/Galois.h
 */

#ifndef GF_H
#define GF_H

#include <stdint.h>

//seemingly designed for up to GF 2**16?
static inline int gforder(uint8_t *a) {
    int highest = 0;
    for (int i = 0; i<15; i++) {
        highest = (a[i] == 1 ? i : highest);
    }
    return highest;
}

static inline uint8_t GFMul(uint8_t a, uint8_t b){
	uint8_t c = 0;
	uint8_t bits[16];
	uint8_t mask = 1;

	// initialize the bit sequence
	for (int i = 0; i<15; i++) {
		bits[i] = 0;
	}
	// multiply in gf
	for (int i = 0; i<8; i++) {
		for (int j = 0; j<8; j++) {
			bits[i + j] = bits[i + j] ^ (((a >> i) & mask) & ((b >> j) & mask));
		}
	}
	// find modulo x8 + x4 + x3 + x + 1 =
	int order = GFOrder(bits) - 8;
	while (order >= 0) {
		bits[order + 8] = bits[order + 8] ^ 1;
		bits[order + 4] = bits[order + 4] ^ 1;
		bits[order + 3] = bits[order + 3] ^ 1;
		bits[order + 1] = bits[order + 1] ^ 1;
		bits[order] = bits[order] ^ 1;
		order = GFOrder(bits) - 8;
	}
	// initialize the bit sequence
	for (int i = 0; i<15; i++) {
		//cout << (int) bits[i] << " " ;
		c = c + bits[i] * pow(2, i);
	}
	return (c);
}

static inline void GFInitInverse(uint8_t * inverses) {
	uint8_t c;
	for (int i = 1; i<256; i++) {
		for (int j = 1; j<256; j++) {
			c = GFMul(i, j);
			if (c == 1) {
				inverses[i] = j;
			}
		}
	}

}

static inline uint8_t GFPower(uint8_t a, int exp){
	unsigned char c = 1;
	for (int i = 1; i <= exp; i++){
		c = GFMul(c, a);
	}
	return (c);
}

static inline uint8_t GFAdd(uint8_t a, uint8_t b){
	uint8_t c;
	c = a ^ b;
	return (c);
}

#endif //GF_H
