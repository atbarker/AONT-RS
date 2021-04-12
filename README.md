# AONT-RS
An implementation of [Resch and Plank's AONT-RS](https://www.usenix.org/legacy/event/fast11/tech/full_papers/Resch.pdf) information dispersal algorithm in C with versions for both the kernel and userspace. 

The algorithm first applies an All or Nothing Transform (a specialized encryption mode) to the plaintext data and then splits the ciphertext into multiple shares using Reed-Solomon erasure codes. A number of shares which together must be equal in size to the original data are required to decode and decrypt the original secret.

This library uses a [SIMD Galois Field library](https://github.com/atbarker/GaloisField-SIMD) (derived from CM256 by Chris Taylor) for Cauchy Reed-Solomon erasure coding and the Linux Kernel Crypto API for AES in CBC mode and SHA256.

It relies on the Speck cipher for symmetric encryption.

Tested on Ubuntu 18.04, Linux kernel v4.15.0.
