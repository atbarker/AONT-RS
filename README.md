# AONT-RS
An implementation of [Resch and Plank's AONT-RS](https://www.usenix.org/legacy/event/fast11/tech/full_papers/Resch.pdf) information dispersal algorithm in C for use in Linux krnel modules.

This library uses a [SIMD Galois Field library](https://github.com/atbarker/GaloisField-SIMD) (derived from CM256 by Chris Taylor) for Cauchy Reed-Solomon erasure coding and the Linux Kernel Crypto API for AES in CBC mode and SHA256.

Tested on Ubuntu 18.04, Linux kernel v4.15.0.
