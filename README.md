# AONT-RS
An implementation of [Resch and Plank's AONT-RS](https://www.usenix.org/legacy/event/fast11/tech/full_papers/Resch.pdf) information dispersal algorithm in C with versions for both the kernel and userspace.

This library uses a [SIMD Galois Field library](https://github.com/atbarker/GaloisField-SIMD) (derived from CM256 by Chris Taylor) for Cauchy Reed-Solomon erasure coding and the Linux Kernel Crypto API for AES in CBC mode and SHA256.

The userspace version relies on libkcapi, the Linux kernel crypto API passthrough library.

Tested on Ubuntu 18.04, Linux kernel v4.15.0.
