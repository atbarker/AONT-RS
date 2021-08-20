# AONT-RS
An implementation of [Resch and Plank's AONT-RS](https://www.usenix.org/legacy/event/fast11/tech/full_papers/Resch.pdf) information dispersal algorithm in C with versions for both the kernel and userspace. 

The algorithm first applies an [All or Nothing Transform](https://people.csail.mit.edu/rivest/pubs/Riv97d.prepub.pdf) (a specialized encryption mode) to the plaintext data and then splits the ciphertext into multiple shares using Reed-Solomon erasure codes. A number of shares which together must be equal in size to the original data are required to decode and decrypt the original secret.

This library uses a [SIMD Galois Field library](https://github.com/atbarker/GaloisField-SIMD) (derived from [CM256](https://github.com/catid/cm256) by Chris Taylor) for Cauchy Reed-Solomon erasure coding and implementations of the [Speck cipher and SHA3](https://github.com/kyle-fredrickson/artifice-crypto) written in collaboration with Kyle Frederickson.

Tested on Ubuntu 18.04, Linux kernel v4.15.0.

## install

install libtool 
```
sudo apt-get install -y libtool
```

install lib ckpai
```
git clone https://github.com/smuellerDD/libkcapi.git

```
