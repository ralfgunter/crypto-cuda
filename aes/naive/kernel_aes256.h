/*
 * 256-bits AES-specific kernel prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef KERNEL_AES256_H_
#define KERNEL_AES256_H_

#include <stdint.h>

// Key schedule
extern __device__ uchar4 rotWord256(uchar4*, uint8_t);
extern __device__ void   roundKeyGeneration256(uchar4*, uint8_t*);
extern __global__ void   generateRoundKeys256(uchar4*, uchar4*, uint8_t*);

// Encryption
extern __device__ void encryptBlock256(uchar4*, uchar4*, uint8_t*);
extern __global__ void encrypt256(char*, int, uchar4*, uint8_t*);

// Decryption
extern __device__ void decryptBlock256(uchar4*, uchar4*, uint8_t*);
extern __global__ void decrypt256(char*, int, uchar4*, uint8_t*);

#endif
