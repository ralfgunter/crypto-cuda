/*
 * 128-bits AES-specific kernel prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef KERNEL_AES128_H_
#define KERNEL_AES128_H_

#define NUM_THREADS 256

#include <stdint.h>
#include "aes_boxes.h"
#include "kernel_aes_indep.h"

// Key schedule
extern __device__ uchar4 rotWord128(uchar4*, uint8_t);
extern __device__ void   roundKeyGeneration128(uchar4*, uint8_t*);
extern __global__ void   generateRoundKeys128(uchar4*, uchar4*, uint8_t*);

// Encryption
extern __device__ void encryptBlock128(uchar4*, uchar4*, uint8_t*);
extern __global__ void encrypt128(char*, int, uchar4*, uint8_t*);

// Decryption
extern __device__ void decryptBlock128(uchar4*, uchar4*, uint8_t*);
extern __global__ void decrypt128(char*, int, uchar4*, uint8_t*);

#endif
