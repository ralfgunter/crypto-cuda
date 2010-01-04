/*
 * 256-bits AES-specific host functions prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef HOST_AES256_H_
#define HOST_AES256_H_

#include <stdint.h>

// Key scheduling
extern void    h_generateCipherKey256(uchar4*, uint64_t, uint64_t, uint64_t, uint64_t);
extern uchar4* d_generateCipherKey256(uint64_t, uint64_t, uint64_t, uint64_t);
extern uchar4* d_expandKey256(uchar4*, uint8_t*);

// Encryption
extern void  encryptDeviceToDevice256(char*, uint8_t*, uchar4*, size_t);
extern char* encryptHostToDevice256(char*, size_t, uint8_t*, uchar4*);
extern char* encryptHostToHost256(char*, size_t, uint8_t*, uchar4*);

// Decryption
extern void  decryptDeviceToDevice256(char*, uint8_t*, uchar4*, size_t);
extern char* decryptHostToDevice256(char*, size_t, uint8_t*, uchar4*);
extern char* decryptHostToHost256(char*, size_t, uint8_t*, uchar4*);

#endif
