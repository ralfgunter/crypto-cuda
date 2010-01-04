/*
 * 128-bits AES-specific host functions prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef HOST_AES128_H_
#define HOST_AES128_H_

#include <stdint.h>

// Key scheduling
extern void    h_generateCipherKey128(uchar4*, uint64_t, uint64_t);
extern uchar4* d_generateCipherKey128(uint64_t, uint64_t);
extern uchar4* d_expandKey128(uchar4*, uint8_t*);

// Encryption
extern void  encryptDeviceToDevice128(char*, uint8_t*, uchar4*, size_t);
extern char* encryptHostToDevice128(char*, size_t, uint8_t*, uchar4*);
extern char* encryptHostToHost128(char*, size_t, uint8_t*, uchar4*);

// Decryption
extern void  decryptDeviceToDevice128(char*, uint8_t*, uchar4*, size_t);
extern char* decryptHostToDevice128(char*, size_t, uint8_t*, uchar4*);
extern char* decryptHostToHost128(char*, size_t, uint8_t*, uchar4*);

#endif
