/*
 * 192-bits AES-specific host functions prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef HOST_AES192_H_
#define HOST_AES192_H_

#include <stdint.h>

// Key scheduling
extern void    h_generateCipherKey192(uchar4*, uint64_t, uint64_t, uint64_t);
extern uchar4* d_generateCipherKey192(uint64_t, uint64_t, uint64_t);
extern uchar4* d_expandKey192(uchar4*, uint8_t*);

// Encryption
extern void  encryptDeviceToDevice192(char*, uint8_t*, uchar4*, size_t);
extern char* encryptHostToDevice192(char*, size_t, uint8_t*, uchar4*);
extern char* encryptHostToHost192(char*, size_t, uint8_t*, uchar4*);

// Decryption
extern void  decryptDeviceToDevice192(char*, uint8_t*, uchar4*, size_t);
extern char* decryptHostToDevice192(char*, size_t, uint8_t*, uchar4*);
extern char* decryptHostToHost192(char*, size_t, uint8_t*, uchar4*);

#endif
