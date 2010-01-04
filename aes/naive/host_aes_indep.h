/*
 * Bitlength-independent host functions prototypes
 * Part of the crypto-cuda project.
 *
 * This file is in the public domain.
 *
*/

#ifndef HOST_AES_INDEP_H_
#define HOST_AES_INDEP_H_

// IO
extern int loadFileIntoMemory(char**, const char*);
extern int writeToFile(char*, const char*, size_t);

#endif
