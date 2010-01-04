#include <stdlib.h>
#include "kernel_aes192.h"
#include "host_aes192.h"


// Key scheduling
void
h_generateCipherKey192( uchar4 *result,
						uint64_t block1,
						uint64_t block2,
						uint64_t block3 )
{
	for (int i = 0; i < 2; ++i) {
		result[i + 0].x = (block1 >> (56 - 32*i)) & 0xFF;
		result[i + 0].y = (block1 >> (48 - 32*i)) & 0xFF;
		result[i + 0].z = (block1 >> (40 - 32*i)) & 0xFF;
		result[i + 0].w = (block1 >> (32 - 32*i)) & 0xFF;
		
		result[i + 2].x = (block2 >> (56 - 32*i)) & 0xFF;
		result[i + 2].y = (block2 >> (48 - 32*i)) & 0xFF;
		result[i + 2].z = (block2 >> (40 - 32*i)) & 0xFF;
		result[i + 2].w = (block2 >> (32 - 32*i)) & 0xFF;
		
		result[i + 4].x = (block3 >> (56 - 32*i)) & 0xFF;
		result[i + 4].y = (block3 >> (48 - 32*i)) & 0xFF;
		result[i + 4].z = (block3 >> (40 - 32*i)) & 0xFF;
		result[i + 4].w = (block3 >> (32 - 32*i)) & 0xFF;
	}
}

uchar4 *
d_generateCipherKey192( uint64_t block1, uint64_t block2, uint64_t block3 )
{
	uchar4 *d_cipher_key;
	uchar4 *h_cipher_key = (uchar4 *) malloc(6 * sizeof(uchar4));
	
	// Generates the cipher key on host from the three uint64_t blocks
	h_generateCipherKey192(h_cipher_key, block1, block2, block3);
	
	// Allocates memory for the device's cipher key, copying the host's to it
	cudaMalloc((void **) &d_cipher_key,    6 * sizeof(uchar4));
	cudaMemcpy(d_cipher_key, h_cipher_key, 6 * sizeof(uchar4), cudaMemcpyHostToDevice);
	
	// Frees up memory used temporarily for the host cipher key
	free(h_cipher_key);
	
	return d_cipher_key;
}

uchar4 *
d_expandKey192( uchar4 *d_cipher_key, uint8_t *d_sbox ) {
	uchar4 *d_round_keys;
	
	// Allocates memory on the device for the round keys
	cudaMalloc((void **) &d_round_keys, 13 * 6 * sizeof(uchar4));
	
	// Generates the round keys, storing them on the global memory
	generateRoundKeys192 <<< 1, 1 >>>
		(
			d_cipher_key, d_round_keys, d_sbox
		);
	cudaThreadSynchronize();
	
	return d_round_keys;
}


// Encryption
inline void
encryptDeviceToDevice192( char *d_contents,     uint8_t *d_sbox,
						  uchar4 *d_round_keys, size_t contents_size )
{
	// Encrypts the contents on the device
	encrypt192 <<< ((contents_size/16 + 255)/ 256), 256 >>>
		(
			d_contents, contents_size, d_round_keys, d_sbox
		);
	cudaThreadSynchronize();
}

char *
encryptHostToDevice192( char *h_contents, size_t contents_size,
						uint8_t *d_sbox, uchar4 *d_round_keys )
{
	char *d_result;
	
	// Allocates memory for the contents
	cudaMalloc((void **) &d_result, contents_size);
	
	// Copies the contents to the device
	cudaMemcpy(d_result, h_contents, contents_size, cudaMemcpyHostToDevice);
	
	// Encrypts the contents on the device
	encryptDeviceToDevice192(d_result, d_sbox, d_round_keys, contents_size);
	
	return d_result;
}

char *
encryptHostToHost192( char *h_contents, size_t contents_size,
					  uint8_t *d_sbox,  uchar4 *d_round_keys )
{
	char *d_contents;
	char *h_result = (char *) malloc(contents_size);
	
	// Encrypts the contents on the device
	d_contents = encryptHostToDevice192( h_contents, contents_size,
										 d_sbox,     d_round_keys );
	
	// Copies back the result from the device
	cudaMemcpy(h_result, d_contents, contents_size, cudaMemcpyDeviceToHost);
	
	// Frees up device memory taken by the contents
	cudaFree(d_contents);
	
	return h_result;
}


// Decryption
inline void
decryptDeviceToDevice192( char *d_contents,     uint8_t *d_inv_sbox,
						  uchar4 *d_round_keys, size_t contents_size )
{
	// Decrypts the contents on the device
	decrypt192 <<< ((contents_size/16 + 255)/ 256), 256 >>>
		(
			d_contents, contents_size, d_round_keys, d_inv_sbox
		);
	cudaThreadSynchronize();
}

char *
decryptHostToDevice192( char *h_contents, size_t contents_size,
						uint8_t *d_sbox,  uchar4 *d_round_keys )
{
	char *d_result;
	
	// Allocates memory for the contents
	cudaMalloc((void **) &d_result, contents_size);
	
	// Copies the contents to the device
	cudaMemcpy(d_result, h_contents, contents_size, cudaMemcpyHostToDevice);
	
	// Encrypts the contents on the device
	decryptDeviceToDevice192(d_result, d_sbox, d_round_keys, contents_size);
	
	return d_result;
}

char *
decryptHostToHost192( char *h_contents,    size_t contents_size,
					  uint8_t *d_inv_sbox, uchar4 *d_round_keys )
{
	char *d_contents;
	char *h_result = (char *) malloc(contents_size);
	
	// Encrypts the contents on the device
	d_contents = decryptHostToDevice192( h_contents, contents_size,
										 d_inv_sbox, d_round_keys );
	
	// Copies back the result from the device
	cudaMemcpy(h_result, d_contents, contents_size, cudaMemcpyDeviceToHost);
	
	// Frees up device memory taken by the contents
	cudaFree(d_contents);
	
	return h_result;
}
