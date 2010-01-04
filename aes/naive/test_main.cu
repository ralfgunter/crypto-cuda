#include <stdlib.h>
#include "aes.h"

/*
void nouveau128( int argc, char *argv[] ) {
	uchar4 *h_round_keys;
	uchar4 *d_cipher_key, *d_round_keys;
	uint8_t *d_sbox, *d_inv_sbox;
	char *h_file;
	char *d_file;
	size_t file_size;
	
	// Generates a 128-bits cipher-key from three uint64_t
	d_cipher_key = d_generateCipherKey128( 0x95A8EE8E89979B9E,
										   0xFDCBC6EB9797528D );
	
	// Loads file from disk
	file_size = loadFileIntoMemory(&h_file, argv[1]);
	
	// Allocates memory for various resources
	h_round_keys =    (uchar4 *) malloc(11 * 4 * sizeof(uchar4));
	cudaMalloc((void **) &d_round_keys, 11 * 4 * sizeof(uchar4));
	cudaMalloc((void **) &d_sbox,          256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_inv_sbox,      256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_file,    file_size * sizeof(char));
	
	// Copies memory to the device
	cudaMemcpy(d_sbox,     s_box,         256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_inv_sbox, inv_s_box,     256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_file,     h_file,     file_size * sizeof(char), cudaMemcpyHostToDevice);
	
	
	// Generates the round keys, storing them on the global memory
	d_round_keys = d_expandKey128( d_cipher_key, d_sbox );
	
	
	// Encrypts the file
	h_file = encryptHostToHost128(h_file, file_size, d_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[2], file_size);
	
	
	// Decrypts the file
	h_file = decryptHostToHost128(h_file, file_size, d_inv_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[3], file_size);
	
	
	// Frees up memory that is not used anymore
	free(h_round_keys);
	free(h_file);
	cudaFree(d_cipher_key);
	cudaFree(d_round_keys);
	cudaFree(d_inv_sbox);
	cudaFree(d_sbox);
	cudaFree(d_file);
}
*/
void nouveau192( int argc, char *argv[] ) {
	uchar4 *h_round_keys;
	uchar4 *d_cipher_key, *d_round_keys;
	uint8_t *d_sbox, *d_inv_sbox;
	char *h_file;
	char *d_file;
	size_t file_size;
	
	// Generates a 192-bits cipher-key from three uint64_t
	d_cipher_key = d_generateCipherKey192( 0x95A8EE8E89979B9E,
										   0xFDCBC6EB9797528D,
										   0x432DC26061553818 );
	
	// Loads file from disk
	file_size = loadFileIntoMemory(&h_file, argv[1]);
	
	// Allocates memory for various resources
	h_round_keys =    (uchar4 *) malloc(13 * 6 * sizeof(uchar4));
	cudaMalloc((void **) &d_round_keys, 13 * 6 * sizeof(uchar4));
	cudaMalloc((void **) &d_sbox,          256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_inv_sbox,      256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_file,    file_size * sizeof(char));
	
	// Copies memory to the device
	cudaMemcpy(d_sbox,     s_box,         256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_inv_sbox, inv_s_box,     256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_file,     h_file,     file_size * sizeof(char), cudaMemcpyHostToDevice);
	
	
	// Generates the round keys, storing them on the global memory
	d_round_keys = d_expandKey192( d_cipher_key, d_sbox );
	
	
	
	// Encrypts the file
	h_file = encryptHostToHost192(h_file, file_size, d_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[2], file_size);
	
	
	// Decrypts the file
	h_file = decryptHostToHost192(h_file, file_size, d_inv_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[3], file_size);
	
	
	// Frees up memory that is not used anymore
	free(h_round_keys);
	free(h_file);
	cudaFree(d_cipher_key);
	cudaFree(d_round_keys);
	cudaFree(d_inv_sbox);
	cudaFree(d_sbox);
	cudaFree(d_file);
}
/*
void nouveau256( int argc, char *argv[] ) {
	uchar4 *h_round_keys;
	uchar4 *d_cipher_key, *d_round_keys;
	uint8_t *d_sbox, *d_inv_sbox;
	char *h_file;
	char *d_file;
	size_t file_size;
	
	// Generates 256-bits cipher-key from four uint64_t
	d_cipher_key = d_generateCipherKey256( 0x95A8EE8E89979B9E,
										   0xFDCBC6EB9797528D,
										   0x432DC26061553818,
										   0xEA635EC5D5A7727E );
	
	// Loads file from disk
	file_size = loadFileIntoMemory(&h_file, argv[1]);
	
	// Allocates memory for various resources
	h_round_keys =    (uchar4 *) malloc(15 * 8 * sizeof(uchar4));
	cudaMalloc((void **) &d_round_keys, 15 * 8 * sizeof(uchar4));
	cudaMalloc((void **) &d_sbox,          256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_inv_sbox,      256 * sizeof(uint8_t));
	cudaMalloc((void **) &d_file,    file_size * sizeof(char));
	
	// Copies memory to the device
	cudaMemcpy(d_sbox, s_box,               256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_inv_sbox, inv_s_box,       256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_file, h_file,        file_size * sizeof(char),    cudaMemcpyHostToDevice);
	
	
	// Generates the round keys, storing them on the global memory
	d_round_keys = d_expandKey256( d_cipher_key, d_sbox );
	
	
	
	// Encrypts the file
	h_file = encryptHostToHost256(h_file, file_size, d_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[2], file_size);
	
	
	// Decrypts the file
	h_file = decryptHostToHost256(h_file, file_size, d_inv_sbox, d_round_keys);
	
	// Writes the encrypted file to disk
	writeToFile(h_file, argv[3], file_size);
	
	
	// Frees up memory that is not used anymore
	free(h_round_keys);
	free(h_file);
	cudaFree(d_cipher_key);
	cudaFree(d_round_keys);
	cudaFree(d_inv_sbox);
	cudaFree(d_sbox);
	cudaFree(d_file);
}
*/

int main( int argc, char *argv[] ) {
	//nouveau128(argc, argv);
	nouveau192(argc, argv);
	//nouveau256(argc, argv);
	
	return 0;
}
