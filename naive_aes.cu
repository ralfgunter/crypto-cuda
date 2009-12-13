#include <stdio.h>
#include <stdint.h>

#define NUM_THREADS 256

enum ciphers { aes128, aes192, aes256 };
typedef enum ciphers ciphertype;

uint8_t s_box[] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b,	0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26,	0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2,	0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed,	0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f,	0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec,	0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14,	0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d,	0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f,	0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11,	0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f,	0xb0, 0x54, 0xbb, 0x16
};

uint8_t inv_s_box[] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Galois field multiplication
// From Wikipedia
__device__ uint8_t gmul( uint8_t a, uint8_t b )
{
	uint8_t p = 0;
	uint8_t counter;
	uint8_t hi_bit_set;
	for(counter = 0; counter < 8; counter++) {
		if(b & 1) 
			p ^= a;
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if(hi_bit_set) 
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		b >>= 1;
	}
	return p;
}

// Key scheduling kernels
__device__ uchar4 rotWord128( uchar4 *state, uint8_t round_number )
{
	uchar4 result;
	
	result.x = state[4*round_number - 1].y;
	result.y = state[4*round_number - 1].z;
	result.z = state[4*round_number - 1].w;
	result.w = state[4*round_number - 1].x;
	
	return result;
}

__device__ uchar4 subBytes( uchar4 word, uint8_t *sbox )
{
	uchar4 result;
	
	result.x = sbox[word.x];
	result.y = sbox[word.y];
	result.z = sbox[word.z];
	result.w = sbox[word.w];
	
	return result;
}

__device__ uchar4 xorTransformation( uchar4 word1, uchar4 word2, uint8_t rcon )
{
	uchar4 result;
	
	result.x = word1.x ^ word2.x ^ rcon;
	result.y = word1.y ^ word2.y;
	result.z = word1.z ^ word2.z;
	result.w = word1.w ^ word2.w;
	
	return result;
}

__device__ void roundKeyGeneration128( uchar4 *keys, uint8_t *sbox )
{
	uchar4 temp;
	uint8_t rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10,
		0x20, 0x40, 0x80, 0x1b, 0x36
	};
	
#pragma unroll
	for (int n = 1; n <= 10; ++n) {
		temp = subBytes(rotWord128(keys, n), sbox);
		keys[4*n + 0] = xorTransformation(temp, keys[4*(n-1) + 0], rcon[n-1]);
		
		keys[4*n + 1] = xorTransformation(keys[4*n + 0], keys[4*(n-1) + 1], 0);
		keys[4*n + 2] = xorTransformation(keys[4*n + 1], keys[4*(n-1) + 2], 0);
		keys[4*n + 3] = xorTransformation(keys[4*n + 2], keys[4*(n-1) + 3], 0);
	}
}

__global__ void generateRoundKeys128( uchar4 *cipher_key, uchar4 *round_keys, uint8_t *sbox )
{
	extern __shared__ uchar4 shmem[];
	
#pragma unroll
	for (int i = 0; i < 4; ++i) {
		shmem[i].x = cipher_key[i].x;
		shmem[i].y = cipher_key[i].y;
		shmem[i].z = cipher_key[i].z;
		shmem[i].w = cipher_key[i].w;
	}
	
	roundKeyGeneration128(shmem, sbox);
	
#pragma unroll
	for (int i = 0; i < 11; ++i) {
#pragma unroll
		for (int p = 0; p < 4; ++p) {
			round_keys[4*i + p].x = shmem[4*i + p].x;
			round_keys[4*i + p].y = shmem[4*i + p].y;
			round_keys[4*i + p].z = shmem[4*i + p].z;
			round_keys[4*i + p].w = shmem[4*i + p].w;
		}
	}
}




// Encryption process kernels
__device__ void addRoundKey128( uchar4 *state, uchar4 *keys, uint8_t round_number )
{
	// First column
	state[0].x ^= keys[4*round_number + 0].x;
	state[0].y ^= keys[4*round_number + 0].y;
	state[0].z ^= keys[4*round_number + 0].z;
	state[0].w ^= keys[4*round_number + 0].w;
	
	// Second column
	state[1].x ^= keys[4*round_number + 1].x;
	state[1].y ^= keys[4*round_number + 1].y;
	state[1].z ^= keys[4*round_number + 1].z;
	state[1].w ^= keys[4*round_number + 1].w;
	
	// Third columna
	state[2].x ^= keys[4*round_number + 2].x;
	state[2].y ^= keys[4*round_number + 2].y;
	state[2].z ^= keys[4*round_number + 2].z;
	state[2].w ^= keys[4*round_number + 2].w;
	
	// Fourth column
	state[3].x ^= keys[4*round_number + 3].x;
	state[3].y ^= keys[4*round_number + 3].y;
	state[3].z ^= keys[4*round_number + 3].z;
	state[3].w ^= keys[4*round_number + 3].w;
}

__device__ void subBytes128( uchar4 *state, uint8_t *sbox )
{
	// First column
	state[0].x = sbox[state[0].x];
	state[0].y = sbox[state[0].y];
	state[0].z = sbox[state[0].z];
	state[0].w = sbox[state[0].w];
	
	// First column
	state[1].x = sbox[state[1].x];
	state[1].y = sbox[state[1].y];
	state[1].z = sbox[state[1].z];
	state[1].w = sbox[state[1].w];
	
	// First column
	state[2].x = sbox[state[2].x];
	state[2].y = sbox[state[2].y];
	state[2].z = sbox[state[2].z];
	state[2].w = sbox[state[2].w];
	
	// First column
	state[3].x = sbox[state[3].x];
	state[3].y = sbox[state[3].y];
	state[3].z = sbox[state[3].z];
	state[3].w = sbox[state[3].w];
}

__device__ void shiftRows128( uchar4 *state )
{
	uchar4 temp;
	
	// First row
	// NOTHING HAPPENS
	
	// Second row
	temp.x = state[0].y;
	temp.y = state[1].y;
	temp.z = state[2].y;
	temp.w = state[3].y;
	state[0].y = temp.y;
	state[1].y = temp.z;
	state[2].y = temp.w;
	state[3].y = temp.x;
	
	// Third row
	temp.x = state[0].z;
	temp.y = state[1].z;
	temp.z = state[2].z;
	temp.w = state[3].z;
	state[0].z = temp.z;
	state[1].z = temp.w;
	state[2].z = temp.x;
	state[3].z = temp.y;
	
	// Fourth row
	temp.x = state[0].w;
	temp.y = state[1].w;
	temp.z = state[2].w;
	temp.w = state[3].w;
	state[0].w = temp.w;
	state[1].w = temp.x;
	state[2].w = temp.y;
	state[3].w = temp.z;
}

__device__ void mixColumns128( uchar4 *state )
{
	uchar4 temp;
	
	// First column
	temp.x = gmul(state[0].x,2) ^ gmul(state[0].y,3) ^ state[0].z ^ state[0].w;
	temp.y = gmul(state[0].y,2) ^ gmul(state[0].z,3) ^ state[0].w ^ state[0].x;
	temp.z = gmul(state[0].z,2) ^ gmul(state[0].w,3) ^ state[0].x ^ state[0].y;
	temp.w = gmul(state[0].w,2) ^ gmul(state[0].x,3) ^ state[0].y ^ state[0].z;
	state[0].x = temp.x;
	state[0].y = temp.y;
	state[0].z = temp.z;
	state[0].w = temp.w;
	
	// Second column
	temp.x = gmul(state[1].x,2) ^ gmul(state[1].y,3) ^ state[1].z ^ state[1].w;
	temp.y = gmul(state[1].y,2) ^ gmul(state[1].z,3) ^ state[1].w ^ state[1].x;
	temp.z = gmul(state[1].z,2) ^ gmul(state[1].w,3) ^ state[1].x ^ state[1].y;
	temp.w = gmul(state[1].w,2) ^ gmul(state[1].x,3) ^ state[1].y ^ state[1].z;
	state[1].x = temp.x;
	state[1].y = temp.y;
	state[1].z = temp.z;
	state[1].w = temp.w;
	
	// Third column
	temp.x = gmul(state[2].x,2) ^ gmul(state[2].y,3) ^ state[2].z ^ state[2].w;
	temp.y = gmul(state[2].y,2) ^ gmul(state[2].z,3) ^ state[2].w ^ state[2].x;
	temp.z = gmul(state[2].z,2) ^ gmul(state[2].w,3) ^ state[2].x ^ state[2].y;
	temp.w = gmul(state[2].w,2) ^ gmul(state[2].x,3) ^ state[2].y ^ state[2].z;
	state[2].x = temp.x;
	state[2].y = temp.y;
	state[2].z = temp.z;
	state[2].w = temp.w;
	
	// Fourth column
	temp.x = gmul(state[3].x,2) ^ gmul(state[3].y,3) ^ state[3].z ^ state[3].w;
	temp.y = gmul(state[3].y,2) ^ gmul(state[3].z,3) ^ state[3].w ^ state[3].x;
	temp.z = gmul(state[3].z,2) ^ gmul(state[3].w,3) ^ state[3].x ^ state[3].y;
	temp.w = gmul(state[3].w,2) ^ gmul(state[3].x,3) ^ state[3].y ^ state[3].z;
	state[3].x = temp.x;
	state[3].y = temp.y;
	state[3].z = temp.z;
	state[3].w = temp.w;
}

__device__ void encryptBlock128( uchar4 *state, uchar4 *keys, uint8_t *sbox )
{
	// First round
	addRoundKey128(state, keys, 0);
	
	// Rounds 1 to 9
	// 1
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 1);
	// 2
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 2);
	// 3
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 3);
	// 4
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 4);
	// 5
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 5);
	// 6
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 6);
	// 7
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 7);
	// 8
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 8);
	// 9
	subBytes128(state, sbox);
	shiftRows128(state);
	mixColumns128(state);
	addRoundKey128(state, keys, 9);
	
	// Last round
	subBytes128(state, sbox);
	shiftRows128(state);
	addRoundKey128(state, keys, 10);
}

__global__ void encrypt128( char *file, int file_size, uchar4 *round_keys, uint8_t *sbox )
{
	__shared__ uchar4  sh_round_keys[44 * sizeof(uchar4)];
	__shared__ uint8_t     sh_sbox[256 * sizeof(uint8_t)];
	
	int id = NUM_THREADS * blockIdx.x + threadIdx.x;
	
	for (int i = 0; i < 44; ++i) {
		sh_round_keys[i].x = round_keys[i].x;
		sh_round_keys[i].y = round_keys[i].y;
		sh_round_keys[i].z = round_keys[i].z;
		sh_round_keys[i].w = round_keys[i].w;
	}

	// This forces the number of threads per block to be 256
	sh_sbox[threadIdx.x] = sbox[threadIdx.x];
	
	__syncthreads();
	
	if (id < file_size / 16) {
		uchar4 state[4];
		
		state[0].x = file[16 * id +  0];
		state[0].y = file[16 * id +  1];
		state[0].z = file[16 * id +  2];
		state[0].w = file[16 * id +  3];
		
		state[1].x = file[16 * id +  4];
		state[1].y = file[16 * id +  5];
		state[1].z = file[16 * id +  6];
		state[1].w = file[16 * id +  7];
		
		state[2].x = file[16 * id +  8];
		state[2].y = file[16 * id +  9];
		state[2].z = file[16 * id + 10];
		state[2].w = file[16 * id + 11];
		
		state[3].x = file[16 * id + 12];
		state[3].y = file[16 * id + 13];
		state[3].z = file[16 * id + 14];
		state[3].w = file[16 * id + 15];
		
		encryptBlock128(state, sh_round_keys, sh_sbox);
		
		file[16 * id +  0] = state[0].x;
		file[16 * id +  1] = state[0].y;
		file[16 * id +  2] = state[0].z;
		file[16 * id +  3] = state[0].w;
		
		file[16 * id +  4] = state[1].x;
		file[16 * id +  5] = state[1].y;
		file[16 * id +  6] = state[1].z;
		file[16 * id +  7] = state[1].w;
		
		file[16 * id +  8] = state[2].x;
		file[16 * id +  9] = state[2].y;
		file[16 * id + 10] = state[2].z;
		file[16 * id + 11] = state[2].w;
		
		file[16 * id + 12] = state[3].x;
		file[16 * id + 13] = state[3].y;
		file[16 * id + 14] = state[3].z;
		file[16 * id + 15] = state[3].w;
	}
}


// Decryption process kernels
__device__ void invShiftRows128( uchar4 *state )
{
	uchar4 temp;
	
	// First row
	// NOTHING HAPPENS
	
	// Second row
	temp.x = state[0].y;
	temp.y = state[1].y;
	temp.z = state[2].y;
	temp.w = state[3].y;
	state[0].y = temp.w;
	state[1].y = temp.x;
	state[2].y = temp.y;
	state[3].y = temp.z;
	
	// Third row
	temp.x = state[0].z;
	temp.y = state[1].z;
	temp.z = state[2].z;
	temp.w = state[3].z;
	state[0].z = temp.z;
	state[1].z = temp.w;
	state[2].z = temp.x;
	state[3].z = temp.y;
	
	// Fourth row
	temp.x = state[0].w;
	temp.y = state[1].w;
	temp.z = state[2].w;
	temp.w = state[3].w;
	state[0].w = temp.y;
	state[1].w = temp.z;
	state[2].w = temp.w;
	state[3].w = temp.x;
}

__device__ void invSubBytes128( uchar4 *state, uint8_t *inv_sbox )
{
	// First column
	state[0].x = inv_sbox[state[0].x];
	state[0].y = inv_sbox[state[0].y];
	state[0].z = inv_sbox[state[0].z];
	state[0].w = inv_sbox[state[0].w];
	
	// First column
	state[1].x = inv_sbox[state[1].x];
	state[1].y = inv_sbox[state[1].y];
	state[1].z = inv_sbox[state[1].z];
	state[1].w = inv_sbox[state[1].w];
	
	// First column
	state[2].x = inv_sbox[state[2].x];
	state[2].y = inv_sbox[state[2].y];
	state[2].z = inv_sbox[state[2].z];
	state[2].w = inv_sbox[state[2].w];
	
	// First column
	state[3].x = inv_sbox[state[3].x];
	state[3].y = inv_sbox[state[3].y];
	state[3].z = inv_sbox[state[3].z];
	state[3].w = inv_sbox[state[3].w];
}

__device__ void invMixColumns128( uchar4 *state )
{
	uchar4 temp;
	
	// First column
	temp.x = gmul(state[0].x,14) ^ gmul(state[0].y,11) ^ gmul(state[0].z,13) ^ gmul(state[0].w,9);
	temp.y = gmul(state[0].y,14) ^ gmul(state[0].z,11) ^ gmul(state[0].w,13) ^ gmul(state[0].x,9);
	temp.z = gmul(state[0].z,14) ^ gmul(state[0].w,11) ^ gmul(state[0].x,13) ^ gmul(state[0].y,9);
	temp.w = gmul(state[0].w,14) ^ gmul(state[0].x,11) ^ gmul(state[0].y,13) ^ gmul(state[0].z,9);
	state[0].x = temp.x;
	state[0].y = temp.y;
	state[0].z = temp.z;
	state[0].w = temp.w;
	
	// Second column
	temp.x = gmul(state[1].x,14) ^ gmul(state[1].y,11) ^ gmul(state[1].z,13) ^ gmul(state[1].w,9);
	temp.y = gmul(state[1].y,14) ^ gmul(state[1].z,11) ^ gmul(state[1].w,13) ^ gmul(state[1].x,9);
	temp.z = gmul(state[1].z,14) ^ gmul(state[1].w,11) ^ gmul(state[1].x,13) ^ gmul(state[1].y,9);
	temp.w = gmul(state[1].w,14) ^ gmul(state[1].x,11) ^ gmul(state[1].y,13) ^ gmul(state[1].z,9);
	state[1].x = temp.x;
	state[1].y = temp.y;
	state[1].z = temp.z;
	state[1].w = temp.w;
	
	// Third column
	temp.x = gmul(state[2].x,14) ^ gmul(state[2].y,11) ^ gmul(state[2].z,13) ^ gmul(state[2].w,9);
	temp.y = gmul(state[2].y,14) ^ gmul(state[2].z,11) ^ gmul(state[2].w,13) ^ gmul(state[2].x,9);
	temp.z = gmul(state[2].z,14) ^ gmul(state[2].w,11) ^ gmul(state[2].x,13) ^ gmul(state[2].y,9);
	temp.w = gmul(state[2].w,14) ^ gmul(state[2].x,11) ^ gmul(state[2].y,13) ^ gmul(state[2].z,9);
	state[2].x = temp.x;
	state[2].y = temp.y;
	state[2].z = temp.z;
	state[2].w = temp.w;
	
	// Fourth column
	temp.x = gmul(state[3].x,14) ^ gmul(state[3].y,11) ^ gmul(state[3].z,13) ^ gmul(state[3].w,9);
	temp.y = gmul(state[3].y,14) ^ gmul(state[3].z,11) ^ gmul(state[3].w,13) ^ gmul(state[3].x,9);
	temp.z = gmul(state[3].z,14) ^ gmul(state[3].w,11) ^ gmul(state[3].x,13) ^ gmul(state[3].y,9);
	temp.w = gmul(state[3].w,14) ^ gmul(state[3].x,11) ^ gmul(state[3].y,13) ^ gmul(state[3].z,9);
	state[3].x = temp.x;
	state[3].y = temp.y;
	state[3].z = temp.z;
	state[3].w = temp.w;
}

__device__ void decryptBlock128( uchar4 *state, uchar4 *keys, uint8_t *inv_sbox )
{
	// First round
	addRoundKey128(state, keys, 10);
	
	// Last round?
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  9);
	
	// Rounds 1 to 9
	// 1
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  8);
	// 2
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  7);
	// 3
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  6);
	// 4
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  5);
	// 5
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  4);
	// 6
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  3);
	// 7
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  2);
	// 8
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  1);
	// 9
	invMixColumns128(state);
	invShiftRows128(state);
	invSubBytes128(state, inv_sbox);
	addRoundKey128(state, keys,  0);
}

__global__ void decrypt128( char *file, int file_size, uchar4 *round_keys, uint8_t *inv_sbox )
{
	__shared__ uchar4  sh_round_keys[44 * sizeof(uchar4)];
	__shared__ uint8_t     sh_sbox[256 * sizeof(uint8_t)];
	
	int id = NUM_THREADS * blockIdx.x + threadIdx.x;
	
	for (int i = 0; i < 44; ++i) {
		sh_round_keys[i].x = round_keys[i].x;
		sh_round_keys[i].y = round_keys[i].y;
		sh_round_keys[i].z = round_keys[i].z;
		sh_round_keys[i].w = round_keys[i].w;
	}
	
	// This forces the number of threads per block to be 256
	sh_sbox[threadIdx.x] = inv_sbox[threadIdx.x];
	
	__syncthreads();
	
	if (id < file_size / 16) {
		uchar4 state[4];
		
		state[0].x = file[16 * id +  0];
		state[0].y = file[16 * id +  1];
		state[0].z = file[16 * id +  2];
		state[0].w = file[16 * id +  3];
		
		state[1].x = file[16 * id +  4];
		state[1].y = file[16 * id +  5];
		state[1].z = file[16 * id +  6];
		state[1].w = file[16 * id +  7];
		
		state[2].x = file[16 * id +  8];
		state[2].y = file[16 * id +  9];
		state[2].z = file[16 * id + 10];
		state[2].w = file[16 * id + 11];
		
		state[3].x = file[16 * id + 12];
		state[3].y = file[16 * id + 13];
		state[3].z = file[16 * id + 14];
		state[3].w = file[16 * id + 15];
		
		decryptBlock128(state, sh_round_keys, sh_sbox);
		
		file[16 * id +  0] = state[0].x;
		file[16 * id +  1] = state[0].y;
		file[16 * id +  2] = state[0].z;
		file[16 * id +  3] = state[0].w;
		
		file[16 * id +  4] = state[1].x;
		file[16 * id +  5] = state[1].y;
		file[16 * id +  6] = state[1].z;
		file[16 * id +  7] = state[1].w;
		
		file[16 * id +  8] = state[2].x;
		file[16 * id +  9] = state[2].y;
		file[16 * id + 10] = state[2].z;
		file[16 * id + 11] = state[2].w;
		
		file[16 * id + 12] = state[3].x;
		file[16 * id + 13] = state[3].y;
		file[16 * id + 14] = state[3].z;
		file[16 * id + 15] = state[3].w;
	}
}



// Host code
void generateCipherKey128( uchar4 *result, uint64_t block1, uint64_t block2 ) {
	for (int i = 0; i < 2; ++i) {
		result[i + 0].x = (block1 >> (56 - 32*i)) & 0xFF;
		result[i + 0].y = (block1 >> (48 - 32*i)) & 0xFF;
		result[i + 0].z = (block1 >> (40 - 32*i)) & 0xFF;
		result[i + 0].w = (block1 >> (32 - 32*i)) & 0xFF;
		
		result[i + 2].x = (block2 >> (56 - 32*i)) & 0xFF;
		result[i + 2].y = (block2 >> (48 - 32*i)) & 0xFF;
		result[i + 2].z = (block2 >> (40 - 32*i)) & 0xFF;
		result[i + 2].w = (block2 >> (32 - 32*i)) & 0xFF;
	}
}

int loadFileIntoMemory( char **memory, const char *filename, ciphertype type ) {
	size_t file_size;
	char pad;
	
	// Opens the file
	FILE *fp = fopen(filename, "rb");
	
	// Makes sure the file was really opened
	if (fp == NULL) {
		*memory = NULL;
		return -1;
	}
	
	// Determines file size
	fseek(fp, 0, SEEK_END);
	file_size = ftell(fp);
	
	// Returns file pointer to the beginning
	fseek(fp, 0, SEEK_SET);
	
	// Calculates padding
	switch (type) {
		case aes128:
			pad = (-file_size) % 16;
			break;
		case aes192:
			pad = (-file_size) % 24;
			break;
		case aes256:
			pad = (-file_size) % 32;
			break;
	}
	file_size += pad;
	
	// Allocates memory
	*memory = (char *) malloc(file_size + 1);
	
	// Loads file into memory, making sure the copy's size is the same as the original's
	if (file_size - pad != fread(*memory, sizeof(char), file_size, fp)) {
		free(*memory);
		return -2;
	}
	
	// Closes the file handler (?)
	fclose(fp);
	
	// Pads the message
	for (int i = 0; i < pad; ++i) {
		(*memory)[file_size - pad + i] = pad;
	}
	
	// O que raios é que isso faz?
	(*memory)[file_size] = 0;
	
	return file_size;
}

int writeToFile( char *memory, const char *filename, size_t file_size ) {
	FILE *file = fopen(filename, "wb");
	char possible_pad = memory[file_size - 1];
	char counter = 0;
	
	while (memory[file_size - counter - 1] == possible_pad)
		counter++;
	
	if (counter == possible_pad)
		file_size -= possible_pad;
	
	fwrite(memory, sizeof(char), file_size, file);
	fclose(file);
	return 0;
}

int main( int argc, char *argv[] ) {
	uchar4 cipher_key[4];
	uchar4 *host_round_keys;
	uchar4 *dev_cipher_key, *dev_round_keys;
	char *dev_file;
	char *host_file;
	uint8_t *dev_sbox, *dev_inv_sbox;
	size_t file_size;
	
	// Generates 128-bit cipher-key from two uint64_t
	generateCipherKey128(cipher_key, 0x2b7e151628aed2a6, 0xabf7158809cf4f3c);
	
	// Loads file from disk
	file_size = loadFileIntoMemory(&host_file, argv[1], aes128);
	
	// Allocates memory for various resources
	host_round_keys =   (uchar4 *) malloc(11 * 4 * sizeof(uchar4));
	cudaMalloc((void **) &dev_round_keys, 11 * 4 * sizeof(uchar4));
	cudaMalloc((void **) &dev_cipher_key,      4 * sizeof(uchar4));
	cudaMalloc((void **) &dev_sbox,          256 * sizeof(uint8_t));
	cudaMalloc((void **) &dev_inv_sbox,      256 * sizeof(uint8_t));
	cudaMalloc((void **) &dev_file,    file_size * sizeof(char));
	
	// Copies memory to the device
	cudaMemcpy(dev_cipher_key, cipher_key,      4 * sizeof(uchar4), cudaMemcpyHostToDevice);
	cudaMemcpy(dev_sbox,       s_box,        256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(dev_inv_sbox,   inv_s_box,    256 * sizeof(uint8_t), cudaMemcpyHostToDevice);
	cudaMemcpy(dev_file,       host_file, file_size * sizeof(char), cudaMemcpyHostToDevice);
	
	
	
	// Generates the round keys, storing them on the global memory
	generateRoundKeys128 <<< 1, 1, 4 * 11 * sizeof(uchar4) >>>
		(
			dev_cipher_key, dev_round_keys, dev_sbox
		);
	cudaThreadSynchronize();
	
	
	
	// Encrypts the file on the device
	encrypt128 <<< ((file_size/16 + NUM_THREADS - 1)/ NUM_THREADS), 256 >>>
		(
			dev_file, file_size, dev_round_keys, dev_sbox
		);
	cudaThreadSynchronize();
	
	// Copies back the result from the device
	cudaMemcpy(host_file, dev_file, file_size, cudaMemcpyDeviceToHost);
	
	// Writes the encrypted file to disk
	writeToFile(host_file, argv[2], file_size);
	
	
	
	
	// Decrypts the file
	decrypt128 <<< ((file_size/16 + NUM_THREADS - 1)/ NUM_THREADS), NUM_THREADS >>>
		(
			dev_file, file_size, dev_round_keys, dev_inv_sbox
		);
	cudaThreadSynchronize();
	
	// Copies back the result from the device
	cudaMemcpy(host_file, dev_file, file_size, cudaMemcpyDeviceToHost);
	
	// Writes the encrypted file to disk
	writeToFile(host_file, argv[3], file_size);
	
	
	
	
/*
	cudaMemcpy(host_round_keys, dev_round_keys, 11 * 4 * sizeof(uchar4), cudaMemcpyDeviceToHost);
	
	printf("%02x %02x %02x %02x\n", host_round_keys[4].x, host_round_keys[5].x, host_round_keys[6].x, host_round_keys[7].x);
	printf("%02x %02x %02x %02x\n", host_round_keys[4].y, host_round_keys[5].y, host_round_keys[6].y, host_round_keys[7].y);
	printf("%02x %02x %02x %02x\n", host_round_keys[4].z, host_round_keys[5].z, host_round_keys[6].z, host_round_keys[7].z);
	printf("%02x %02x %02x %02x\n", host_round_keys[4].w, host_round_keys[5].w, host_round_keys[6].w, host_round_keys[7].w);
*/	
	
	// Frees up memory that is not used anymore
	free(host_round_keys);
	free(host_file);
	cudaFree(dev_cipher_key);
	cudaFree(dev_round_keys);
	cudaFree(dev_sbox);
	cudaFree(dev_inv_sbox);
	cudaFree(dev_file);
	
	return 0;
}