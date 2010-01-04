#include "kernel_aes128.h"

// Key scheduling
__device__ uchar4 rotWord128( uchar4 *state, uint8_t round_number )
{
	uchar4 result;
	
	result.x = state[4*round_number - 1].y;
	result.y = state[4*round_number - 1].z;
	result.z = state[4*round_number - 1].w;
	result.w = state[4*round_number - 1].x;
	
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
		temp = key_subBytes(rotWord128(keys, n), sbox);
		keys[4*n + 0] = xorTransformation(temp, keys[4*(n-1) + 0], rcon[n-1]);
		
		keys[4*n + 1] = xorTransformation(keys[4*n + 0], keys[4*(n-1) + 1], 0);
		keys[4*n + 2] = xorTransformation(keys[4*n + 1], keys[4*(n-1) + 2], 0);
		keys[4*n + 3] = xorTransformation(keys[4*n + 2], keys[4*(n-1) + 3], 0);
	}
}

__global__ void generateRoundKeys128( uchar4 *cipher_key, uchar4 *round_keys, uint8_t *sbox )
{
	__shared__ uchar4 shmem[4 * 11 * sizeof(uchar4)];
	
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


// Encryption
__device__ void encryptBlock128( uchar4 *state, uchar4 *keys, uint8_t *sbox )
{
	// First round
	addRoundKey(state, keys, 0);
	
	// Rounds 1 to 9
	// 1
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 1);
	// 2
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 2);
	// 3
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 3);
	// 4
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 4);
	// 5
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 5);
	// 6
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 6);
	// 7
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 7);
	// 8
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 8);
	// 9
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 9);
	
	// Last round
	enc_subBytes(state, sbox);
	shiftRows(state);
	addRoundKey(state, keys, 10);
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


// Decryption
__device__ void decryptBlock128( uchar4 *state, uchar4 *keys, uint8_t *inv_sbox )
{
	// First round
	addRoundKey(state, keys, 10);
	
	// Last round?
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  9);
	
	// Rounds 1 to 9
	// 1
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  8);
	// 2
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  7);
	// 3
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  6);
	// 4
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  5);
	// 5
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  4);
	// 6
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  3);
	// 7
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  2);
	// 8
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  1);
	// 9
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  0);
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
