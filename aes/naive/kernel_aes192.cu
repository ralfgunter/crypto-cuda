#include "kernel_aes192.h"

// Key scheduling
__device__ uchar4 rotWord192( uchar4 *state, uint8_t round_number )
{
	uchar4 result;
	
	result.x = state[6*round_number - 1].y;
	result.y = state[6*round_number - 1].z;
	result.z = state[6*round_number - 1].w;
	result.w = state[6*round_number - 1].x;
	
	return result;
}

__device__ void roundKeyGeneration192( uchar4 *keys, uint8_t *sbox )
{
	uchar4 temp;
	uint8_t rcon[] = {
		0x01, 0x02, 0x04,
		0x08, 0x10,	0x20,
		0x40, 0x80, 0x1b,
		0x36, 0x6c, 0xd8
	};
	
#pragma unroll
	for (int n = 1; n <= 12; ++n) {
		temp = key_subBytes(rotWord192(keys, n), sbox);
		keys[6*n + 0] = xorTransformation(temp, keys[6*(n-1)], rcon[n-1]);
		
		keys[6*n + 1] = xorTransformation(keys[6*n + 0], keys[6*(n-1) + 1], 0);
		keys[6*n + 2] = xorTransformation(keys[6*n + 1], keys[6*(n-1) + 2], 0);
		keys[6*n + 3] = xorTransformation(keys[6*n + 2], keys[6*(n-1) + 3], 0);
		keys[6*n + 4] = xorTransformation(keys[6*n + 3], keys[6*(n-1) + 4], 0);
		keys[6*n + 5] = xorTransformation(keys[6*n + 4], keys[6*(n-1) + 5], 0);
	}
}

__global__ void generateRoundKeys192( uchar4 *cipher_key, uchar4 *round_keys, uint8_t *sbox )
{
	__shared__ uchar4 shmem[6 * 13 * sizeof(uchar4)];
	
#pragma unroll
	for (int i = 0; i < 6; ++i) {
		shmem[i].x = cipher_key[i].x;
		shmem[i].y = cipher_key[i].y;
		shmem[i].z = cipher_key[i].z;
		shmem[i].w = cipher_key[i].w;
	}
	
	roundKeyGeneration192(shmem, sbox);
	
#pragma unroll
	for (int i = 0; i < 13; ++i) {
#pragma unroll
		for (int p = 0; p < 6; ++p) {
			round_keys[6*i + p].x = shmem[6*i + p].x;
			round_keys[6*i + p].y = shmem[6*i + p].y;
			round_keys[6*i + p].z = shmem[6*i + p].z;
			round_keys[6*i + p].w = shmem[6*i + p].w;
		}
	}
}


// Encryption
__device__ void encryptBlock192( uchar4 *state, uchar4 *keys, uint8_t *sbox )
{
	// First round
	addRoundKey(state, keys,  0);
	
	// Rounds 1 to 11
	// 1
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  1);
	// 2
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  2);
	// 3
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  3);
	// 4
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  4);
	// 5
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  5);
	// 6
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  6);
	// 7
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  7);
	// 8
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  8);
	// 9
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys,  9);
	// 10
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 10);
	// 11
	enc_subBytes(state, sbox);
	shiftRows(state);
	mixColumns(state);
	addRoundKey(state, keys, 11);
	
	// Last round
	enc_subBytes(state, sbox);
	shiftRows(state);
	addRoundKey(state, keys, 12);
}

__global__ void encrypt192( char *file, int file_size, uchar4 *round_keys, uint8_t *sbox )
{
	__shared__ uchar4  sh_round_keys[13 * 4 * sizeof(uchar4)];
	__shared__ uint8_t         sh_sbox[256 * sizeof(uint8_t)];
	
	int id = NUM_THREADS * blockIdx.x + threadIdx.x;
	
	for (int i = 0; i < 52; ++i) {
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
		
		encryptBlock192(state, sh_round_keys, sh_sbox);
		
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
__device__ void decryptBlock192( uchar4 *state, uchar4 *keys, uint8_t *inv_sbox )
{
	// First round
	addRoundKey(state, keys, 12);
	
	// Last round?
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys, 11);
	
	// Rounds 1 to 11
	// 1
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys, 10);
	// 2
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  9);
	// 3
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  8);
	// 4
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  7);
	// 5
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  6);
	// 6
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  5);
	// 7
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  4);
	// 8
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  3);
	// 9
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  2);
	// 10
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  1);
	// 11
	invMixColumns(state);
	invShiftRows(state);
	invSubBytes(state, inv_sbox);
	addRoundKey(state, keys,  0);
}

__global__ void decrypt192( char *file, int file_size, uchar4 *round_keys, uint8_t *inv_sbox )
{
	__shared__ uchar4  sh_round_keys[13 * 4 * sizeof(uchar4)];
	__shared__ uint8_t         sh_sbox[256 * sizeof(uint8_t)];
	
	int id = NUM_THREADS * blockIdx.x + threadIdx.x;
	
	for (int i = 0; i < 52; ++i) {
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
		
		decryptBlock192(state, sh_round_keys, sh_sbox);
		
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
