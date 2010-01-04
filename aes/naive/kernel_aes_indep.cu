#include <stdint.h>

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


// Key scheduling
__device__ uchar4 key_subBytes( uchar4 word, uint8_t *sbox )
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

// Encryption
__device__ void enc_subBytes( uchar4 *state, uint8_t *sbox )
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

__device__ void shiftRows( uchar4 *state )
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

__device__ void mixColumns( uchar4 *state )
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

__device__ void addRoundKey( uchar4 *state, uchar4 *keys, uint8_t round_number )
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
	
	// Third column
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


// Decryption
__device__ void invSubBytes( uchar4 *state, uint8_t *inv_sbox )
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

__device__ void invShiftRows( uchar4 *state )
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

__device__ void invMixColumns( uchar4 *state )
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
