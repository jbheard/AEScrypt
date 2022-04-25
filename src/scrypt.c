#include <stdlib.h> // malloc, free
#include <stdio.h>  // malloc, free
#include <stdint.h> // int32_t
#include <string.h> // memcpy

#include "sha256.h" // sha256
#include "scrypt.h"

/**************** Static Utility Functions *****************/

// Function prototypes for static utilities (for use in this file only)
static void XOR(uint8_t *, const uint8_t *, int);
static void INT(uint8_t *, int32_t);
static void malloc2D(uint8_t ***, int, int);
static void free2D(uint8_t **, int);
static uint64_t integerify(void *, size_t);
static void scryptBlockMix(int, uint8_t *);
static void scryptROMix(int, int, uint8_t *);
static void salsa20_core(uint32_t[16],uint32_t[16]);

static void XOR(uint8_t *dest, const uint8_t *src, int len) {
	for(int i = 0; i < len; i++)
		dest[i] ^= src[i];
}

static void INT(uint8_t *res, int32_t i) {
	res[0] = (i >> 24) & 0xFF;
	res[1] = (i >> 16) & 0xFF;
	res[2] = (i >>  8) & 0xFF;
	res[3] = i & 0xFF;
}

static void malloc2D(uint8_t ***dest, int d1, int d2) {
	uint8_t **T;

	*dest = malloc(d1 * sizeof (uint8_t*));
	T = *dest;

	if(T == NULL) {
		perror("malloc");
		abort();
	}
	for(int i = 0; i < d1; i++) {
		T[i] = malloc(d2);
		if(T[i] == NULL) {
			perror("malloc");
			abort();
		}
	}
}

static void free2D(uint8_t **dest, int d1) {
	for(int i = 0; i < d1; i ++)
		free(dest[i]);
	free(dest);
}

static uint64_t integerify(void * B, size_t r) {
	uint32_t * X = (void *)((uintptr_t)(B) + (2 * r - 1) * 64);

	return (((uint64_t)(X[13]) << 32) + X[0]);
}

static void scryptBlockMix(int r, uint8_t *B) {
	uint8_t *Y = malloc(128*r);
	uint8_t X[64];
	uint8_t T[64];

	memcpy(X, &B[64*(2*r-1)], 64);

	// Step 2
	for(int i = 0; i < 2*r; i++) {
		memcpy(T, B + 64*i, 64);
		XOR(T, X, 64);
		salsa20_core((uint32_t*)X, (uint32_t*)T);
		if(i % 2 == 0) // even indices (0...r-1)
			memcpy(Y + (64*i/2), X, 64);
		else // odd indices (r...2r-1)
			memcpy(Y + (64*(i/2) + 64*r), X, 64);
	}
	memcpy(B, Y, 128*r);
	free(Y);
}

static void scryptROMix(int r, int n, uint8_t *B) {
	int j;
	uint8_t **V;

	// Step 1
	uint8_t *X = malloc(r*128);
	memcpy(X, B, r*128);	
	malloc2D(&V, n, r*128);

	// Step 2
	for(int i = 0; i < n; i++) {
		memcpy(V[i], X, 128*r);
		scryptBlockMix(r, X);
	}

	// Step 3
	for(int i = 0; i < n; i++) {
		j = integerify(X, r) % n;
		XOR(X, V[j], 128*r);
		scryptBlockMix(r, X);
	}

	// Step 4
	memcpy(B, X, r*128);
	free2D(V, n);
	free(X);
}

/**
 * salsa20/8 Core algorithm from rfc7914 (section 3)
 * TODO: endianness conversion and alignment (see http://cr.yp.to/snuffle/spec.pdf for Salsa20 spec)
 */
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
static void salsa20_core(uint32_t out[16],uint32_t in[16]) {
	int i;
	uint32_t x[16];
	for (i = 0;i < 16;++i) x[i] = in[i];

	for (i = 8;i > 0;i -= 2) {
		x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
		x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
		x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
		x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
		x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
		x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
		x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
		x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
		x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
		x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
		x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
		x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
		x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
		x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
		x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
		x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
	}

	for (i = 0;i < 16;++i) out[i] = x[i] + in[i];
}

/***************** End of Utility Functions *****************/

void initScryptInfo(struct ScryptInfo *info) {
	info->salt = NULL;
	info->slen = 0;
	info->n = 16384;
	info->p = 1;
	info->r = 8;
	info->dklen = 32;
}

void HMAC_SHA256(const uint8_t *key, int klen, const uint8_t *message, int mlen, uint8_t *out) {
	const int bsize = 64; // sha256 block size (bytes)
	const int hsize = 32; // sha256 output size (bytes)

	uint8_t temp[mlen+bsize];       // for intermediate steps
	uint8_t usekey[bsize];          // The buffer we will use for the key
	uint8_t okp[bsize], ikp[bsize]; // Outer and Inner Key Pads
	memcpy(usekey, key, klen);   // Copy original key into key area

	if(klen > bsize) {
		// Hash key down to hash output size
		sha256((char*)key, (char*)usekey, klen);
		klen = hsize;
	}
	if(klen < bsize) {
		memset(usekey+klen, 0, bsize-klen);
	}

	memset(okp, 0x5c, bsize); // Fill okp with 5C (opad)
	memset(ikp, 0x36, bsize); // Fill ikp with 36 (ipad)
	XOR(okp, usekey, bsize);  // = okp xor key
	XOR(ikp, usekey, bsize);  // = ikp xor key

	// Append message to inner key
	memcpy(temp, ikp, bsize);
	memcpy(temp+bsize, message, mlen);
	// hash inner key + message
	sha256((char*)temp, (char*)out, mlen+bsize);

	// Append result hash to outer key
	memcpy(temp, okp, bsize);
	memcpy(temp+bsize, out, hsize);
	// Hash again for final result
	sha256((char*)temp, (char*)out, bsize+hsize);
}

uint8_t *PBKDF2(const uint8_t *passwd, int plen, const uint8_t *salt, int slen, int c, int dklen) {
	const int hlen = 32;           // SHA-256 output length in bytes
	int r, ctr = 0;                // Progress tracking
	uint8_t T[hlen];                  // Tracks progress of final result
	uint8_t *final = malloc(dklen);   // Final result, returned to user
	uint8_t Uprev[hlen], Ucurr[hlen]; // For our previous and current blocks
	uint8_t rnd1[slen+4];             // round 1 buffer (salt+INT(i))
	memcpy(rnd1, salt, slen);

	// F(P, S, c, i) (RFC 2898 p10 step 3)
	for(int i = 1; dklen > 0; i++) {
		// Get 4 byte, big-endian integer repr
		INT(rnd1+slen, i);
		// Calculate initial hash (U_1) for this round
		HMAC_SHA256(passwd, plen, rnd1, slen+4, Uprev);
		memcpy(T, Uprev, hlen);

		for(int j = 1; j < c; j++) {
			// Get PRF output for current U
			HMAC_SHA256(passwd, plen, Uprev, hlen, Ucurr);
			// Running XOR of T with current U
			XOR(T, Ucurr, hlen);
			// Update previous
			memcpy(Uprev, Ucurr, hlen);
		}

		// Step 4 key extraction
		r = (dklen < hlen) ? dklen : hlen;
		memcpy(final+ctr, T, r);
		ctr += r;
		dklen -= r;
	}

	return final;
}

uint8_t *scrypt(char *passwd, int plen, struct ScryptInfo *info) {
	uint8_t *B;
	B = PBKDF2((uint8_t*)passwd, plen, info->salt, info->slen, 1, info->p * 128 * info->r);

	for(int i = 0; i < info->p; i++) {
		scryptROMix(info->r, info->n, B + 128 * info->r * i);
	}

	uint8_t* result = PBKDF2((uint8_t*)passwd, plen, B, info->r*info->p*128, 1, info->dklen);
	free(B);
	
	return result;
}

