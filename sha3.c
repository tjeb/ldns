/* sha3.c - an implementation of Secure Hash Algorithm 3 (Keccak).
 * based on the
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * Copyright: 2013 Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission is hereby granted,  free of charge,  to any person  obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction,  including without limitation
 * the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
 * and/or sell copies  of  the Software,  and to permit  persons  to whom the
 * Software is furnished to do so.
 *
 * This program  is  distributed  in  the  hope  that it will be useful,  but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "ldns/sha3_byte_order.h"
#include "ldns/sha3.h"

/* constants */
#define NumberOfRounds 24

/* SHA3 (Keccak) constants for 24 rounds */
static uint64_t keccak_round_constants[NumberOfRounds] = {
	I64(0x0000000000000001), I64(0x0000000000008082), I64(0x800000000000808A), I64(0x8000000080008000),
	I64(0x000000000000808B), I64(0x0000000080000001), I64(0x8000000080008081), I64(0x8000000000008009),
	I64(0x000000000000008A), I64(0x0000000000000088), I64(0x0000000080008009), I64(0x000000008000000A),
	I64(0x000000008000808B), I64(0x800000000000008B), I64(0x8000000000008089), I64(0x8000000000008003),
	I64(0x8000000000008002), I64(0x8000000000000080), I64(0x000000000000800A), I64(0x800000008000000A),
	I64(0x8000000080008081), I64(0x8000000000008080), I64(0x0000000080000001), I64(0x8000000080008008)
};

/* Initializing a sha3 context for given number of output bits */
static void rhash_keccak_init(sha3_ctx *ctx, unsigned bits)
{
	/* NB: The Keccak capacity parameter = bits * 2 */
	unsigned rate = 1600 - bits * 2;

	memset(ctx, 0, sizeof(sha3_ctx));
	ctx->block_size = rate / 8;
	assert(rate <= 1600 && (rate % 64) == 0);
}

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void rhash_sha3_224_init(sha3_ctx *ctx)
{
	rhash_keccak_init(ctx, 224);
}

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void rhash_sha3_256_init(sha3_ctx *ctx)
{
	rhash_keccak_init(ctx, 256);
}

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void rhash_sha3_384_init(sha3_ctx *ctx)
{
	rhash_keccak_init(ctx, 384);
}

/**
 * Initialize context before calculating hash.
 *
 * @param ctx context to initialize
 */
void rhash_sha3_512_init(sha3_ctx *ctx)
{
	rhash_keccak_init(ctx, 512);
}

/* Keccak theta() transformation */
static void keccak_theta(uint64_t *A)
{
	unsigned int x;
	uint64_t C[5], D[5];

	for (x = 0; x < 5; x++) {
		C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
	}
	D[0] = ROTL64(C[1], 1) ^ C[4];
	D[1] = ROTL64(C[2], 1) ^ C[0];
	D[2] = ROTL64(C[3], 1) ^ C[1];
	D[3] = ROTL64(C[4], 1) ^ C[2];
	D[4] = ROTL64(C[0], 1) ^ C[3];

	for (x = 0; x < 5; x++) {
		A[x]      ^= D[x];
		A[x + 5]  ^= D[x];
		A[x + 10] ^= D[x];
		A[x + 15] ^= D[x];
		A[x + 20] ^= D[x];
	}
}

/* Keccak pi() transformation */
static void keccak_pi(uint64_t *A)
{
	uint64_t A1;
	A1 = A[1];
	A[ 1] = A[ 6];
	A[ 6] = A[ 9];
	A[ 9] = A[22];
	A[22] = A[14];
	A[14] = A[20];
	A[20] = A[ 2];
	A[ 2] = A[12];
	A[12] = A[13];
	A[13] = A[19];
	A[19] = A[23];
	A[23] = A[15];
	A[15] = A[ 4];
	A[ 4] = A[24];
	A[24] = A[21];
	A[21] = A[ 8];
	A[ 8] = A[16];
	A[16] = A[ 5];
	A[ 5] = A[ 3];
	A[ 3] = A[18];
	A[18] = A[17];
	A[17] = A[11];
	A[11] = A[ 7];
	A[ 7] = A[10];
	A[10] = A1;
	/* note: A[ 0] is left as is */
}

/* Keccak chi() transformation */
static void keccak_chi(uint64_t *A)
{
	int i;
	for (i = 0; i < 25; i += 5) {
		uint64_t A0 = A[0 + i], A1 = A[1 + i];
		A[0 + i] ^= ~A1 & A[2 + i];
		A[1 + i] ^= ~A[2 + i] & A[3 + i];
		A[2 + i] ^= ~A[3 + i] & A[4 + i];
		A[3 + i] ^= ~A[4 + i] & A0;
		A[4 + i] ^= ~A0 & A1;
	}
}

static void rhash_sha3_permutation(uint64_t *state)
{
	int round;
	for (round = 0; round < NumberOfRounds; round++)
	{
		keccak_theta(state);

		/* apply Keccak rho() transformation */
		state[ 1] = ROTL64(state[ 1],  1);
		state[ 2] = ROTL64(state[ 2], 62);
		state[ 3] = ROTL64(state[ 3], 28);
		state[ 4] = ROTL64(state[ 4], 27);
		state[ 5] = ROTL64(state[ 5], 36);
		state[ 6] = ROTL64(state[ 6], 44);
		state[ 7] = ROTL64(state[ 7],  6);
		state[ 8] = ROTL64(state[ 8], 55);
		state[ 9] = ROTL64(state[ 9], 20);
		state[10] = ROTL64(state[10],  3);
		state[11] = ROTL64(state[11], 10);
		state[12] = ROTL64(state[12], 43);
		state[13] = ROTL64(state[13], 25);
		state[14] = ROTL64(state[14], 39);
		state[15] = ROTL64(state[15], 41);
		state[16] = ROTL64(state[16], 45);
		state[17] = ROTL64(state[17], 15);
		state[18] = ROTL64(state[18], 21);
		state[19] = ROTL64(state[19],  8);
		state[20] = ROTL64(state[20], 18);
		state[21] = ROTL64(state[21],  2);
		state[22] = ROTL64(state[22], 61);
		state[23] = ROTL64(state[23], 56);
		state[24] = ROTL64(state[24], 14);

		keccak_pi(state);
		keccak_chi(state);

		/* apply iota(state, round) */
		*state ^= keccak_round_constants[round];
	}
}

/**
 * The core transformation. Process the specified block of data.
 *
 * @param hash the algorithm state
 * @param block the message block to process
 * @param block_size the size of the processed block in bytes
 */
static void rhash_sha3_process_block(uint64_t hash[25], const uint64_t *block, size_t block_size)
{
	/* expanded loop */
	hash[ 0] ^= le2me_64(block[ 0]);
	hash[ 1] ^= le2me_64(block[ 1]);
	hash[ 2] ^= le2me_64(block[ 2]);
	hash[ 3] ^= le2me_64(block[ 3]);
	hash[ 4] ^= le2me_64(block[ 4]);
	hash[ 5] ^= le2me_64(block[ 5]);
	hash[ 6] ^= le2me_64(block[ 6]);
	hash[ 7] ^= le2me_64(block[ 7]);
	hash[ 8] ^= le2me_64(block[ 8]);
	/* if not sha3-512 */
	if (block_size > 72) {
		hash[ 9] ^= le2me_64(block[ 9]);
		hash[10] ^= le2me_64(block[10]);
		hash[11] ^= le2me_64(block[11]);
		hash[12] ^= le2me_64(block[12]);
		/* if not sha3-384 */
		if (block_size > 104) {
			hash[13] ^= le2me_64(block[13]);
			hash[14] ^= le2me_64(block[14]);
			hash[15] ^= le2me_64(block[15]);
			hash[16] ^= le2me_64(block[16]);
			/* if not sha3-256 */
			if (block_size > 136) {
				hash[17] ^= le2me_64(block[17]);
#ifdef FULL_SHA3_FAMILY_SUPPORT
				/* if not sha3-224 */
				if (block_size > 144) {
					hash[18] ^= le2me_64(block[18]);
					hash[19] ^= le2me_64(block[19]);
					hash[20] ^= le2me_64(block[20]);
					hash[21] ^= le2me_64(block[21]);
					hash[22] ^= le2me_64(block[22]);
					hash[23] ^= le2me_64(block[23]);
					hash[24] ^= le2me_64(block[24]);
				}
#endif
			}
		}
	}
	/* make a permutation of the hash */
	rhash_sha3_permutation(hash);
}

#define SHA3_FINALIZED 0x80000000

/**
 * Calculate message hash.
 * Can be called repeatedly with chunks of the message to be hashed.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param msg message chunk
 * @param size length of the message chunk
 */
void rhash_sha3_update(sha3_ctx *ctx, const unsigned char *msg, size_t size)
{
	size_t index = (size_t)ctx->rest;
	size_t block_size = (size_t)ctx->block_size;

	if (ctx->rest & SHA3_FINALIZED) return; /* too late for additional input */
	ctx->rest = (unsigned)((ctx->rest + size) % block_size);

	/* fill partial block */
	if (index) {
		size_t left = block_size - index;
		memcpy((char*)ctx->message + index, msg, (size < left ? size : left));
		if (size < left) return;

		/* process partial block */
		rhash_sha3_process_block(ctx->hash, ctx->message, block_size);
		msg  += left;
		size -= left;
	}
	while (size >= block_size) {
		uint64_t* aligned_message_block;
		if (IS_ALIGNED_64(msg)) {
			/* the most common case is processing of an already aligned message
			without copying it */
			aligned_message_block = (uint64_t*)msg;
		} else {
			memcpy(ctx->message, msg, block_size);
			aligned_message_block = ctx->message;
		}

		rhash_sha3_process_block(ctx->hash, aligned_message_block, block_size);
		msg  += block_size;
		size -= block_size;
	}
	if (size) {
		memcpy(ctx->message, msg, size); /* save leftovers */
	}
}

/**
 * Store calculated hash into the given array.
 *
 * @param ctx the algorithm context containing current hashing state
 * @param result calculated hash in binary form
 */
void rhash_sha3_final(sha3_ctx *ctx, unsigned char* result)
{
	size_t digest_length = 100 - ctx->block_size / 2;
	const size_t block_size = ctx->block_size;

	if (!(ctx->rest & SHA3_FINALIZED))
	{
		/* clear the rest of the data queue */
		memset((char*)ctx->message + ctx->rest, 0, block_size - ctx->rest);
		((char*)ctx->message)[ctx->rest] |= 0x06;
		((char*)ctx->message)[block_size - 1] |= 0x80;

		/* process final block */
		rhash_sha3_process_block(ctx->hash, ctx->message, block_size);
		ctx->rest = SHA3_FINALIZED; /* mark context as finalized */
	}

	assert(block_size > digest_length);
	if (result) me64_to_le_str(result, ctx->hash, digest_length);
}

#ifdef USE_KECCAK
/**
* Store calculated hash into the given array.
*
* @param ctx the algorithm context containing current hashing state
* @param result calculated hash in binary form
*/
void rhash_keccak_final(sha3_ctx *ctx, unsigned char* result)
{
	size_t digest_length = 100 - ctx->block_size / 2;
	const size_t block_size = ctx->block_size;

	if (!(ctx->rest & SHA3_FINALIZED))
	{
		/* clear the rest of the data queue */
		memset((char*)ctx->message + ctx->rest, 0, block_size - ctx->rest);
		((char*)ctx->message)[ctx->rest] |= 0x01;
		((char*)ctx->message)[block_size - 1] |= 0x80;

		/* process final block */
		rhash_sha3_process_block(ctx->hash, ctx->message, block_size);
		ctx->rest = SHA3_FINALIZED; /* mark context as finalized */
	}

	assert(block_size > digest_length);
	if (result) me64_to_le_str(result, ctx->hash, digest_length);
}
#endif /* USE_KECCAK */

unsigned char *
ldns_sha3_256(unsigned char *data, unsigned int data_len, unsigned char *digest)
{
    sha3_ctx ctx;
    if (digest == NULL) {
        digest = (unsigned char*) malloc(LDNS_SHA3_256_DIGEST_LENGTH);
    }
    printf("[XX] digesting data\n");
    rhash_sha3_256_init(&ctx);
    rhash_sha3_update(&ctx, data, data_len);
    rhash_sha3_final(&ctx, digest);
    printf("[XX] done digesting data\n");
    return digest;
}

unsigned char *
ldns_sha3_384(unsigned char *data, unsigned int data_len, unsigned char *digest)
{
    sha3_ctx ctx;
    if (digest == NULL) {
        digest = (unsigned char*) malloc(LDNS_SHA3_384_DIGEST_LENGTH);
    }
    rhash_sha3_384_init(&ctx);
    rhash_sha3_update(&ctx, data, data_len);
    rhash_sha3_final(&ctx, digest);
    return digest;
}

unsigned char *
ldns_sha3_512(unsigned char *data, unsigned int data_len, unsigned char *digest)
{
    sha3_ctx ctx;
    if (digest == NULL) {
        digest = (unsigned char*) malloc(LDNS_SHA3_512_DIGEST_LENGTH);
    }
    rhash_sha3_512_init(&ctx);
    rhash_sha3_update(&ctx, data, data_len);
    rhash_sha3_final(&ctx, digest);
    return digest;
}

// PSS-related functions
// for SHA3 we need to digest twice, so we have a helper function to
// keep the PSS algorithm more readable
unsigned int
sha3_digest_len(ldns_algorithm algorithm)
{
	switch (algorithm) {
	case LDNS_SIGN_RSASHA3_256:
		return LDNS_SHA3_256_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_384:
		return LDNS_SHA3_384_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_512:
		return LDNS_SHA3_512_DIGEST_LENGTH;
		break;
	default:
		fprintf(stderr, "Error: called sha3_digest_len without rsasha3 algorithm\n");
		return 0;
	}
}

unsigned char*
sha3_digest(unsigned char* data, unsigned int data_len, ldns_algorithm algorithm, unsigned int* digest_len)
{
	if (digest_len != NULL) {
		*digest_len = sha3_digest_len(algorithm);
	}
	switch (algorithm) {
	case LDNS_SIGN_RSASHA3_256:
		printf("[XX] sha3 256\n");
		return ldns_sha3_256(data, data_len, NULL);
		break;
	case LDNS_SIGN_RSASHA3_384:
		printf("[XX] sha3 384\n");
		return ldns_sha3_384(data, data_len, NULL);
		break;
	case LDNS_SIGN_RSASHA3_512:
		printf("[XX] sha3 512\n");
		return ldns_sha3_512(data, data_len, NULL);
		break;
	default:
		fprintf(stderr, "Error: called ldns_sign_public_rsasha3 without rsasha3 algorithm\n");
		return NULL;
	}
}

void I2OSP(unsigned char* output, unsigned int X, unsigned int xLen)
{
	unsigned int i;
	memset(output, 0, xLen);
	for (i = xLen-1; i > 0; i--) {
		output[i] = (uint8_t) (X % 256);
		X = X / 256;
	}
}

unsigned char*
MGF(unsigned char* mgfSeed, unsigned int mgfSeed_len, unsigned int maskLen, ldns_algorithm algorithm)
{
	(void)mgfSeed;
	(void)algorithm;

	unsigned int digest_len = sha3_digest_len(algorithm);
	unsigned int counter;
	unsigned int steps = (maskLen / digest_len);
	unsigned char* tmpseed;
	unsigned char* tmpdata;
	unsigned char* result;
	unsigned char* digest;

	if (maskLen % digest_len > 0) {
		steps++;
	}

	tmpseed = (unsigned char*) malloc(mgfSeed_len + 4);
	tmpdata = (unsigned char*) malloc(digest_len * steps);
	memcpy(tmpseed, mgfSeed, mgfSeed_len);

	for (counter = 0; counter < steps; counter++) {
	    I2OSP(tmpseed + mgfSeed_len, counter, 4);
	    digest = sha3_digest(tmpseed, mgfSeed_len + 4, algorithm, NULL);
	    memcpy(tmpdata + counter*digest_len, digest, digest_len);
	    free(digest);
	}

	result = (unsigned char*) malloc(maskLen);
	memcpy(result, tmpdata, maskLen);
	free(tmpdata);
	return result;
}

static inline void
hexdump(FILE*out, const char* str, unsigned char* data, unsigned int data_len) {
	fflush(stdout);
	fflush(stderr);
	fprintf(out, "%s:\n", str);
	unsigned int i;
	for (i = 0; i < data_len; i++) {
		if (i % 10 == 0) {
			fprintf(out, "\n%u:\t", i);
		}
		fprintf(out, "0x%02x ", data[i]);
	}
	fprintf(out, "\n");
	fflush(stdout);
	fflush(stderr);
}

unsigned char*
emsa_pss_encode(unsigned char* M, unsigned int M_len, unsigned int emBits, unsigned int* emLen, ldns_algorithm algorithm)
{
	unsigned char* mHash = NULL;
	unsigned int mHash_len;

	// Hard coded salt for now
	char* salt = NULL;
	unsigned int salt_len;

	unsigned char* MM = NULL;
	unsigned int MM_len;

	unsigned char* H = NULL;
	unsigned int H_len;

	unsigned char* PS = NULL;
	unsigned int PS_len;

	unsigned char* DB = NULL;
	unsigned int DB_len;

	unsigned char* dbMask = NULL;
	unsigned int dbMask_len;

	unsigned char* maskedDB = NULL;
	unsigned int maskedDB_len;

	unsigned char* EM = NULL;
	unsigned int EM_len;

	unsigned int i;

	// settings from draft-muks: EM_len is keysize (-1); salt_len is digest len
	// From RFC8017:
	// Note that the octet length of EM will be one less than k if
	// modBits - 1 is divisible by 8 and equal to k otherwise.
	EM_len = emBits / 8;
	if (emBits % 8 > 0) {
	    EM_len++;
	}
	// (set salt len after first digest)

	//1.   If the length of M is greater than the input limitation for
	//     the hash function (2^61 - 1 octets for SHA-1), output
	//     "message too long" and stop.

	// ignore length for now, should be OK

	//2.   Let mHash = Hash(M), an octet string of length hLen.
	mHash = sha3_digest(M, M_len, algorithm, &mHash_len);
	// TODO: check NULL
	salt_len = mHash_len;
	printf("[XX] salt len: %u\n", salt_len);

	//3.   If EM_len < hLen + sLen + 2, output "encoding error" and stop.
	// do we know intended EM_len?
	if (EM_len < mHash_len + salt_len + 2) {
	    // error
	    fprintf(stderr, "PSS Encoding error\n");
	    goto cleanup;
	}

	//4.   Generate a random octet string salt of length sLen; if sLen =
	//     0, then salt is the empty string.

	// fixed salt for now
	salt = (char*) malloc(salt_len);
	memset(salt, 0x00, salt_len);

	//5.   Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	MM_len = 8 + mHash_len + salt_len;
	MM = (unsigned char*) malloc(MM_len);
	memset(MM, 0, 8);
	memcpy(MM+8, mHash, mHash_len);
	memcpy(MM+8+mHash_len, salt, salt_len);

	//6.   Let H = Hash(M'), an octet string of length hLen.
	H = sha3_digest(MM, MM_len, algorithm, &H_len);

	//7.   Generate an octet string PS consisting of EM_len - sLen - hLen
	//     - 2 zero octets.  The length of PS may be 0.
	PS_len = EM_len - salt_len - H_len - 2;
	printf("[XX] PS size: %d\n", PS_len);
	PS = (unsigned char*) malloc(PS_len);
	memset(PS, 0, PS_len);

	//8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     EM_len - hLen - 1.
	DB_len = PS_len + 1 + salt_len;
	if (DB_len != EM_len - mHash_len - 1) {
	    fprintf(stderr, "DB len is wrong?\n");
	    goto cleanup;
	}
	DB = (unsigned char*) malloc(DB_len);
	memcpy(DB, PS, PS_len);
	memset(DB + PS_len, 0x01, 1);
	memcpy(DB + PS_len + 1, salt, salt_len);

	//9.   Let dbMask = MGF(H, EM_len - hLen - 1).
	dbMask_len = EM_len - H_len - 1;
	dbMask = MGF(H, H_len, dbMask_len, algorithm);

	//10.  Let maskedDB = DB \xor dbMask.
	maskedDB_len = dbMask_len;
	maskedDB = (unsigned char*) malloc(maskedDB_len);
	for (i = 0; i < maskedDB_len; i++) {
	    maskedDB[i] = DB[i] ^ dbMask[i];
	}

	//11.  Set the leftmost 8EM_len - emBits bits of the leftmost octet
	//     in maskedDB to zero.
	printf("[XX] Byte zero: %02x\n", maskedDB[0]);
	maskedDB[0] = maskedDB[0] << (EM_len*8 - emBits);
	maskedDB[0] = maskedDB[0] >> (EM_len*8 - emBits);
	printf("[XX] Byte zero: %02x\n", maskedDB[0]);

	//12.  Let EM = maskedDB || H || 0xbc.
	printf("[XX] EM_len: %u\n", EM_len);
	printf("[XX] emBits: %u\n", emBits);
	printf("[XX] maskedDBlen: %u\n", maskedDB_len);
	printf("[XX] H_len: %u\n", H_len);
	// sanity check
	if (EM_len != maskedDB_len + H_len + 1) {
	    fprintf(stderr, "Error in PSS algorithm; sizes do not match up\n");
	    goto cleanup;
	}
	EM = (unsigned char*) malloc(EM_len);
	memcpy(EM, maskedDB, maskedDB_len);
	memcpy(EM+maskedDB_len, H, H_len);
	memset(EM+maskedDB_len+H_len, 0xbc, 1);

	if (emLen != NULL) {
		*emLen = EM_len;
	}

	hexdump(stderr, "EM", EM, EM_len);

	cleanup:
	if (mHash != NULL) { free(mHash); }
	if (salt != NULL) { free(salt); }
	if (MM != NULL) { free(MM); }
	if (H != NULL) { free(H); }
	if (PS != NULL) { free(PS); }
	if (DB != NULL) { free(DB); }
	if (dbMask != NULL) { free(dbMask); }
	if (maskedDB != NULL) { free(maskedDB); }

	return EM;
}

int
emsa_pss_verify(unsigned char* M, unsigned int M_len,
                unsigned char* EM, unsigned int EM_len,
                unsigned int emBits,
                ldns_algorithm algorithm) {
	(void) M;
	(void) M_len;
	(void) EM;
	(void) EM_len;
	(void) emBits;
	(void) algorithm;
	fflush(stdout);
	fflush(stderr);

	int result = 1;

	unsigned int mHash_len;
	unsigned char* mHash = NULL;

	unsigned int maskedDB_len;
	unsigned char* maskedDB = NULL;

	unsigned int H_len;
	unsigned char* H = NULL;

	unsigned int zeroBits;

	unsigned char* dbMask = NULL;

    unsigned int DB_len;
    unsigned char* DB = NULL;
    unsigned int i;

    unsigned int zeroOctets;
    unsigned int oneOctet_pos;

    unsigned char* salt = NULL;
	unsigned int salt_len;

	unsigned int MM_len;
	unsigned char* MM = NULL;

	unsigned int HH_len;
	unsigned char* HH = NULL;


    // 1.   If the length of M is greater than the input limitation for
    //      the hash function (2^61 - 1 octets for SHA-1), output
    //      "inconsistent" and stop.

    // 2.   Let mHash = Hash(M), an octet string of length hLen.
    mHash = sha3_digest(M, M_len, algorithm, &mHash_len);

    // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    salt_len = sha3_digest_len(algorithm);
    if (EM_len < mHash_len + salt_len + 2) {
		fprintf(stderr, "EM len wrong\n");
		goto cleanup;
	}

	hexdump(stderr, "EM", EM, EM_len);

    // 4.   If the rightmost octet of EM does not have hexadecimal value
    //      0xbc, output "inconsistent" and stop.
    if (EM[EM_len-1] != 0xbc) {
		fprintf(stderr, "Last octet of EM not 0xbc\n");
		goto cleanup;
	}

    // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
    //      and let H be the next hLen octets.
    H_len = sha3_digest_len(algorithm);
    maskedDB_len = EM_len - H_len - 1;
    maskedDB = (unsigned char*) malloc(maskedDB_len);
    memcpy(maskedDB, EM, maskedDB_len);
    H = (unsigned char*) malloc(H_len);
    memcpy(H, EM + maskedDB_len, H_len);

    // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
    //      maskedDB are not all equal to zero, output "inconsistent" and
    //      stop.
    zeroBits = 8 * EM_len - emBits;
    printf("[XX] zerobits: %u\n", zeroBits);
    if (maskedDB[0] >> (8-zeroBits) != 0x00) {
		fprintf(stderr, "leftmost %u bits of maskedDB are not zero\n", zeroBits);
		goto cleanup;
	}

    // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
	dbMask = MGF(H, H_len, EM_len - H_len - 1, algorithm);

    // 8.   Let DB = maskedDB \xor dbMask.
    DB_len = maskedDB_len;
    DB = (unsigned char*) malloc(DB_len);
	for (i = 0; i < DB_len; i++) {
		DB[i] = maskedDB[i] ^ dbMask[i];
	}

    // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
    //      in DB to zero.
	printf("[XX] Byte zero: %02x\n", DB[0]);
	DB[0] = DB[0] << (EM_len*8 - emBits);
	DB[0] = DB[0] >> (EM_len*8 - emBits);
	printf("[XX] Byte zero: %02x\n", DB[0]);

    // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
    //      zero or if the octet at position emLen - hLen - sLen - 1 (the
    //      leftmost position is "position 1") does not have hexadecimal
    //      value 0x01, output "inconsistent" and stop.
    zeroOctets = EM_len - H_len - salt_len - 2;
    for (i = 0; i < zeroOctets; i++) {
		if (DB[i] != 0x00) {
			fprintf(stderr, "Leftmost %u octets of DB are not zero\n", zeroOctets);
			goto cleanup;
		}
	}

	printf("[XX] EM_len: %u\n", EM_len);
	printf("[XX] EM_len: %u\n", EM_len);
	printf("[XX] H_len: %u\n", H_len);
	printf("[XX] salt_len: %u\n", salt_len);

	oneOctet_pos = EM_len - H_len - salt_len - 1;
	if (DB[oneOctet_pos -1] != 0x01) {
		fprintf(stderr, "octet at %u not 0x01 (0x%02x)\n", oneOctet_pos, DB[oneOctet_pos-1]);
		goto cleanup;
	}

	hexdump(stderr, "DB", DB, DB_len);

    // 11.  Let salt be the last sLen octets of DB.
	salt = (unsigned char*) malloc(salt_len);
	memcpy(salt, DB + DB_len - salt_len, salt_len);

	hexdump(stderr, "Salt", salt, salt_len);
    // 12.  Let

    //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
    //      M' is an octet string of length 8 + hLen + sLen with eight
    //      initial zero octets.
    MM_len = 8 + mHash_len + salt_len;
	MM = (unsigned char*) malloc(MM_len);
	memset(MM, 0, 8);
	memcpy(MM + 8, mHash, mHash_len);
	memcpy(MM + 8 + mHash_len, salt, salt_len);

    // 13.  Let H' = Hash(M'), an octet string of length hLen.
    HH = sha3_digest(MM, MM_len, algorithm, &HH_len);

	hexdump(stderr, "MM", MM, MM_len);

    // 14.  If H = H', output "consistent".  Otherwise, output
    //      "inconsistent".
    if (HH_len != H_len) {
		fprintf(stderr, "Error: H' and H differ in size\n");
		goto cleanup;
	}
    if (memcmp(H, HH, HH_len) != 0) {
		fprintf(stderr, "Error: H' and H do not match\n");
		hexdump(stderr, "H", H, H_len);
		hexdump(stderr, "HH", HH, HH_len);
		goto cleanup;
	}

	// consistent!
	printf("[XX] sig good!\n");
	result = LDNS_STATUS_OK;

	cleanup:
	fflush(stdout);
	fflush(stderr);
	if (mHash != NULL) { free(mHash); }
	if (maskedDB != NULL) { free(maskedDB); }
	if (H != NULL) { free(H); }
	if (dbMask != NULL) { free(dbMask); }
	if (salt != NULL) { free(salt); }
	if (MM != NULL) { free(MM); }
	if (HH != NULL) { free(HH); }

	return result;
}

void dotests(void) {
    const char* data = "abc";
    unsigned int data_len = 3;
    unsigned char* digest;
    unsigned int digest_len;
    digest = sha3_digest((unsigned char*)data, data_len, LDNS_SIGN_RSASHA3_256, &digest_len);
    hexdump(stdout, "SHA3_256_TEST", digest, digest_len);
    free(digest);
    digest = sha3_digest((unsigned char*)data, data_len, LDNS_SIGN_RSASHA3_384, &digest_len);
    hexdump(stdout, "SHA3_384_TEST", digest, digest_len);
    free(digest);
    digest = sha3_digest((unsigned char*)data, data_len, LDNS_SIGN_RSASHA3_512, &digest_len);
    hexdump(stdout, "SHA3_512_TEST", digest, digest_len);
    free(digest);
}
