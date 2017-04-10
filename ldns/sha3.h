/**
 * SHA-3 (keccak) implementation.
 * This file is taken from RHash; https://github.com/rhash
 *
 * There are some small modifications to fit into the ldns library
 * by Jelte Jansen (2017)
 */

/* sha3.h */
#ifndef RHASH_SHA3_H
#define RHASH_SHA3_H
#include <openssl/evp.h>
#include "ldns/ldns.h"

#ifdef __cplusplus
extern "C" {
#endif

#define sha3_224_hash_size  28
#define LDNS_SHA3_256_DIGEST_LENGTH  32
#define LDNS_SHA3_384_DIGEST_LENGTH  48
#define LDNS_SHA3_512_DIGEST_LENGTH  64
#define sha3_max_permutation_size 25
#define sha3_max_rate_in_qwords 24

/**
 * SHA3 Algorithm context.
 */
typedef struct sha3_ctx
{
	/* 1600 bits algorithm hashing state */
	uint64_t hash[sha3_max_permutation_size];
	/* 1536-bit buffer for leftovers */
	uint64_t message[sha3_max_rate_in_qwords];
	/* count of bytes in the message[] buffer */
	unsigned rest;
	/* size of a message block processed at once */
	unsigned block_size;
} sha3_ctx;

/* methods for calculating the hash function */

void rhash_sha3_224_init(sha3_ctx *ctx);
void rhash_sha3_256_init(sha3_ctx *ctx);
void rhash_sha3_384_init(sha3_ctx *ctx);
void rhash_sha3_512_init(sha3_ctx *ctx);
void rhash_sha3_update(sha3_ctx *ctx, const unsigned char* msg, size_t size);
void rhash_sha3_final(sha3_ctx *ctx, unsigned char* result);

#ifdef USE_KECCAK
#define rhash_keccak_224_init rhash_sha3_224_init
#define rhash_keccak_256_init rhash_sha3_256_init
#define rhash_keccak_384_init rhash_sha3_384_init
#define rhash_keccak_512_init rhash_sha3_512_init
#define rhash_keccak_update rhash_sha3_update
void rhash_keccak_final(sha3_ctx *ctx, unsigned char* result);
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

/* convenience functions */
unsigned char *ldns_sha3_256(const unsigned char *data, unsigned int data_len, unsigned char *digest);
unsigned char *ldns_sha3_384(const unsigned char *data, unsigned int data_len, unsigned char *digest);
unsigned char *ldns_sha3_512(const unsigned char *data, unsigned int data_len, unsigned char *digest);

#endif /* RHASH_SHA3_H */
