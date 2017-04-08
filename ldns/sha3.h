/*
 * FILE:	sha3.h
 * AUTHOR: Jelte Jansen
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Based on ldns/sha2.h, which in turn was based on code by
 * Aaron D. Gifford
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __LDNS_SHA3_H__
#define __LDNS_SHA3_H__

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Import u_intXX_t size_t type definitions from system headers.  You
 * may need to change this, or define these things yourself in this
 * file.
 */
#include <sys/types.h>

#if LDNS_BUILD_CONFIG_HAVE_INTTYPES_H

#include <inttypes.h>

#endif /* LDNS_BUILD_CONFIG_HAVE_INTTYPES_H */


/*** SHA-256/384/512 Various Length Definitions ***********************/
#define LDNS_SHA3_256_BLOCK_LENGTH		64
#define LDNS_SHA3_256_DIGEST_LENGTH		32
#define LDNS_SHA3_256_DIGEST_STRING_LENGTH	(LDNS_SHA3_256_DIGEST_LENGTH * 2 + 1)
#define LDNS_SHA3_384_BLOCK_LENGTH		128
#define LDNS_SHA3_384_DIGEST_LENGTH		48
#define LDNS_SHA3_384_DIGEST_STRING_LENGTH	(LDNS_SHA3_384_DIGEST_LENGTH * 2 + 1)
#define LDNS_SHA3_512_BLOCK_LENGTH		128
#define LDNS_SHA3_512_DIGEST_LENGTH		64
#define LDNS_SHA3_512_DIGEST_STRING_LENGTH	(LDNS_SHA3_512_DIGEST_LENGTH * 2 + 1)


/*** SHA-256/384/512 Context Structures *******************************/

typedef struct _ldns_sha3_256_CTX {
	uint32_t	state[8];
	uint64_t	bitcount;
	uint8_t	buffer[LDNS_SHA3_256_BLOCK_LENGTH];
} ldns_sha3_256_CTX;
typedef struct _ldns_sha3_512_CTX {
	uint64_t	state[8];
	uint64_t	bitcount[2];
	uint8_t	buffer[LDNS_SHA3_512_BLOCK_LENGTH];
} ldns_sha3_512_CTX;

typedef ldns_sha3_512_CTX ldns_sha3_384_CTX;


/*** SHA-256/384/512 Function Prototypes ******************************/
void ldns_sha3_256_init(ldns_sha3_256_CTX *);
void ldns_sha3_256_update(ldns_sha3_256_CTX*, const uint8_t*, size_t);
void ldns_sha3_256_final(uint8_t[LDNS_SHA3_256_DIGEST_LENGTH], ldns_sha3_256_CTX*);

void ldns_sha3_384_init(ldns_sha3_384_CTX*);
void ldns_sha3_384_update(ldns_sha3_384_CTX*, const uint8_t*, size_t);
void ldns_sha3_384_final(uint8_t[LDNS_SHA3_384_DIGEST_LENGTH], ldns_sha3_384_CTX*);

void ldns_sha3_512_init(ldns_sha3_512_CTX*);
void ldns_sha3_512_update(ldns_sha3_512_CTX*, const uint8_t*, size_t);
void ldns_sha3_512_final(uint8_t[LDNS_SHA3_512_DIGEST_LENGTH], ldns_sha3_512_CTX*);

/**
 * Convenience function to digest a fixed block of data at once.
 *
 * \param[in] data the data to digest
 * \param[in] data_len the length of data in bytes
 * \param[out] digest the length of data in bytes
 *             This pointer MUST have LDNS_SHA3_256_DIGEST_LENGTH bytes
 *             available
 * \return the SHA1 digest of the given data
 */
unsigned char *ldns_sha3_256(unsigned char *data, unsigned int data_len, unsigned char *digest);

/**
 * Convenience function to digest a fixed block of data at once.
 *
 * \param[in] data the data to digest
 * \param[in] data_len the length of data in bytes
 * \param[out] digest the length of data in bytes
 *             This pointer MUST have LDNS_SHA3_384_DIGEST_LENGTH bytes
 *             available
 * \return the SHA1 digest of the given data
 */
unsigned char *ldns_sha3_384(unsigned char *data, unsigned int data_len, unsigned char *digest);

/**
 * Convenience function to digest a fixed block of data at once.
 *
 * \param[in] data the data to digest
 * \param[in] data_len the length of data in bytes
 * \param[out] digest the length of data in bytes
 *             This pointer MUST have LDNS_SHA3_512_DIGEST_LENGTH bytes
 *             available
 * \return the SHA1 digest of the given data
 */
unsigned char *ldns_sha3_512(unsigned char *data, unsigned int data_len, unsigned char *digest);

#ifdef	__cplusplus
}
#endif /* __cplusplus */

#endif /* __LDNS_SHA3_H__ */

