
/**
 * Implementation of EMSA-PSS (RFC8017)
 * Copyright 2017 Jelte Jansen
 */

#include "ldns/emsa_pss.h"

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

	unsigned int digest_len = ldns_digest_length(algorithm);
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
	    digest = ldns_digest_raw(tmpseed, mgfSeed_len + 4, NULL, NULL, algorithm);
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
	mHash = ldns_digest_raw(M, M_len, NULL, &mHash_len, algorithm);
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
	H = ldns_digest_raw(MM, MM_len, NULL, &H_len, algorithm);

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
    mHash = ldns_digest_raw(M, M_len, NULL, &mHash_len, algorithm);

    // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    salt_len = ldns_digest_length(algorithm);
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
    H_len = ldns_digest_length(algorithm);
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
    HH = ldns_digest_raw(MM, MM_len, NULL, &HH_len, algorithm);

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
    digest = ldns_digest_raw((unsigned char*)data, data_len, NULL, &digest_len, LDNS_SIGN_RSASHA3_256);
    hexdump(stdout, "SHA3_256_TEST", digest, digest_len);
    free(digest);
    digest = ldns_digest_raw((unsigned char*)data, data_len, NULL, &digest_len, LDNS_SIGN_RSASHA3_384);
    hexdump(stdout, "SHA3_384_TEST", digest, digest_len);
    free(digest);
    digest = ldns_digest_raw((unsigned char*)data, data_len, NULL, &digest_len, LDNS_SIGN_RSASHA3_512);
    hexdump(stdout, "SHA3_512_TEST", digest, digest_len);
    free(digest);
}
