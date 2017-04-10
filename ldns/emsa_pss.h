
#ifndef LDNS_EMSA_PSS_H
#define LDNS_EMSA_PSS_H 1

#include "ldns/ldns.h"

//unsigned char *ldns_digest_raw(unsigned char* data, unsigned int data_len, ldns_algorithm algorithm, unsigned int* digest_len);
void I2OSP(unsigned char* output, unsigned int X, unsigned int xLen);
unsigned char* MGF(unsigned char* mgfSeed, unsigned int mgfSeed_len, unsigned int maskLen, ldns_algorithm algorithm);
unsigned char *emsa_pss_encode(unsigned char* M, unsigned int M_len, unsigned int emBits, unsigned int* emLen, ldns_algorithm algorithm);
int emsa_pss_verify(unsigned char* M, unsigned int M_len, unsigned char* EM, unsigned int EM_len, unsigned int emBits, ldns_algorithm algorithm);
void dotests(void);

#endif // LDNS_EMSA_PSS_H
