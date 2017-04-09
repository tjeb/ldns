#include <ldns/config.h>

#include <ldns/ldns.h>

#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>

#include <strings.h>
#include <time.h>

#ifdef HAVE_SSL
/* this entire file is rather useless when you don't have
 * crypto...
 */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#endif /* HAVE_SSL */

ldns_rr *
ldns_create_empty_rrsig(const ldns_rr_list *rrset,
                        const ldns_key *current_key)
{
	uint32_t orig_ttl;
	ldns_rr_class orig_class;
	time_t now;
	ldns_rr *current_sig;
	uint8_t label_count;
	ldns_rdf *signame;

	label_count = ldns_dname_label_count(ldns_rr_owner(ldns_rr_list_rr(rrset,
	                                                   0)));
        /* RFC4035 2.2: not counting the leftmost label if it is a wildcard */
        if(ldns_dname_is_wildcard(ldns_rr_owner(ldns_rr_list_rr(rrset, 0))))
                label_count --;

	current_sig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);

	/* set the type on the new signature */
	orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));
	orig_class = ldns_rr_get_class(ldns_rr_list_rr(rrset, 0));

	ldns_rr_set_ttl(current_sig, orig_ttl);
	ldns_rr_set_class(current_sig, orig_class);
	ldns_rr_set_owner(current_sig,
			  ldns_rdf_clone(
			       ldns_rr_owner(
				    ldns_rr_list_rr(rrset,
						    0))));

	/* fill in what we know of the signature */

	/* set the orig_ttl */
	(void)ldns_rr_rrsig_set_origttl(
		   current_sig,
		   ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
					 orig_ttl));
	/* the signers name */
	signame = ldns_rdf_clone(ldns_key_pubkey_owner(current_key));
	ldns_dname2canonical(signame);
	(void)ldns_rr_rrsig_set_signame(
			current_sig,
			signame);
	/* label count - get it from the first rr in the rr_list */
	(void)ldns_rr_rrsig_set_labels(
			current_sig,
			ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8,
			                     label_count));
	/* inception, expiration */
	now = time(NULL);
	if (ldns_key_inception(current_key) != 0) {
		(void)ldns_rr_rrsig_set_inception(
				current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME,
				    ldns_key_inception(current_key)));
	} else {
		(void)ldns_rr_rrsig_set_inception(
				current_sig,
				ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, now));
	}
	if (ldns_key_expiration(current_key) != 0) {
		(void)ldns_rr_rrsig_set_expiration(
				current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME,
				    ldns_key_expiration(current_key)));
	} else {
		(void)ldns_rr_rrsig_set_expiration(
			     current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME,
				    now + LDNS_DEFAULT_EXP_TIME));
	}

	(void)ldns_rr_rrsig_set_keytag(
		   current_sig,
		   ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16,
		                         ldns_key_keytag(current_key)));

	(void)ldns_rr_rrsig_set_algorithm(
			current_sig,
			ldns_native2rdf_int8(
			    LDNS_RDF_TYPE_ALG,
			    ldns_key_algorithm(current_key)));

	(void)ldns_rr_rrsig_set_typecovered(
			current_sig,
			ldns_native2rdf_int16(
			    LDNS_RDF_TYPE_TYPE,
			    ldns_rr_get_type(ldns_rr_list_rr(rrset,
			                                     0))));
	return current_sig;
}

#ifdef HAVE_SSL
ldns_rdf *
ldns_sign_public_buffer(ldns_buffer *sign_buf, ldns_key *current_key)
{
	ldns_rdf *b64rdf = NULL;

	switch(ldns_key_algorithm(current_key)) {
#ifdef USE_DSA
	case LDNS_SIGN_DSA:
	case LDNS_SIGN_DSA_NSEC3:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
# ifdef HAVE_EVP_DSS1
				   EVP_dss1()
# else
				   EVP_sha1()
# endif
				   );
		break;
#endif /* USE_DSA */
	case LDNS_SIGN_RSASHA1:
	case LDNS_SIGN_RSASHA1_NSEC3:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha1());
		break;
#ifdef USE_SHA2
	case LDNS_SIGN_RSASHA256:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha256());
		break;
	case LDNS_SIGN_RSASHA512:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha512());
		break;
#endif /* USE_SHA2 */
#ifdef USE_GOST
	case LDNS_SIGN_ECC_GOST:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_get_digestbyname("md_gost94"));
		break;
#endif /* USE_GOST */
#ifdef USE_ECDSA
        case LDNS_SIGN_ECDSAP256SHA256:
       		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha256());
                break;
        case LDNS_SIGN_ECDSAP384SHA384:
       		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha384());
                break;
#endif
#ifdef USE_ED25519
        case LDNS_SIGN_ED25519:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha512());
                break;
#endif
#ifdef USE_ED448
        case LDNS_SIGN_ED448:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha512());
                break;
#endif
	case LDNS_SIGN_RSAMD5:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_md5());
		break;
#ifdef USE_SHA3
	case LDNS_SIGN_RSASHA3_256:
//		b64rdf = ldns_sign_public_rsasha3_256(
//				   sign_buf,
//				   ldns_key_evp_key(current_key));
//		break;
	case LDNS_SIGN_RSASHA3_384:
	case LDNS_SIGN_RSASHA3_512:
		b64rdf = ldns_sign_public_rsasha3(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   ldns_key_algorithm(current_key));
		break;
#endif
	default:
		/* do _you_ know this alg? */
		printf("unknown algorithm, ");
		printf("is the one used available on this system?\n");
		break;
	}

	return b64rdf;
}

/**
 * use this function to sign with a public/private key alg
 * return the created signatures
 */
ldns_rr_list *
ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys)
{
	ldns_rr_list *signatures;
	ldns_rr_list *rrset_clone;
	ldns_rr *current_sig;
	ldns_rdf *b64rdf;
	ldns_key *current_key;
	size_t key_count;
	uint16_t i;
	ldns_buffer *sign_buf;
	ldns_rdf *new_owner;

	if (!rrset || ldns_rr_list_rr_count(rrset) < 1 || !keys) {
		return NULL;
	}

	new_owner = NULL;

	signatures = ldns_rr_list_new();

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_clone(rrset);
	if (!rrset_clone) {
		return NULL;
	}

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr_set_ttl(ldns_rr_list_rr(rrset_clone, i),
			ldns_rr_ttl(ldns_rr_list_rr(rrset, 0)));
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);

	for (key_count = 0;
		key_count < ldns_key_list_key_count(keys);
		key_count++) {
		if (!ldns_key_use(ldns_key_list_key(keys, key_count))) {
			continue;
		}
		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		if (!sign_buf) {
			ldns_rr_list_free(rrset_clone);
			ldns_rr_list_free(signatures);
			ldns_rdf_free(new_owner);
			return NULL;
		}
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		/* sign all RRs with keys that have ZSKbit, !SEPbit.
		   sign DNSKEY RRs with keys that have ZSKbit&SEPbit */
		if (ldns_key_flags(current_key) & LDNS_KEY_ZONE_KEY) {
			current_sig = ldns_create_empty_rrsig(rrset_clone,
			                                      current_key);

			/* right now, we have: a key, a semi-sig and an rrset. For
			 * which we can create the sig and base64 encode that and
			 * add that to the signature */

			if (ldns_rrsig2buffer_wire(sign_buf, current_sig)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				/* ERROR */
				ldns_rr_list_deep_free(rrset_clone);
				ldns_rr_free(current_sig);
				ldns_rr_list_deep_free(signatures);
				return NULL;
			}

			/* add the rrset in sign_buf */
			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				ldns_rr_list_deep_free(rrset_clone);
				ldns_rr_free(current_sig);
				ldns_rr_list_deep_free(signatures);
				return NULL;
			}

			b64rdf = ldns_sign_public_buffer(sign_buf, current_key);

			if (!b64rdf) {
				/* signing went wrong */
				ldns_rr_list_deep_free(rrset_clone);
				ldns_rr_free(current_sig);
				ldns_rr_list_deep_free(signatures);
				return NULL;
			}

			ldns_rr_rrsig_set_sig(current_sig, b64rdf);

			/* push the signature to the signatures list */
			ldns_rr_list_push_rr(signatures, current_sig);
		}
		ldns_buffer_free(sign_buf); /* restart for the next key */
	}
	ldns_rr_list_deep_free(rrset_clone);

	return signatures;
}

/**
 * Sign data with DSA
 *
 * \param[in] to_sign The ldns_buffer containing raw data that is
 *                    to be signed
 * \param[in] key The DSA key structure to sign with
 * \return ldns_rdf for the RRSIG ldns_rr
 */
ldns_rdf *
ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key)
{
#ifdef USE_DSA
	unsigned char *sha1_hash;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	DSA_SIG *sig;
	const BIGNUM *R, *S;
	uint8_t *data;
	size_t pad;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
				  ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	sig = DSA_do_sign(sha1_hash, SHA_DIGEST_LENGTH, key);
        if(!sig) {
		ldns_buffer_free(b64sig);
		return NULL;
        }

	data = LDNS_XMALLOC(uint8_t, 1 + 2 * SHA_DIGEST_LENGTH);
        if(!data) {
		ldns_buffer_free(b64sig);
                DSA_SIG_free(sig);
		return NULL;
        }

	data[0] = 1;
# ifdef HAVE_DSA_SIG_GET0
	DSA_SIG_get0(sig, &R, &S);
# else
	R = sig->r;
	S = sig->s;
# endif
	pad = 20 - (size_t) BN_num_bytes(R);
	if (pad > 0) {
		memset(data + 1, 0, pad);
	}
	BN_bn2bin(R, (unsigned char *) (data + 1) + pad);

	pad = 20 - (size_t) BN_num_bytes(S);
	if (pad > 0) {
		memset(data + 1 + SHA_DIGEST_LENGTH, 0, pad);
	}
	BN_bn2bin(S, (unsigned char *) (data + 1 + SHA_DIGEST_LENGTH + pad));

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,
								 1 + 2 * SHA_DIGEST_LENGTH,
								 data);

	ldns_buffer_free(b64sig);
	LDNS_FREE(data);
        DSA_SIG_free(sig);

	return sigdata_rdf;
#else
	(void)to_sign; (void)key;
	return NULL;
#endif
}

#ifdef USE_ECDSA
#ifndef S_SPLINT_S
/** returns the number of bytes per signature-component (i.e. bits/8), or 0. */
static int
ldns_pkey_is_ecdsa(EVP_PKEY* pkey)
{
        EC_KEY* ec;
        const EC_GROUP* g;
#ifdef HAVE_EVP_PKEY_BASE_ID
        if(EVP_PKEY_base_id(pkey) != EVP_PKEY_EC)
                return 0;
#else
        if(EVP_PKEY_type(key->type) != EVP_PKEY_EC)
                return 0;
#endif
        ec = EVP_PKEY_get1_EC_KEY(pkey);
        g = EC_KEY_get0_group(ec);
        if(!g) {
                EC_KEY_free(ec);
                return 0;
        }
        if(EC_GROUP_get_curve_name(g) == NID_X9_62_prime256v1) {
                EC_KEY_free(ec);
                return 32; /* 256/8 */
	}
        if(EC_GROUP_get_curve_name(g) == NID_secp384r1) {
                EC_KEY_free(ec);
                return 48; /* 384/8 */
        }
        /* downref the eckey, the original is still inside the pkey */
        EC_KEY_free(ec);
        return 0;
}
#endif /* splint */
#endif /* USE_ECDSA */

ldns_rdf *
ldns_sign_public_evp(ldns_buffer *to_sign,
				 EVP_PKEY *key,
				 const EVP_MD *digest_type)
{
	unsigned int siglen;
	ldns_rdf *sigdata_rdf = NULL;
	ldns_buffer *b64sig;
	EVP_MD_CTX *ctx;
	const EVP_MD *md_type;
	int r;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	/* initializes a signing context */
	md_type = digest_type;
	if(!md_type) {
		/* unknown message difest */
		ldns_buffer_free(b64sig);
		return NULL;
	}

#ifdef HAVE_EVP_MD_CTX_NEW
	ctx = EVP_MD_CTX_new();
#else
	ctx = (EVP_MD_CTX*)malloc(sizeof(*ctx));
	if(ctx) EVP_MD_CTX_init(ctx);
#endif
	if(!ctx) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	r = EVP_SignInit(ctx, md_type);
	if(r == 1) {
		r = EVP_SignUpdate(ctx, (unsigned char*)
					    ldns_buffer_begin(to_sign),
					    ldns_buffer_position(to_sign));
	} else {
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	if(r == 1) {
		r = EVP_SignFinal(ctx, (unsigned char*)
					   ldns_buffer_begin(b64sig), &siglen, key);
	} else {
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	if(r != 1) {
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	/* OpenSSL output is different, convert it */
	r = 0;
#ifdef USE_DSA
#ifndef S_SPLINT_S
	/* unfortunately, OpenSSL output is different from DNS DSA format */
# ifdef HAVE_EVP_PKEY_BASE_ID
	if (EVP_PKEY_base_id(key) == EVP_PKEY_DSA) {
# else
	if (EVP_PKEY_type(key->type) == EVP_PKEY_DSA) {
# endif
		r = 1;
		sigdata_rdf = ldns_convert_dsa_rrsig_asn12rdf(b64sig, siglen);
	}
#endif
#endif
#if defined(USE_ECDSA) || defined(USE_ED25519) || defined(USE_ED448)
	if(
#  ifdef HAVE_EVP_PKEY_BASE_ID
		EVP_PKEY_base_id(key)
#  else
		EVP_PKEY_type(key->type)
#  endif
		== EVP_PKEY_EC) {
#  ifdef USE_ECDSA
                if(ldns_pkey_is_ecdsa(key)) {
			r = 1;
			sigdata_rdf = ldns_convert_ecdsa_rrsig_asn1len2rdf(
				b64sig, (long)siglen, ldns_pkey_is_ecdsa(key));
		}
#  endif /* USE_ECDSA */
#  ifdef USE_ED25519
		if(EVP_PKEY_id(key) == NID_X25519) {
			r = 1;
			sigdata_rdf = ldns_convert_ed25519_rrsig_asn12rdf(
				b64sig, siglen);
		}
#  endif /* USE_ED25519 */
#  ifdef USE_ED448
		if(EVP_PKEY_id(key) == NID_X448) {
			r = 1;
			sigdata_rdf = ldns_convert_ed448_rrsig_asn12rdf(
				b64sig, siglen);
		}
#  endif /* USE_ED448 */
	}
#endif /* PKEY_EC */
	if(r == 0) {
		/* ok output for other types is the same */
		sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
									 ldns_buffer_begin(b64sig));
	}
	ldns_buffer_free(b64sig);
	EVP_MD_CTX_destroy(ctx);
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	int result;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
				  ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	result = RSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
				   (unsigned char*)ldns_buffer_begin(b64sig),
				   &siglen, key);
	if (result != 1) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig); /* can't free this buffer ?? */
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *md5_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	md5_hash = MD5((unsigned char*)ldns_buffer_begin(to_sign),
				ldns_buffer_position(to_sign), NULL);
	if (!md5_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_md5, md5_hash, MD5_DIGEST_LENGTH,
		    (unsigned char*)ldns_buffer_begin(b64sig),
		    &siglen, key);

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}
#endif /* HAVE_SSL */

#if 0
ldns_rdf *
ldns_sign_public_rsasha3_256(ldns_buffer *to_sign, EVP_PKEY *key)
{
	//unsigned int siglen;
	//ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	int r;
	unsigned int digest_len = LDNS_SHA3_256_DIGEST_LENGTH;
	unsigned char digest[LDNS_SHA3_256_DIGEST_LENGTH];

	//siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		fprintf(stderr, "Error, could not allocate signature buffer");
		return NULL;
	}

	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	r = EVP_DigestInit(ctx, EVP_sha3_256());
	if(r != 1) {
		fprintf(stderr, "error in EVP_DigestInit: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	r = EVP_DigestUpdate(ctx, (unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign));
	if(r != 1) {
		fprintf(stderr, "error in EVP_DigestUpdate: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	r = EVP_DigestFinal(ctx, digest, &digest_len);
	if(r != 1) {
		fprintf(stderr, "error in EVP_DigestFinal: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	printf("[XX] adding padding\n");
	unsigned char EM[1024];
	r = RSA_padding_add_PKCS1_PSS(EVP_PKEY_get1_RSA(key), EM, digest, EVP_sha3_256(), -2 /* maximum salt length*/);
	printf("[XX] done adding padding\n");
	if(r == 1) {
		fprintf(stderr, "[XX] ok\n");
	} else {
		fprintf(stderr, "error in RSA_padding_add_PKCS1_PSS: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	return NULL;
}
#endif // if 0

#if 0
ldns_rdf *
ldns_sign_public_rsasha3(ldns_buffer *to_sign, EVP_PKEY *key, ldns_signing_algorithm algorithm)
{
	printf("[XX] signing data\n");
	unsigned char *sha3_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	int r;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		fprintf(stderr, "Error, could not allocate signature buffer");
		return NULL;
	}
	printf("[XX] algorithm: %u\n", algorithm);

	// Digest using one of the SHA3 digests
	unsigned int digest_size;
	switch (algorithm) {
	case LDNS_SIGN_RSASHA3_256:
		printf("[XX] sha3 256\n");
		sha3_hash = ldns_sha3_256((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_256_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_384:
		printf("[XX] sha3 384\n");
		sha3_hash = ldns_sha3_384((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_384_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_512:
		printf("[XX] sha3 512\n");
		sha3_hash = ldns_sha3_512((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_512_DIGEST_LENGTH;
		break;
	default:
		fprintf(stderr, "Error: called ldns_sign_public_rsasha3 without rsasha3 algorithm\n");
		return NULL;
	}

	if (!sha3_hash) {
		fprintf(stderr, "Error, unable to create SHA3 digest\n");
		ldns_buffer_free(b64sig);
		return NULL;
	}

	printf("[XX] converting digest to EVP form\n");
	// put that in a null digester
	unsigned char pDigest[32];
	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	EVP_DigestInit(ctx, EVP_sha384());
	EVP_DigestUpdate(ctx, (const void*) sha3_hash, digest_size);
	EVP_DigestFinal(ctx, pDigest, &digest_size);
	printf("[XX] done converting digest to EVP form\n");


	// Pad the message using RSASSA-PSS
	// TODO: size etc. ctx?
	unsigned char EM[128];
	printf("[XX] adding padding\n");
	r = RSA_padding_add_PKCS1_PSS(EVP_PKEY_get1_RSA(key), EM, pDigest, EVP_md_null(), -2 /* maximum salt length*/);
	printf("[XX] done adding padding\n");
	if(r == 1) {
		fprintf(stderr, "[XX] ok\n");
	} else {
		fprintf(stderr, "error in RSA_padding_add_PKCS1_PSS: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}

	// can we pass NULL as digest type?
	r = EVP_SignInit(ctx, EVP_md_null());
	if(r == 1) {
		r = EVP_SignUpdate(ctx, sha3_hash, digest_size);
	} else {
		fprintf(stderr, "error in EVP_SignUpdate: %s\n", ERR_error_string(r, NULL));
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	if(r == 1) {
		r = EVP_SignFinal(ctx, (unsigned char*)
					   ldns_buffer_begin(b64sig), &siglen, key);
	} else {
		fprintf(stderr, "error in EVP_SignFinal\n");
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	if(r != 1) {
		fprintf(stderr, "error in EVP_Sign\n");
		ldns_buffer_free(b64sig);
		EVP_MD_CTX_destroy(ctx);
		return NULL;
	}
	// pad using PSS
	//status = RSA_padding_add_PKCS1_PSS(pRsaKey, EM, pDigest, EVP_sha256(), -2 /* maximum salt length*/);

//	result = RSA_sign(0, sha3_hash, SHA_DIGEST_LENGTH,
//				   (unsigned char*)ldns_buffer_begin(b64sig),
//				   &siglen, key);
	if (r != 1) {
		fprintf(stderr, "error signing data\n");
		ldns_buffer_free(b64sig);
		return NULL;
	}

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}
#endif

#if 0
ldns_rdf *
ldns_sign_public_rsasha3(ldns_buffer *to_sign, EVP_PKEY *key, ldns_signing_algorithm algorithm)
{
	printf("[XX] signing data\n");
	unsigned char *sha3_hash;
	int siglen = -1;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		fprintf(stderr, "Error, could not allocate signature buffer");
		return NULL;
	}
	printf("[XX] algorithm: %u\n", algorithm);

	// Digest using one of the SHA3 digests
	unsigned int digest_size;
	switch (algorithm) {
	case LDNS_SIGN_RSASHA3_256:
		printf("[XX] sha3 256\n");
		sha3_hash = ldns_sha3_256((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_256_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_384:
		printf("[XX] sha3 384\n");
		sha3_hash = ldns_sha3_384((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_384_DIGEST_LENGTH;
		break;
	case LDNS_SIGN_RSASHA3_512:
		printf("[XX] sha3 512\n");
		sha3_hash = ldns_sha3_512((unsigned char*)ldns_buffer_begin(to_sign),
		                          ldns_buffer_position(to_sign), NULL);
		digest_size = LDNS_SHA3_512_DIGEST_LENGTH;
		break;
	default:
		fprintf(stderr, "Error: called ldns_sign_public_rsasha3 without rsasha3 algorithm\n");
		return NULL;
	}

	if (!sha3_hash) {
		fprintf(stderr, "Error, unable to create SHA3 digest\n");
		ldns_buffer_free(b64sig);
		return NULL;
	}

	// use local memory to keep data for now
	RSA* rsa_key = EVP_PKEY_get1_RSA(key);
	size_t keysize = RSA_size(rsa_key);

	// Pad it using RSASSA-PSS


	unsigned char* sign_bytes = (unsigned char*)malloc(keysize);
	memset(sign_bytes, 0, 8);
	memcpy(sign_bytes+8, sha3_hash, digest_size);
	// salt
	memset(sign_bytes+8+digest_size, 0, keysize - digest_size - 8);

	unsigned char* sign_result = (unsigned char*)malloc(keysize);
	memset(sign_result, 0, keysize);

	printf("[XX] key at: %p size %u\n", rsa_key, RSA_size(rsa_key));
	printf("[XX] digest size: %u\n", digest_size);

	// Sign it with a hard call to RSA_privacte_encrypt
	siglen = RSA_private_encrypt(keysize, sign_bytes, ldns_buffer_begin(b64sig), EVP_PKEY_get1_RSA(key), RSA_NO_PADDING);

	free(sign_bytes);
	free(sign_result);
	if (siglen < 0) {
		fprintf(stderr, "error signing data: %s\n", ERR_error_string(siglen, NULL));
		ldns_buffer_free(b64sig);
		return NULL;
	}
	printf("[XX] sig size: %d\n", siglen);

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}
#endif
#if 0
static inline unsigned int
sha3_digest_len(ldns_algorithm algorithm) {
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

// for SHA3 we need to digest twice, so we have a helper function to
// keep the PSS algorithm more readable
static inline unsigned char*
sha3_digest(unsigned char* data, unsigned int data_len, ldns_algorithm algorithm, unsigned int* digest_len) {
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

static inline void I2OSP(unsigned char* output, unsigned int X, unsigned int xLen)
{
	unsigned int i;
	memset(output, 0, xLen);
	for (i = xLen-1; i > 0; i--) {
		output[i] = (uint8_t) (X % 256);
		X = X / 256;
	}
}

static inline unsigned char*
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

unsigned char*
rssa_pss_encode(unsigned char* M, unsigned int M_len, unsigned int emBits, unsigned int* emLen, ldns_algorithm algorithm)
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
	memset(salt, 0, salt_len);

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
	memcpy(DB + 9, salt, salt_len);

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
#endif // 0
ldns_rdf *
ldns_sign_public_rsasha3(ldns_buffer *M, EVP_PKEY *key, ldns_signing_algorithm algorithm)
{
	RSA* rsa_key;
	unsigned int keysize;

	unsigned int emLen;
	unsigned char* EM;

	unsigned char* sig = NULL;
	int sig_len;

	ldns_rdf* sigdata_rdf = NULL;

	rsa_key = EVP_PKEY_get1_RSA(key);
	keysize = RSA_size(rsa_key);

	EM = rssa_pss_encode(ldns_buffer_begin(M), ldns_buffer_position(M), (keysize*8)-1, &emLen, algorithm);

	// phew. Now sign that.
	sig = (unsigned char*)malloc(keysize);
	fflush(stderr);
	fflush(stdout);
	fprintf(stderr, "Signing EM of size %u with key of size %u\n", emLen, keysize);
	fprintf(stderr, "EM at %p, sig at %p\n", EM, sig);
	fprintf(stderr, "byte 0 is: %02x\n", (uint8_t)EM[0]);
	fflush(stderr);
	fflush(stdout);
	sig_len = RSA_private_encrypt(emLen, EM, sig, rsa_key, RSA_NO_PADDING);
	if (sig_len != (int)keysize) {
	    fflush(stderr);
	    fflush(stdout);
	    fprintf(stderr, "Error in RSA signing; signature size seems wrong (got %d, expected %u)\n", sig_len, keysize);
	    fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	    fprintf(stderr, "to repeat; emLen is %u, keysize is %u\n", emLen, RSA_size(rsa_key));
	    fflush(stderr);
	    fflush(stdout);
	    goto cleanup;
	}

	//13.  Output EM.
	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, sig_len, sig);

	//cleanup
	cleanup:
	if (EM != NULL) { free(EM); }
	if (sig != NULL) { free(sig); }

	return sigdata_rdf;
}

#if 0
ldns_rdf *
ldns_sign_public_rsasha3(ldns_buffer *M, EVP_PKEY *key, ldns_signing_algorithm algorithm)
{
	RSA* rsa_key;
	unsigned int keysize;

	unsigned int emLen;

	unsigned char* mHash = NULL;
	unsigned int mHash_len;

	// Hard coded salt for now
	char* salt;
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

	unsigned char* sig = NULL;
	int sig_len;

	unsigned int i;
	ldns_rdf* sigdata_rdf = NULL;

	// settings from draft-muks: emLen is keysize (-1); salt_len is digest len
	// From RFC8017:
	// Note that the octet length of EM will be one less than k if
	// modBits - 1 is divisible by 8 and equal to k otherwise.
	rsa_key = EVP_PKEY_get1_RSA(key);
	keysize = RSA_size(rsa_key);
	emLen = keysize;
	if (keysize % 8 == 0) {
	    emLen--;
	}
	// (set salt len after first digest)

	//1.   If the length of M is greater than the input limitation for
	//     the hash function (2^61 - 1 octets for SHA-1), output
	//     "message too long" and stop.

	// ignore length for now, should be OK

	//2.   Let mHash = Hash(M), an octet string of length hLen.
	mHash = sha3_digest(ldns_buffer_begin(M),
	                    ldns_buffer_position(M),
	                    algorithm,
	                    &mHash_len);
	// TODO: check NULL
	salt_len = mHash_len;

	//3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
	// do we know intended emLen?
	if (emLen < mHash_len + salt_len + 2) {
	    // error
	    fprintf(stderr, "PSS Encoding error\n");
	    return NULL;
	}

	//4.   Generate a random octet string salt of length sLen; if sLen =
	//     0, then salt is the empty string.

	// fixed salt for now
	salt = (char*) malloc(salt_len);
	memset(salt, 0, salt_len);

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

	//7.   Generate an octet string PS consisting of emLen - sLen - hLen
	//     - 2 zero octets.  The length of PS may be 0.
	PS_len = emLen - salt_len - H_len - 2;
	printf("[XX] PS size: %d\n", PS_len);
	PS = (unsigned char*) malloc(PS_len);
	memset(PS, 0, PS_len);

	//8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.
	DB_len = PS_len + 1 + salt_len;
	if (DB_len != emLen - mHash_len - 1) {
	    fprintf(stderr, "DB len is wrong?\n");
	    return NULL;
	}
	DB = (unsigned char*) malloc(DB_len);
	memcpy(DB, PS, PS_len);
	memset(DB + PS_len, 0x01, 1);
	memcpy(DB + 9, salt, salt_len);

	//9.   Let dbMask = MGF(H, emLen - hLen - 1).
	dbMask_len = emLen - H_len - 1;
	dbMask = MGF(H, H_len, dbMask_len, algorithm);

	//10.  Let maskedDB = DB \xor dbMask.
	maskedDB_len = dbMask_len;
	maskedDB = (unsigned char*) malloc(maskedDB_len);
	for (i = 0; i < maskedDB_len; i++) {
	    maskedDB[i] = DB[i] ^ dbMask[i];
	}

	//11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
	//     in maskedDB to zero.
	// we set emBits to 8*emLen so this step should not be necessary

	//12.  Let EM = maskedDB || H || 0xbc.
	printf("[XX] emLen: %u\n", emLen);
	printf("[XX] emBits: %u\n", emLen);
	printf("[XX] maskedDBlen: %u\n", maskedDB_len);
	printf("[XX] H_len: %u\n", H_len);
	// sanity check
	if (emLen != maskedDB_len + H_len + 1) {
	    fprintf(stderr, "Error in PSS algorithm; sizes do not match up\n");
	    return NULL;
	}
	EM = (unsigned char*) malloc(emLen);
	memcpy(EM, maskedDB, maskedDB_len);
	memcpy(EM+maskedDB_len, H, H_len);
	memset(EM+maskedDB_len+H_len, 0xbc, 1);

	// phew. Now sign that.
	sig = (unsigned char*)malloc(keysize);
	fflush(stderr);
	fflush(stdout);
	fprintf(stderr, "Signing EM of size %u with key of size %u\n", emLen, keysize);
	fprintf(stderr, "EM at %p, sig at %p\n", EM, sig);
	fprintf(stderr, "byte 0 is: %02x\n", (uint8_t)EM[0]);
	fflush(stderr);
	fflush(stdout);
	sig_len = RSA_private_encrypt(emLen, EM, sig, rsa_key, RSA_NO_PADDING);
	if (sig_len != (int)keysize) {
	    fflush(stderr);
	    fflush(stdout);
	    fprintf(stderr, "Error in RSA signing; signature size seems wrong (got %d, expected %u)\n", sig_len, keysize);
	    fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));
	    fprintf(stderr, "to repeat; emLen is %u, keysize is %u\n", emLen, RSA_size(rsa_key));
	    fflush(stderr);
	    fflush(stdout);
	    return NULL;
	}

	//13.  Output EM.
	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, sig_len, sig);
	goto cleanup;

	//cleanup
	cleanup:
	if (mHash != NULL) { free(mHash); }
	if (salt != NULL) { free(salt); }
	if (MM != NULL) { free(MM); }
	if (H != NULL) { free(H); }
	if (PS != NULL) { free(PS); }
	if (DB != NULL) { free(DB); }
	if (dbMask != NULL) { free(dbMask); }
	if (maskedDB != NULL) { free(maskedDB); }
	if (EM != NULL) { free(EM); }
	if (sig != NULL) { free(sig); }

	// free etc.
	return sigdata_rdf;
}
#endif // 0
/**
 * Pushes all rrs from the rrsets of type A and AAAA on gluelist.
 */
static ldns_status
ldns_dnssec_addresses_on_glue_list(
		ldns_dnssec_rrsets *cur_rrset,
		ldns_rr_list *glue_list)
{
	ldns_dnssec_rrs *cur_rrs;
	while (cur_rrset) {
		if (cur_rrset->type == LDNS_RR_TYPE_A
				|| cur_rrset->type == LDNS_RR_TYPE_AAAA) {
			for (cur_rrs = cur_rrset->rrs;
					cur_rrs;
					cur_rrs = cur_rrs->next) {
				if (cur_rrs->rr) {
					if (!ldns_rr_list_push_rr(glue_list,
							cur_rrs->rr)) {
						return LDNS_STATUS_MEM_ERR;
						/* ldns_rr_list_push_rr()
						 * returns false when unable
						 * to increase the capacity
						 * of the ldsn_rr_list
						 */
					}
				}
			}
		}
		cur_rrset = cur_rrset->next;
	}
	return LDNS_STATUS_OK;
}

/**
 * Marks the names in the zone that are occluded. Those names will be skipped
 * when walking the tree with the ldns_dnssec_name_node_next_nonglue()
 * function. But watch out! Names that are partially occluded (like glue with
 * the same name as the delegation) will not be marked and should specifically
 * be taken into account separately.
 *
 * When glue_list is given (not NULL), in the process of marking the names, all
 * glue resource records will be pushed to that list, even glue at delegation names.
 *
 * \param[in] zone the zone in which to mark the names
 * \param[in] glue_list the list to which to push the glue rrs
 * \return LDNS_STATUS_OK on success, an error code otherwise
 */
ldns_status
ldns_dnssec_zone_mark_and_get_glue(ldns_dnssec_zone *zone,
	ldns_rr_list *glue_list)
{
	ldns_rbnode_t    *node;
	ldns_dnssec_name *name;
	ldns_rdf         *owner;
	ldns_rdf         *cut = NULL; /* keeps track of zone cuts */
	/* When the cut is caused by a delegation, below_delegation will be 1.
	 * When caused by a DNAME, below_delegation will be 0.
	 */
	int below_delegation = -1; /* init suppresses comiler warning */
	ldns_status s;

	if (!zone || !zone->names) {
		return LDNS_STATUS_NULL;
	}
	for (node = ldns_rbtree_first(zone->names);
			node != LDNS_RBTREE_NULL;
			node = ldns_rbtree_next(node)) {
		name = (ldns_dnssec_name *) node->data;
		owner = ldns_dnssec_name_name(name);

		if (cut) {
			/* The previous node was a zone cut, or a subdomain
			 * below a zone cut. Is this node (still) a subdomain
			 * below the cut? Then the name is occluded. Unless
			 * the name contains a SOA, after which we are
			 * authoritative again.
			 *
			 * FIXME! If there are labels in between the SOA and
			 * the cut, going from the authoritative space (below
			 * the SOA) up into occluded space again, will not be
			 * detected with the contruct below!
			 */
			if (ldns_dname_is_subdomain(owner, cut) &&
					!ldns_dnssec_rrsets_contains_type(
					name->rrsets, LDNS_RR_TYPE_SOA)) {

				if (below_delegation && glue_list) {
					s = ldns_dnssec_addresses_on_glue_list(
						name->rrsets, glue_list);
					if (s != LDNS_STATUS_OK) {
						return s;
					}
				}
				name->is_glue = true; /* Mark occluded name! */
				continue;
			} else {
				cut = NULL;
			}
		}

		/* The node is not below a zone cut. Is it a zone cut itself?
		 * Everything below a SOA is authoritative of course; Except
		 * when the name also contains a DNAME :).
		 */
		if (ldns_dnssec_rrsets_contains_type(
				name->rrsets, LDNS_RR_TYPE_NS)
			    && !ldns_dnssec_rrsets_contains_type(
				name->rrsets, LDNS_RR_TYPE_SOA)) {
			cut = owner;
			below_delegation = 1;
			if (glue_list) { /* record glue on the zone cut */
				s = ldns_dnssec_addresses_on_glue_list(
					name->rrsets, glue_list);
				if (s != LDNS_STATUS_OK) {
					return s;
				}
			}
		} else if (ldns_dnssec_rrsets_contains_type(
				name->rrsets, LDNS_RR_TYPE_DNAME)) {
			cut = owner;
			below_delegation = 0;
		}
	}
	return LDNS_STATUS_OK;
}

/**
 * Marks the names in the zone that are occluded. Those names will be skipped
 * when walking the tree with the ldns_dnssec_name_node_next_nonglue()
 * function. But watch out! Names that are partially occluded (like glue with
 * the same name as the delegation) will not be marked and should specifically
 * be taken into account separately.
 *
 * \param[in] zone the zone in which to mark the names
 * \return LDNS_STATUS_OK on success, an error code otherwise
 */
ldns_status
ldns_dnssec_zone_mark_glue(ldns_dnssec_zone *zone)
{
	return ldns_dnssec_zone_mark_and_get_glue(zone, NULL);
}

ldns_rbnode_t *
ldns_dnssec_name_node_next_nonglue(ldns_rbnode_t *node)
{
	ldns_rbnode_t *next_node = NULL;
	ldns_dnssec_name *next_name = NULL;
	bool done = false;

	if (node == LDNS_RBTREE_NULL) {
		return NULL;
	}
	next_node = node;
	while (!done) {
		if (next_node == LDNS_RBTREE_NULL) {
			return NULL;
		} else {
			next_name = (ldns_dnssec_name *)next_node->data;
			if (!next_name->is_glue) {
				done = true;
			} else {
				next_node = ldns_rbtree_next(next_node);
			}
		}
	}
	return next_node;
}

ldns_status
ldns_dnssec_zone_create_nsecs(ldns_dnssec_zone *zone,
                              ldns_rr_list *new_rrs)
{

	ldns_rbnode_t *first_node, *cur_node, *next_node;
	ldns_dnssec_name *cur_name, *next_name;
	ldns_rr *nsec_rr;
	uint32_t nsec_ttl;
	ldns_dnssec_rrsets *soa;

	/* the TTL of NSEC rrs should be set to the minimum TTL of
	 * the zone SOA (RFC4035 Section 2.3)
	 */
	soa = ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA);

	/* did the caller actually set it? if not,
	 * fall back to default ttl
	 */
	if (soa && soa->rrs && soa->rrs->rr
			&& (ldns_rr_rdf(soa->rrs->rr, 6) != NULL)) {
		nsec_ttl = ldns_rdf2native_int32(ldns_rr_rdf(soa->rrs->rr, 6));
	} else {
		nsec_ttl = LDNS_DEFAULT_TTL;
	}

	first_node = ldns_dnssec_name_node_next_nonglue(
			       ldns_rbtree_first(zone->names));
	cur_node = first_node;
	if (cur_node) {
		next_node = ldns_dnssec_name_node_next_nonglue(
			           ldns_rbtree_next(cur_node));
	} else {
		next_node = NULL;
	}

	while (cur_node && next_node) {
		cur_name = (ldns_dnssec_name *)cur_node->data;
		next_name = (ldns_dnssec_name *)next_node->data;
		nsec_rr = ldns_dnssec_create_nsec(cur_name,
		                                  next_name,
		                                  LDNS_RR_TYPE_NSEC);
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		if(ldns_dnssec_name_add_rr(cur_name, nsec_rr)!=LDNS_STATUS_OK){
			ldns_rr_free(nsec_rr);
			return LDNS_STATUS_ERR;
		}
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		cur_node = next_node;
		if (cur_node) {
			next_node = ldns_dnssec_name_node_next_nonglue(
                               ldns_rbtree_next(cur_node));
		}
	}

	if (cur_node && !next_node) {
		cur_name = (ldns_dnssec_name *)cur_node->data;
		next_name = (ldns_dnssec_name *)first_node->data;
		nsec_rr = ldns_dnssec_create_nsec(cur_name,
		                                  next_name,
		                                  LDNS_RR_TYPE_NSEC);
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		if(ldns_dnssec_name_add_rr(cur_name, nsec_rr)!=LDNS_STATUS_OK){
			ldns_rr_free(nsec_rr);
			return LDNS_STATUS_ERR;
		}
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
	} else {
		printf("error\n");
	}

	return LDNS_STATUS_OK;
}

#ifdef HAVE_SSL
static void
ldns_hashed_names_node_free(ldns_rbnode_t *node, void *arg) {
	(void) arg;
	LDNS_FREE(node);
}

static ldns_status
ldns_dnssec_zone_create_nsec3s_mkmap(ldns_dnssec_zone *zone,
		ldns_rr_list *new_rrs,
		uint8_t algorithm,
		uint8_t flags,
		uint16_t iterations,
		uint8_t salt_length,
		uint8_t *salt,
		ldns_rbtree_t **map)
{
	ldns_rbnode_t *first_name_node;
	ldns_rbnode_t *current_name_node;
	ldns_dnssec_name *current_name;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rr *nsec_rr;
	ldns_rr_list *nsec3_list;
	uint32_t nsec_ttl;
	ldns_dnssec_rrsets *soa;
	ldns_rbnode_t *hashmap_node;

	if (!zone || !new_rrs || !zone->names) {
		return LDNS_STATUS_ERR;
	}

	/* the TTL of NSEC rrs should be set to the minimum TTL of
	 * the zone SOA (RFC4035 Section 2.3)
	 */
	soa = ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA);

	/* did the caller actually set it? if not,
	 * fall back to default ttl
	 */
	if (soa && soa->rrs && soa->rrs->rr
			&& ldns_rr_rdf(soa->rrs->rr, 6) != NULL) {
		nsec_ttl = ldns_rdf2native_int32(ldns_rr_rdf(soa->rrs->rr, 6));
	} else {
		nsec_ttl = LDNS_DEFAULT_TTL;
	}

	if (ldns_rdf_size(zone->soa->name) > 222) {
		return LDNS_STATUS_NSEC3_DOMAINNAME_OVERFLOW;
	}

	if (zone->hashed_names) {
		ldns_traverse_postorder(zone->hashed_names,
				ldns_hashed_names_node_free, NULL);
		LDNS_FREE(zone->hashed_names);
	}
	zone->hashed_names = ldns_rbtree_create(ldns_dname_compare_v);
	if (zone->hashed_names && map) {
		*map = zone->hashed_names;
	}

	first_name_node = ldns_dnssec_name_node_next_nonglue(
					  ldns_rbtree_first(zone->names));

	current_name_node = first_name_node;

	while (current_name_node && current_name_node != LDNS_RBTREE_NULL &&
			result == LDNS_STATUS_OK) {

		current_name = (ldns_dnssec_name *) current_name_node->data;
		nsec_rr = ldns_dnssec_create_nsec3(current_name,
		                                   NULL,
		                                   zone->soa->name,
		                                   algorithm,
		                                   flags,
		                                   iterations,
		                                   salt_length,
		                                   salt);
		/* by default, our nsec based generator adds rrsigs
		 * remove the bitmap for empty nonterminals */
		if (!current_name->rrsets) {
			ldns_rdf_deep_free(ldns_rr_pop_rdf(nsec_rr));
		}
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		result = ldns_dnssec_name_add_rr(current_name, nsec_rr);
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		if (ldns_rr_owner(nsec_rr)) {
			hashmap_node = LDNS_MALLOC(ldns_rbnode_t);
			if (hashmap_node == NULL) {
				return LDNS_STATUS_MEM_ERR;
			}
			current_name->hashed_name =
				ldns_dname_label(ldns_rr_owner(nsec_rr), 0);

			if (current_name->hashed_name == NULL) {
				LDNS_FREE(hashmap_node);
				return LDNS_STATUS_MEM_ERR;
			}
			hashmap_node->key  = current_name->hashed_name;
			hashmap_node->data = current_name;

			if (! ldns_rbtree_insert(zone->hashed_names
						, hashmap_node)) {
				LDNS_FREE(hashmap_node);
			}
		}
		current_name_node = ldns_dnssec_name_node_next_nonglue(
		                   ldns_rbtree_next(current_name_node));
	}
	if (result != LDNS_STATUS_OK) {
		return result;
	}

	/* Make sorted list of nsec3s (via zone->hashed_names)
	 */
	nsec3_list = ldns_rr_list_new();
	if (nsec3_list == NULL) {
		return LDNS_STATUS_MEM_ERR;
	}
	for ( hashmap_node  = ldns_rbtree_first(zone->hashed_names)
	    ; hashmap_node != LDNS_RBTREE_NULL
	    ; hashmap_node  = ldns_rbtree_next(hashmap_node)
	    ) {
		current_name = (ldns_dnssec_name *) hashmap_node->data;
		nsec_rr = ((ldns_dnssec_name *) hashmap_node->data)->nsec;
		if (nsec_rr) {
			ldns_rr_list_push_rr(nsec3_list, nsec_rr);
		}
	}
	result = ldns_dnssec_chain_nsec3_list(nsec3_list);
	ldns_rr_list_free(nsec3_list);

	return result;
}

ldns_status
ldns_dnssec_zone_create_nsec3s(ldns_dnssec_zone *zone,
		ldns_rr_list *new_rrs,
		uint8_t algorithm,
		uint8_t flags,
		uint16_t iterations,
		uint8_t salt_length,
		uint8_t *salt)
{
	return ldns_dnssec_zone_create_nsec3s_mkmap(zone, new_rrs, algorithm,
		       	flags, iterations, salt_length, salt, NULL);

}
#endif /* HAVE_SSL */

ldns_dnssec_rrs *
ldns_dnssec_remove_signatures( ldns_dnssec_rrs *signatures
			     , ATTR_UNUSED(ldns_key_list *key_list)
			     , int (*func)(ldns_rr *, void *)
			     , void *arg
			     )
{
	ldns_dnssec_rrs *base_rrs = signatures;
	ldns_dnssec_rrs *cur_rr = base_rrs;
	ldns_dnssec_rrs *prev_rr = NULL;
	ldns_dnssec_rrs *next_rr;

	uint16_t keytag;
	size_t i;

	if (!cur_rr) {
		switch(func(NULL, arg)) {
		case LDNS_SIGNATURE_LEAVE_ADD_NEW:
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
		break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
		ldns_key_list_set_use(key_list, false);
		break;
		default:
#ifdef STDERR_MSGS
			fprintf(stderr, "[XX] unknown return value from callback\n");
#endif
			break;
		}
		return NULL;
	}
	(void)func(cur_rr->rr, arg);

	while (cur_rr) {
		next_rr = cur_rr->next;

		switch (func(cur_rr->rr, arg)) {
		case  LDNS_SIGNATURE_LEAVE_ADD_NEW:
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
			keytag = ldns_rdf2native_int16(
					   ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i)) ==
				    keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
			keytag = ldns_rdf2native_int16(
					   ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i))
				    == keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		default:
#ifdef STDERR_MSGS
			fprintf(stderr, "[XX] unknown return value from callback\n");
#endif
			break;
		}
		cur_rr = next_rr;
	}

	return base_rrs;
}

#ifdef HAVE_SSL
ldns_status
ldns_dnssec_zone_create_rrsigs(ldns_dnssec_zone *zone,
                               ldns_rr_list *new_rrs,
                               ldns_key_list *key_list,
                               int (*func)(ldns_rr *, void*),
                               void *arg)
{
	return ldns_dnssec_zone_create_rrsigs_flg(zone, new_rrs, key_list,
		func, arg, 0);
}

/** If there are KSKs use only them and mark ZSKs unused */
static void
ldns_key_list_filter_for_dnskey(ldns_key_list *key_list, int flags)
{
	bool algos[256]
#ifndef S_SPLINT_S
	                = { false }
#endif
	                           ;
	ldns_signing_algorithm saw_ksk = 0;
	ldns_key *key;
	size_t i;

	if (!ldns_key_list_key_count(key_list))
		return;

	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		key = ldns_key_list_key(key_list, i);
		if ((ldns_key_flags(key) & LDNS_KEY_SEP_KEY) && !saw_ksk)
			saw_ksk = ldns_key_algorithm(key);
		algos[ldns_key_algorithm(key)] = true;
	}
	if (!saw_ksk)
		return;
	else
		algos[saw_ksk] = 0;

	for (i =0; i < ldns_key_list_key_count(key_list); i++) {
		key = ldns_key_list_key(key_list, i);
		if (!(ldns_key_flags(key) & LDNS_KEY_SEP_KEY)) {
			/* We have a ZSK.
			 * Still use it if it has a unique algorithm though!
			 */
			if ((flags & LDNS_SIGN_WITH_ALL_ALGORITHMS) &&
			    algos[ldns_key_algorithm(key)])
				algos[ldns_key_algorithm(key)] = false;
			else
				ldns_key_set_use(key, 0);
		}
	}
}

/** If there are no ZSKs use KSK as ZSK */
static void
ldns_key_list_filter_for_non_dnskey(ldns_key_list *key_list, int flags)
{
	bool algos[256]
#ifndef S_SPLINT_S
	                = { false }
#endif
	                           ;
	ldns_signing_algorithm saw_zsk = 0;
	ldns_key *key;
	size_t i;

	if (!ldns_key_list_key_count(key_list))
		return;

	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		key = ldns_key_list_key(key_list, i);
		if (!(ldns_key_flags(key) & LDNS_KEY_SEP_KEY) && !saw_zsk)
			saw_zsk = ldns_key_algorithm(key);
		algos[ldns_key_algorithm(key)] = true;
	}
	if (!saw_zsk)
		return;
	else
		algos[saw_zsk] = 0;

	for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
		key = ldns_key_list_key(key_list, i);
		if((ldns_key_flags(key) & LDNS_KEY_SEP_KEY)) {
			/* We have a KSK.
			 * Still use it if it has a unique algorithm though!
			 */
			if ((flags & LDNS_SIGN_WITH_ALL_ALGORITHMS) &&
			    algos[ldns_key_algorithm(key)])
				algos[ldns_key_algorithm(key)] = false;
			else
				ldns_key_set_use(key, 0);
		}
	}
}

ldns_status
ldns_dnssec_zone_create_rrsigs_flg( ldns_dnssec_zone *zone
				  , ldns_rr_list *new_rrs
				  , ldns_key_list *key_list
				  , int (*func)(ldns_rr *, void*)
				  , void *arg
				  , int flags
				  )
{
	ldns_status result = LDNS_STATUS_OK;

	ldns_rbnode_t *cur_node;
	ldns_rr_list *rr_list;

	ldns_dnssec_name *cur_name;
	ldns_dnssec_rrsets *cur_rrset;
	ldns_dnssec_rrs *cur_rr;

	ldns_rr_list *siglist;

	size_t i;

	int on_delegation_point = 0; /* handle partially occluded names */

	ldns_rr_list *pubkey_list = ldns_rr_list_new();
	for (i = 0; i<ldns_key_list_key_count(key_list); i++) {
		ldns_rr_list_push_rr( pubkey_list
				    , ldns_key2rr(ldns_key_list_key(
							key_list, i))
				    );
	}
	/* TODO: callback to see is list should be signed */
	/* TODO: remove 'old' signatures from signature list */
	cur_node = ldns_rbtree_first(zone->names);
	while (cur_node != LDNS_RBTREE_NULL) {
		cur_name = (ldns_dnssec_name *) cur_node->data;

		if (!cur_name->is_glue) {
			on_delegation_point = ldns_dnssec_rrsets_contains_type(
					cur_name->rrsets, LDNS_RR_TYPE_NS)
				&& !ldns_dnssec_rrsets_contains_type(
					cur_name->rrsets, LDNS_RR_TYPE_SOA);
			cur_rrset = cur_name->rrsets;
			while (cur_rrset) {
				/* reset keys to use */
				ldns_key_list_set_use(key_list, true);

				/* walk through old sigs, remove the old,
				   and mark which keys (not) to use) */
				cur_rrset->signatures =
					ldns_dnssec_remove_signatures(cur_rrset->signatures,
											key_list,
											func,
											arg);
				if(!(flags&LDNS_SIGN_DNSKEY_WITH_ZSK) &&
					cur_rrset->type == LDNS_RR_TYPE_DNSKEY)
					ldns_key_list_filter_for_dnskey(key_list, flags);

				if(cur_rrset->type != LDNS_RR_TYPE_DNSKEY)
					ldns_key_list_filter_for_non_dnskey(key_list, flags);

				/* TODO: just set count to zero? */
				rr_list = ldns_rr_list_new();

				cur_rr = cur_rrset->rrs;
				while (cur_rr) {
					ldns_rr_list_push_rr(rr_list, cur_rr->rr);
					cur_rr = cur_rr->next;
				}

				/* only sign non-delegation RRsets */
				/* (glue should have been marked earlier,
				 *  except on the delegation points itself) */
				if (!on_delegation_point ||
						ldns_rr_list_type(rr_list)
							== LDNS_RR_TYPE_DS ||
						ldns_rr_list_type(rr_list)
							== LDNS_RR_TYPE_NSEC ||
						ldns_rr_list_type(rr_list)
							== LDNS_RR_TYPE_NSEC3) {
					siglist = ldns_sign_public(rr_list, key_list);
					for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
						if (cur_rrset->signatures) {
							result = ldns_dnssec_rrs_add_rr(cur_rrset->signatures,
											   ldns_rr_list_rr(siglist,
														    i));
						} else {
							cur_rrset->signatures = ldns_dnssec_rrs_new();
							cur_rrset->signatures->rr =
								ldns_rr_list_rr(siglist, i);
						}
						if (new_rrs) {
							ldns_rr_list_push_rr(new_rrs,
												 ldns_rr_list_rr(siglist,
															  i));
						}
					}
					ldns_rr_list_free(siglist);
				}

				ldns_rr_list_free(rr_list);

				cur_rrset = cur_rrset->next;
			}

			/* sign the nsec */
			ldns_key_list_set_use(key_list, true);
			cur_name->nsec_signatures =
				ldns_dnssec_remove_signatures(cur_name->nsec_signatures,
										key_list,
										func,
										arg);
			ldns_key_list_filter_for_non_dnskey(key_list, flags);

			rr_list = ldns_rr_list_new();
			ldns_rr_list_push_rr(rr_list, cur_name->nsec);
			siglist = ldns_sign_public(rr_list, key_list);

			for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
				if (cur_name->nsec_signatures) {
					result = ldns_dnssec_rrs_add_rr(cur_name->nsec_signatures,
									   ldns_rr_list_rr(siglist, i));
				} else {
					cur_name->nsec_signatures = ldns_dnssec_rrs_new();
					cur_name->nsec_signatures->rr =
						ldns_rr_list_rr(siglist, i);
				}
				if (new_rrs) {
					ldns_rr_list_push_rr(new_rrs,
								 ldns_rr_list_rr(siglist, i));
				}
			}

			ldns_rr_list_free(siglist);
			ldns_rr_list_free(rr_list);
		}
		cur_node = ldns_rbtree_next(cur_node);
	}

	ldns_rr_list_deep_free(pubkey_list);
	return result;
}

ldns_status
ldns_dnssec_zone_sign(ldns_dnssec_zone *zone,
				  ldns_rr_list *new_rrs,
				  ldns_key_list *key_list,
				  int (*func)(ldns_rr *, void *),
				  void *arg)
{
	return ldns_dnssec_zone_sign_flg(zone, new_rrs, key_list, func, arg, 0);
}

ldns_status
ldns_dnssec_zone_sign_flg(ldns_dnssec_zone *zone,
				  ldns_rr_list *new_rrs,
				  ldns_key_list *key_list,
				  int (*func)(ldns_rr *, void *),
				  void *arg,
				  int flags)
{
	ldns_status result = LDNS_STATUS_OK;

	if (!zone || !new_rrs || !key_list) {
		return LDNS_STATUS_ERR;
	}

	/* zone is already sorted */
	result = ldns_dnssec_zone_mark_glue(zone);
	if (result != LDNS_STATUS_OK) {
		return result;
	}

	/* check whether we need to add nsecs */
	if (zone->names && !((ldns_dnssec_name *)zone->names->root->data)->nsec) {
		result = ldns_dnssec_zone_create_nsecs(zone, new_rrs);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
	}

	result = ldns_dnssec_zone_create_rrsigs_flg(zone,
					new_rrs,
					key_list,
					func,
					arg,
					flags);

	return result;
}

ldns_status
ldns_dnssec_zone_sign_nsec3(ldns_dnssec_zone *zone,
					   ldns_rr_list *new_rrs,
					   ldns_key_list *key_list,
					   int (*func)(ldns_rr *, void *),
					   void *arg,
					   uint8_t algorithm,
					   uint8_t flags,
					   uint16_t iterations,
					   uint8_t salt_length,
					   uint8_t *salt)
{
	return ldns_dnssec_zone_sign_nsec3_flg_mkmap(zone, new_rrs, key_list,
		func, arg, algorithm, flags, iterations, salt_length, salt, 0,
	       	NULL);
}

ldns_status
ldns_dnssec_zone_sign_nsec3_flg_mkmap(ldns_dnssec_zone *zone,
		ldns_rr_list *new_rrs,
		ldns_key_list *key_list,
		int (*func)(ldns_rr *, void *),
		void *arg,
		uint8_t algorithm,
		uint8_t flags,
		uint16_t iterations,
		uint8_t salt_length,
		uint8_t *salt,
		int signflags,
		ldns_rbtree_t **map)
{
	ldns_rr *nsec3, *nsec3param;
	ldns_status result = LDNS_STATUS_OK;

	/* zone is already sorted */
	result = ldns_dnssec_zone_mark_glue(zone);
	if (result != LDNS_STATUS_OK) {
		return result;
	}

	/* TODO if there are already nsec3s presents and their
	 * parameters are the same as these, we don't have to recreate
	 */
	if (zone->names) {
		/* add empty nonterminals */
		result = ldns_dnssec_zone_add_empty_nonterminals(zone);
		if (result != LDNS_STATUS_OK) {
			return result;
		}

		nsec3 = ((ldns_dnssec_name *)zone->names->root->data)->nsec;
		if (nsec3 && ldns_rr_get_type(nsec3) == LDNS_RR_TYPE_NSEC3) {
			/* no need to recreate */
		} else {
			if (!ldns_dnssec_zone_find_rrset(zone,
									   zone->soa->name,
									   LDNS_RR_TYPE_NSEC3PARAM)) {
				/* create and add the nsec3param rr */
				nsec3param =
					ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAM);
				ldns_rr_set_owner(nsec3param,
							   ldns_rdf_clone(zone->soa->name));
				ldns_nsec3_add_param_rdfs(nsec3param,
									 algorithm,
									 flags,
									 iterations,
									 salt_length,
									 salt);
				/* always set bit 7 of the flags to zero, according to
				 * rfc5155 section 11. The bits are counted from right to left,
				 * so bit 7 in rfc5155 is bit 0 in ldns */
				ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(nsec3param, 1)), 0, 0);
				result = ldns_dnssec_zone_add_rr(zone, nsec3param);
				if (result != LDNS_STATUS_OK) {
					return result;
				}
				ldns_rr_list_push_rr(new_rrs, nsec3param);
			}
			result = ldns_dnssec_zone_create_nsec3s_mkmap(zone,
											new_rrs,
											algorithm,
											flags,
											iterations,
											salt_length,
											salt,
											map);
			if (result != LDNS_STATUS_OK) {
				return result;
			}
		}

		result = ldns_dnssec_zone_create_rrsigs_flg(zone,
						new_rrs,
						key_list,
						func,
						arg,
						signflags);
	}

	return result;
}

ldns_status
ldns_dnssec_zone_sign_nsec3_flg(ldns_dnssec_zone *zone,
		ldns_rr_list *new_rrs,
		ldns_key_list *key_list,
		int (*func)(ldns_rr *, void *),
		void *arg,
		uint8_t algorithm,
		uint8_t flags,
		uint16_t iterations,
		uint8_t salt_length,
		uint8_t *salt,
		int signflags)
{
	return ldns_dnssec_zone_sign_nsec3_flg_mkmap(zone, new_rrs, key_list,
		func, arg, algorithm, flags, iterations, salt_length, salt,
		signflags, NULL);
}

ldns_zone *
ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list)
{
	ldns_dnssec_zone *dnssec_zone;
	ldns_zone *signed_zone;
	ldns_rr_list *new_rrs;
	size_t i;

	signed_zone = ldns_zone_new();
	dnssec_zone = ldns_dnssec_zone_new();

	(void) ldns_dnssec_zone_add_rr(dnssec_zone, ldns_zone_soa(zone));
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));

	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
		(void) ldns_dnssec_zone_add_rr(dnssec_zone,
								 ldns_rr_list_rr(ldns_zone_rrs(zone),
											  i));
		ldns_zone_push_rr(signed_zone,
					   ldns_rr_clone(ldns_rr_list_rr(ldns_zone_rrs(zone),
											   i)));
	}

	new_rrs = ldns_rr_list_new();
	(void) ldns_dnssec_zone_sign(dnssec_zone,
						    new_rrs,
						    key_list,
						    ldns_dnssec_default_replace_signatures,
						    NULL);

    	for (i = 0; i < ldns_rr_list_rr_count(new_rrs); i++) {
		ldns_rr_list_push_rr(ldns_zone_rrs(signed_zone),
						 ldns_rr_clone(ldns_rr_list_rr(new_rrs, i)));
	}

	ldns_rr_list_deep_free(new_rrs);
	ldns_dnssec_zone_free(dnssec_zone);

	return signed_zone;
}

ldns_zone *
ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	ldns_dnssec_zone *dnssec_zone;
	ldns_zone *signed_zone;
	ldns_rr_list *new_rrs;
	size_t i;

	signed_zone = ldns_zone_new();
	dnssec_zone = ldns_dnssec_zone_new();

	(void) ldns_dnssec_zone_add_rr(dnssec_zone, ldns_zone_soa(zone));
	ldns_zone_set_soa(signed_zone, ldns_rr_clone(ldns_zone_soa(zone)));

	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
		(void) ldns_dnssec_zone_add_rr(dnssec_zone,
								 ldns_rr_list_rr(ldns_zone_rrs(zone),
											  i));
		ldns_zone_push_rr(signed_zone,
					   ldns_rr_clone(ldns_rr_list_rr(ldns_zone_rrs(zone),
											   i)));
	}

	new_rrs = ldns_rr_list_new();
	(void) ldns_dnssec_zone_sign_nsec3(dnssec_zone,
								new_rrs,
								key_list,
								ldns_dnssec_default_replace_signatures,
								NULL,
								algorithm,
								flags,
								iterations,
								salt_length,
								salt);

    	for (i = 0; i < ldns_rr_list_rr_count(new_rrs); i++) {
		ldns_rr_list_push_rr(ldns_zone_rrs(signed_zone),
						 ldns_rr_clone(ldns_rr_list_rr(new_rrs, i)));
	}

	ldns_rr_list_deep_free(new_rrs);
	ldns_dnssec_zone_free(dnssec_zone);

	return signed_zone;
}
#endif /* HAVE_SSL */


