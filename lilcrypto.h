/*
 * Copyright (c) 2024 Lucas Gabriel Vuotto <lucas@lgv5.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef LILCRYPTO_H
#define LILCRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>


/*
 * CONSTANTS
 */


/* Authentitcation */

#define LC_POLY1305_BLOCKLEN	16
#define LC_POLY1305_KEYLEN	32
#define LC_POLY1305_TAGLEN	16


/* Ciphers */

#define LC_CHACHA20_BLOCKLEN	64
#define LC_CHACHA20_KEYLEN	32
#define LC_CHACHA20_NONCELEN	12
#define LC_XCHACHA20_BLOCKLEN	64
#define LC_XCHACHA20_KEYLEN	32
#define LC_XCHACHA20_NONCELEN	24


/* Hashes */

#define LC_SHA224_BLOCKLEN	64
#define LC_SHA224_HASHLEN	28
#define LC_SHA256_BLOCKLEN	64
#define LC_SHA256_HASHLEN	32
#define LC_SHA384_BLOCKLEN	128
#define LC_SHA384_HASHLEN	48
#define LC_SHA512_BLOCKLEN	128
#define LC_SHA512_HASHLEN	64
#define LC_SHA512_224_BLOCKLEN	128
#define LC_SHA512_224_HASHLEN	28
#define LC_SHA512_256_BLOCKLEN	128
#define LC_SHA512_256_HASHLEN	32


/*
 * STRUCTS
 */


struct lc_aead_ctx;
struct lc_aead_impl;

struct lc_auth_ctx;
struct lc_auth_impl;

struct lc_cipher_ctx;
struct lc_cipher_impl;

struct lc_hash_ctx;
struct lc_hash_impl;

struct lc_kdf_impl;


/* AEAD parameters */

struct lc_chacha20_poly1305_params {
	struct lc_auth_ctx	*auth;
	struct lc_cipher_ctx	*cipher;
	uint8_t			 key[LC_CHACHA20_KEYLEN];
	uint8_t			 nonce[LC_CHACHA20_NONCELEN];
};

struct lc_xchacha20_poly1305_params {
	struct lc_auth_ctx	*auth;
	struct lc_cipher_ctx	*cipher;
	uint8_t			 key[LC_XCHACHA20_KEYLEN];
	uint8_t			 nonce[LC_XCHACHA20_NONCELEN];
};


/* Authentication parameters */

struct lc_hmac_params {
	struct lc_hash_ctx	*hash;
	size_t			 keylen;
	uint8_t			*key;
};

struct lc_poly1305_params {
	uint8_t	key[LC_POLY1305_KEYLEN];
};


/* Ciphers parameters */

struct lc_chacha20_params {
	uint8_t		key[LC_CHACHA20_KEYLEN];
	uint8_t		nonce[LC_CHACHA20_NONCELEN];
	uint32_t	counter;
};

struct lc_xchacha20_params {
	uint8_t		key[LC_XCHACHA20_KEYLEN];
	uint8_t		nonce[LC_XCHACHA20_NONCELEN];
	uint32_t	counter;
};


/* KDF parameters */

struct lc_hkdf_params {
	struct lc_hash_ctx	*hash;
	struct lc_auth_ctx	*hmac;
	uint8_t			*ikm;
	size_t			 ikmlen;
	uint8_t			*info;
	size_t			 infolen;
	uint8_t			*salt;
	size_t			 saltlen;
};


/*
 * PROTOTYPES
 */


/* Constant-time operations */

uint32_t	lc_ct_cmp(const void *, const void *, size_t);
uint32_t	lc_ct_mask32(uint32_t);


/* Hashes */

int	lc_hash_init(struct lc_hash_ctx *);
int	lc_hash_update(struct lc_hash_ctx *, const uint8_t *, size_t);
int	lc_hash_final(struct lc_hash_ctx *, uint8_t *, size_t *);
int	lc_hash(const struct lc_hash_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t);

struct lc_hash_ctx	*lc_hash_ctx_new(const struct lc_hash_impl *);
void			 lc_hash_ctx_free(struct lc_hash_ctx *);

const struct lc_hash_impl	*lc_hash_impl_sha224(void);
const struct lc_hash_impl	*lc_hash_impl_sha256(void);
const struct lc_hash_impl	*lc_hash_impl_sha384(void);
const struct lc_hash_impl	*lc_hash_impl_sha512(void);
const struct lc_hash_impl	*lc_hash_impl_sha512_224(void);
const struct lc_hash_impl	*lc_hash_impl_sha512_256(void);


/* Authentication */

int	lc_auth_init(struct lc_auth_ctx *, void *);
int	lc_auth_update(struct lc_auth_ctx *, const uint8_t *, size_t);
int	lc_auth_final(struct lc_auth_ctx *, uint8_t *, size_t *);
int	lc_auth(const struct lc_auth_impl *, uint8_t *, size_t *, void *,
	    const uint8_t *, size_t);

struct lc_auth_ctx	*lc_auth_ctx_new(const struct lc_auth_impl *);
void			 lc_auth_ctx_free(struct lc_auth_ctx *);

const struct lc_auth_impl	*lc_auth_impl_hmac(void);
const struct lc_auth_impl	*lc_auth_impl_poly1305(void);


/* Ciphers */

int	lc_cipher_encrypt_init(struct lc_cipher_ctx *, void *);
int	lc_cipher_encrypt_update(struct lc_cipher_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t);
int	lc_cipher_encrypt_final(struct lc_cipher_ctx *, uint8_t *, size_t *);
int	lc_cipher_encrypt(const struct lc_cipher_impl *, uint8_t *, size_t *,
	    void *, const uint8_t *, size_t);
int	lc_cipher_decrypt_init(struct lc_cipher_ctx *, void *);
int	lc_cipher_decrypt_update(struct lc_cipher_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t);
int	lc_cipher_decrypt_final(struct lc_cipher_ctx *, uint8_t *, size_t *);
int	lc_cipher_decrypt(const struct lc_cipher_impl *, uint8_t *, size_t *,
	    void *, const uint8_t *, size_t);

struct lc_cipher_ctx	*lc_cipher_ctx_new(const struct lc_cipher_impl *);
void			 lc_cipher_ctx_free(struct lc_cipher_ctx *);

const struct lc_cipher_impl	*lc_cipher_impl_chacha20(void);
const struct lc_cipher_impl	*lc_cipher_impl_xchacha20(void);


/* Authenticated encryption with additional data */

int	lc_aead_seal_init(struct lc_aead_ctx *, void *);
int	lc_aead_seal_update(struct lc_aead_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t);
int	lc_aead_seal_final(struct lc_aead_ctx *, uint8_t *, size_t *,
	    uint8_t *, size_t *);
int	lc_aead_seal(const struct lc_aead_impl *, uint8_t *, size_t *,
	    uint8_t *, size_t *, void *, const uint8_t *, size_t,
	    const uint8_t *, size_t);
int	lc_aead_open_init(struct lc_aead_ctx *, void *);
int	lc_aead_open_update(struct lc_aead_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t);
int	lc_aead_open_final(struct lc_aead_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t);
int	lc_aead_open(const struct lc_aead_impl *, uint8_t *, size_t *, void *,
	    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
	    size_t);

struct lc_aead_ctx	*lc_aead_ctx_new(const struct lc_aead_impl *);
void			 lc_aead_ctx_free(struct lc_aead_ctx *);

const struct lc_aead_impl	*lc_aead_impl_chacha20_poly1305(void);
const struct lc_aead_impl	*lc_aead_impl_xchacha20_poly1305(void);


/* Key derivation functions */

int	lc_kdf(const struct lc_kdf_impl *, uint8_t *, size_t *, void *,
	    size_t);

const struct lc_kdf_impl	*lc_kdf_impl_hkdf(void);


/* Utilities */

int	lc_hexdump_fp(FILE *, const void *, size_t);
void	lc_scrub(void *, size_t);


#endif /* LILCRYPTO_H */
