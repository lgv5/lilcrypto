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

#ifndef LC_INTERNAL_H
#define LC_INTERNAL_H

#include "lilcrypto.h"


/*
 * CONSTANTS
 */


/* Authentitcation */

#define HMAC_BLOCKLEN_MAX	LC_SHA512_BLOCKLEN
#define HMAC_HASHLEN_MAX	LC_SHA512_HASHLEN

#define POLY1305_TAGLEN_WORDS	(LC_POLY1305_TAGLEN / sizeof(uint32_t))


/* Ciphers */

#define CHACHA20_BLOCKLEN_WORDS	(LC_CHACHA20_BLOCKLEN / sizeof(uint32_t))
#define CHACHA20_CTRMAX		4294967295	/* 2^32 - 1 */
#define CHACHA20_KEY_WORDS	(LC_CHACHA20_KEYLEN / sizeof(uint32_t))
#define CHACHA20_NONCE_WORDS	4
#define CHACHA20_ROUNDS		10


/* Hashes */

#define SHA256_BLOCKLEN_WORDS	(LC_SHA256_BLOCKLEN / sizeof(uint32_t))
#define SHA256_ROUNDS		64

#define SHA512_BLOCKLEN_WORDS	(LC_SHA512_BLOCKLEN / sizeof(uint64_t))
#define SHA512_ROUNDS		80


/*
 * STRUCTS
 */


/*
 * *_impl provides the function pointers to the actual implementation of
 * methods, serving as an interface to the cryptographic algorithms.
 */

struct lc_aead_impl {
	int	(*seal_init)(void *, void *);
	int	(*seal_update)(void *, uint8_t *, size_t *, const uint8_t *,
		    size_t, const uint8_t *, size_t);
	int	(*seal_final)(void *, uint8_t *, size_t *, uint8_t *,
		    size_t *);
	int	(*seal)(uint8_t *, size_t *, uint8_t *, size_t *, void *,
		    const uint8_t *, size_t, const uint8_t *, size_t);

	int	(*open_init)(void *, void *);
	int	(*open_update)(void *, uint8_t *, size_t *, const uint8_t *,
		    size_t, const uint8_t *, size_t);
	int	(*open_final)(void *, uint8_t *, size_t *, const uint8_t *,
		    size_t);
	int	(*open)(uint8_t *, size_t *, void *, const uint8_t *, size_t,
		    const uint8_t *, size_t, const uint8_t *, size_t);

	size_t	  argsz;
	size_t	  blocklen;
};

struct lc_auth_impl {
	int	(*init)(void *, void *);
	int	(*update)(void *, const uint8_t *, size_t);
	int	(*final)(void *, uint8_t *, size_t *);
	int	(*auth)(uint8_t *, size_t *, void *, const uint8_t *, size_t);

	size_t	  argsz;
	size_t	  blocklen;
	size_t	  taglen;
};

struct lc_cipher_impl {
	int	(*encrypt_init)(void *, void *);
	int	(*encrypt_update)(void *, uint8_t *, size_t *, const uint8_t *,
		    size_t);
	int	(*encrypt_final)(void *, uint8_t *, size_t *);
	int	(*encrypt)(uint8_t *, size_t *, void *, const uint8_t *,
		    size_t);

	int	(*decrypt_init)(void *, void *);
	int	(*decrypt_update)(void *, uint8_t *, size_t *, const uint8_t *,
		    size_t);
	int	(*decrypt_final)(void *, uint8_t *, size_t *);
	int	(*decrypt)(uint8_t *, size_t *, void *, const uint8_t *,
		    size_t);

	size_t	  argsz;
	size_t	  blocklen;
};

struct lc_hash_impl {
	int	(*init)(void *);
	int	(*update)(void *, const uint8_t *, size_t);
	int	(*final)(void *, uint8_t *, size_t *);
	int	(*hash)(uint8_t *, size_t *, const uint8_t *, size_t);

	size_t	  argsz;
	size_t	  blocklen;
	size_t	  hashlen;
};

struct lc_kdf_impl {
	int	(*kdf)(uint8_t *, size_t *, void *, size_t);

	size_t	  argsz;
};


/*
 * *_ctx binds an *_impl with an state, effectively representing an instance of
 * a cryptographic algorithm.
 */

struct lc_aead_ctx {
	const struct lc_aead_impl	*impl;
	void				*arg;
};

struct lc_auth_ctx {
	const struct lc_auth_impl	*impl;
	void				*arg;
};

struct lc_cipher_ctx {
	const struct lc_cipher_impl	*impl;
	void				*arg;
};

struct lc_hash_ctx {
	const struct lc_hash_impl	*impl;
	void				*arg;
};


/*
 * *_state holds the internal state of the cryptographic algorithms.
 */


/* AEAD */

struct chacha20_poly1305_state {
	struct lc_auth_ctx	*auth;
	struct lc_cipher_ctx	*cipher;
	uint64_t		 aadlen;
	uint64_t		 ctlen;
	int			 aaddone;
};


/* Authentication */

struct hmac_state {
	struct lc_hash_ctx	*hash;
	uint8_t			 key[HMAC_BLOCKLEN_MAX];
};

struct poly1305_state {
	uint32_t	h0, h1, h2, h3, h4;
	uint32_t	r0, r1, r2, r3, r4;
	uint32_t	x1, x2, x3, x4;
	uint32_t	s0, s1, s2, s3;
	size_t		blen;
	uint8_t		b[LC_POLY1305_BLOCKLEN];
};


/* Ciphers */

struct chacha20_state {
	uint32_t	s[CHACHA20_BLOCKLEN_WORDS];
	uint32_t	k[CHACHA20_KEY_WORDS];
	uint32_t	n[CHACHA20_NONCE_WORDS];
	size_t		blen;
	uint8_t		b[LC_CHACHA20_BLOCKLEN];
};


/* Hashes */

struct sha256_state {
	uint32_t	h0, h1, h2, h3, h4, h5, h6, h7;
	uint64_t	sz;
	size_t		blen;
	uint8_t		b[LC_SHA256_BLOCKLEN];
};

struct sha512_state {
	uint64_t	h0, h1, h2, h3, h4, h5, h6, h7;
	uint64_t	szhi, szlo;
	size_t		blen;
	uint8_t		b[LC_SHA512_BLOCKLEN];
};


/*
 * PROTOTYPES
 */


/* Authentitcation */

void	poly1305_block(struct poly1305_state *, uint32_t);
void	poly1305_reduce(struct poly1305_state *,
	    uint32_t [POLY1305_TAGLEN_WORDS]);


/* Ciphers */

void	chacha20_block(struct chacha20_state *);
void	hchacha20_block(struct chacha20_state *);


/* Hashes */

void	sha256_block(struct sha256_state *);

void	sha512_block(struct sha512_state *);


/*
 * VARIABLES
 */

extern uint8_t	zerobuf[128];


#endif /* LC_INTERNAL_H */
