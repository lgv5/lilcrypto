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
 * Constants.
 */

/* Hashes. */
#define LC_SHA224_HASHLEN	28
#define LC_SHA256_HASHLEN	32
#define LC_SHA384_HASHLEN	48
#define LC_SHA512_HASHLEN	64

/* Authentitcation. */
#define LC_POLY1305_KEYLEN	32
#define LC_POLY1305_TAGLEN	16

/* Ciphers. */
#define LC_CHACHA20_KEYLEN	32
#define LC_CHACHA20_IVLEN	12
#define LC_XCHACHA20_KEYLEN	32
#define LC_XCHACHA20_IVLEN	24


/*
 * Constant-time operations.
 */

uint32_t	lc_ct_cmp(const uint8_t *, const uint8_t *, size_t);


/*
 * Hashes.
 */

struct lc_hash_ctx;
struct lc_hash_impl;


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


/*
 * Authentication.
 */

struct lc_auth_ctx;
struct lc_auth_impl;


int	lc_auth_init(struct lc_auth_ctx *, const uint8_t *, size_t);
int	lc_auth_update(struct lc_auth_ctx *, const uint8_t *, size_t);
int	lc_auth_final(struct lc_auth_ctx *, uint8_t *, size_t *);
int	lc_auth(const struct lc_auth_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t);

struct lc_auth_ctx	*lc_auth_ctx_new(const struct lc_auth_impl *);
void			 lc_auth_ctx_free(struct lc_auth_ctx *);

const struct lc_auth_impl	*lc_auth_impl_poly1305(void);
const struct lc_auth_impl	*lc_auth_impl_hmac_sha224(void);
const struct lc_auth_impl	*lc_auth_impl_hmac_sha256(void);
const struct lc_auth_impl	*lc_auth_impl_hmac_sha384(void);
const struct lc_auth_impl	*lc_auth_impl_hmac_sha512(void);


/*
 * Ciphers.
 */

struct lc_cipher_ctx;
struct lc_cipher_impl;


int	lc_cipher_encrypt_init(struct lc_cipher_ctx *, const uint8_t *, size_t,
	    const uint8_t *, size_t);
int	lc_cipher_encrypt_update(struct lc_cipher_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t);
int	lc_cipher_encrypt_final(struct lc_cipher_ctx *, uint8_t *, size_t *);
int	lc_cipher_encrypt(const struct lc_cipher_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
	    size_t);
int	lc_cipher_decrypt_init(struct lc_cipher_ctx *, const uint8_t *, size_t,
	    const uint8_t *, size_t);
int	lc_cipher_decrypt_update(struct lc_cipher_ctx *, uint8_t *, size_t *,
	    const uint8_t *, size_t);
int	lc_cipher_decrypt_final(struct lc_cipher_ctx *, uint8_t *, size_t *);
int	lc_cipher_decrypt(const struct lc_cipher_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
	    size_t);

struct lc_cipher_ctx	*lc_cipher_ctx_new(const struct lc_cipher_impl *);
void			 lc_cipher_ctx_free(struct lc_cipher_ctx *);

const struct lc_cipher_impl	*lc_cipher_impl_chacha20(void);
const struct lc_cipher_impl	*lc_cipher_impl_xchacha20(void);


/*
 * Authenticated encryption with additional data.
 */

struct lc_aead_impl;


int	lc_aead_seal(const struct lc_aead_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
	    size_t, const uint8_t *, size_t);
int	lc_aead_open(const struct lc_aead_impl *, uint8_t *, size_t *,
	    const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *,
	    size_t, const uint8_t *, size_t);

const struct lc_aead_impl	*lc_aead_impl_chacha20_poly1305(void);
const struct lc_aead_impl	*lc_aead_impl_xchacha20_poly1305(void);


/*
 * Utilities.
 */

int	lc_hexdump_fp(FILE *, const void *, size_t);
void	lc_scrub(void *, size_t);

#endif /* LILCRYPTO_H */
