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

#include <stdlib.h>

#include "lilcrypto.h"
#include "hash.h"
#include "impl_sha256.h"
#include "util.h"


/*
 * SHA-224 and SHA-256 implementations.
 *
 * This implementation doesn't support arbitrary amounts of bits, but only full
 * bytes sizes. In particular, size is stored in bytes until the length has to
 * be appended to the input. This is done to simplify overflow checks for input
 * length.
 */


#define SHA256_SZ_MAX	UINT32_C(0x1fffffff)	/* 2^29 - 1 */

#define SHA224_H0_0	UINT32_C(0xc1059ed8)
#define SHA224_H0_1	UINT32_C(0x367cd507)
#define SHA224_H0_2	UINT32_C(0x3070dd17)
#define SHA224_H0_3	UINT32_C(0xf70e5939)
#define SHA224_H0_4	UINT32_C(0xffc00b31)
#define SHA224_H0_5	UINT32_C(0x68581511)
#define SHA224_H0_6	UINT32_C(0x64f98fa7)
#define SHA224_H0_7	UINT32_C(0xbefa4fa4)

#define SHA256_H0_0	UINT32_C(0x6a09e667)
#define SHA256_H0_1	UINT32_C(0xbb67ae85)
#define SHA256_H0_2	UINT32_C(0x3c6ef372)
#define SHA256_H0_3	UINT32_C(0xa54ff53a)
#define SHA256_H0_4	UINT32_C(0x510e527f)
#define SHA256_H0_5	UINT32_C(0x9b05688c)
#define SHA256_H0_6	UINT32_C(0x1f83d9ab)
#define SHA256_H0_7	UINT32_C(0x5be0cd19)


static int
sha224_init(void *arg)
{
	struct sha256_state	*state = arg;
	size_t			 i;

	state->h0 = SHA224_H0_0;
	state->h1 = SHA224_H0_1;
	state->h2 = SHA224_H0_2;
	state->h3 = SHA224_H0_3;
	state->h4 = SHA224_H0_4;
	state->h5 = SHA224_H0_5;
	state->h6 = SHA224_H0_6;
	state->h7 = SHA224_H0_7;

	state->sz = 0;

	state->blen = 0;
	for (i = 0; i < LC_SHA256_BLOCKLEN; i++)
		state->b[i] = 0;

	return 1;
}

static int
sha256_init(void *arg)
{
	struct sha256_state	*state = arg;
	size_t			 i;

	state->h0 = SHA256_H0_0;
	state->h1 = SHA256_H0_1;
	state->h2 = SHA256_H0_2;
	state->h3 = SHA256_H0_3;
	state->h4 = SHA256_H0_4;
	state->h5 = SHA256_H0_5;
	state->h6 = SHA256_H0_6;
	state->h7 = SHA256_H0_7;

	state->sz = 0;

	state->blen = 0;
	for (i = 0; i < LC_SHA256_BLOCKLEN; i++)
		state->b[i] = 0;

	return 1;
}

static int
sha224_sha256_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct sha256_state	*state = arg;
	size_t			 i;

	if (inlen > SHA256_SZ_MAX - state->sz)
		return 0;
	state->sz += inlen;

	for (i = 0; i + state->blen < LC_SHA256_BLOCKLEN && i < inlen; i++)
		state->b[i + state->blen] = in[i];
	state->blen += i;
	in += i;
	inlen -= i;

	if (state->blen == LC_SHA256_BLOCKLEN) {
		sha256_block(state);
		state->blen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= LC_SHA256_BLOCKLEN) {
		for (i = 0; i < LC_SHA256_BLOCKLEN; i++)
			state->b[i] = in[i];
		in += i;
		inlen -= i;

		sha256_block(state);
	}

	for (i = 0; i < inlen; i++)
		state->b[i] = in[i];
	state->blen = inlen;

	return 1;
}

static int
sha224_update(void *arg, const uint8_t *in, size_t inlen)
{
	return sha224_sha256_update(arg, in, inlen);
}

static int
sha256_update(void *arg, const uint8_t *in, size_t inlen)
{
	return sha224_sha256_update(arg, in, inlen);
}

static void
sha224_sha256_final(struct sha256_state *state)
{
	size_t	i, mlen;

	mlen = state->blen;
	state->b[mlen++] = 0x80;

	if (mlen >= LC_SHA256_BLOCKLEN - sizeof(uint64_t)) {
		for (i = mlen; i < LC_SHA256_BLOCKLEN; i++)
			state->b[i] = 0;
		sha256_block(state);
		mlen = 0;
	}

	for (i = mlen; i < LC_SHA256_BLOCKLEN - sizeof(uint64_t); i++)
		state->b[i] = 0;
	store64be(&state->b[i], state->sz << 3);
	sha256_block(state);
}

static int
sha224_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha256_state	*state = arg;

	*outlen = LC_SHA224_HASHLEN;
	if (out == NULL)
		return 1;

	sha224_sha256_final(state);
	store32be(out, state->h0);
	store32be(out + 4, state->h1);
	store32be(out + 8, state->h2);
	store32be(out + 12, state->h3);
	store32be(out + 16, state->h4);
	store32be(out + 20, state->h5);
	store32be(out + 24, state->h6);

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
sha256_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha256_state	*state = arg;

	*outlen = LC_SHA256_HASHLEN;
	if (out == NULL)
		return 1;

	sha224_sha256_final(state);
	store32be(out, state->h0);
	store32be(out + 4, state->h1);
	store32be(out + 8, state->h2);
	store32be(out + 12, state->h3);
	store32be(out + 16, state->h4);
	store32be(out + 20, state->h5);
	store32be(out + 24, state->h6);
	store32be(out + 28, state->h7);

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
sha224_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha256_state	state;

	if (out == NULL) {
		*outlen = LC_SHA224_HASHLEN;
		return 1;
	}

	return sha224_init(&state) &&
	    sha224_update(&state, in, inlen) &&
	    sha224_final(&state, out, outlen);
}

static int
sha256_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha256_state	state;

	if (out == NULL) {
		*outlen = LC_SHA256_HASHLEN;
		return 1;
	}

	return sha256_init(&state) &&
	    sha256_update(&state, in, inlen) &&
	    sha256_final(&state, out, outlen);
}


static struct lc_hash_impl	sha224_impl = {
	.init = &sha224_init,
	.update = &sha224_update,
	.final = &sha224_final,
	.hash = &sha224_hash,

	.argsz = sizeof(struct sha256_state),
	.blocklen = LC_SHA224_BLOCKLEN,
	.hashlen = LC_SHA224_HASHLEN,
};

static struct lc_hash_impl	sha256_impl = {
	.init = &sha256_init,
	.update = &sha256_update,
	.final = &sha256_final,
	.hash = &sha256_hash,

	.argsz = sizeof(struct sha256_state),
	.blocklen = LC_SHA256_BLOCKLEN,
	.hashlen = LC_SHA256_HASHLEN,
};

const struct lc_hash_impl *
lc_hash_impl_sha224(void)
{
	return &sha224_impl;
}

const struct lc_hash_impl *
lc_hash_impl_sha256(void)
{
	return &sha256_impl;
}
