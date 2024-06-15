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
#include "impl_sha512.h"
#include "util.h"


/*
 * SHA-384 and SHA-512 implementations.
 *
 * This implementation doesn't support arbitrary amounts of bits, but only full
 * bytes sizes. In particular, size is stored in bytes until the length has to
 * be appended to the input. This is done to simplify overflow checks for input
 * length.
 */


#define SHA512_SZHI_MAX	UINT64_C(0x1fffffffffffffff)	/* 2^125 - 1 */
#define SHA512_SZLO_MAX UINT64_MAX

#define SHA384_H0_0	UINT64_C(0xcbbb9d5dc1059ed8)
#define SHA384_H0_1	UINT64_C(0x629a292a367cd507)
#define SHA384_H0_2	UINT64_C(0x9159015a3070dd17)
#define SHA384_H0_3	UINT64_C(0x152fecd8f70e5939)
#define SHA384_H0_4	UINT64_C(0x67332667ffc00b31)
#define SHA384_H0_5	UINT64_C(0x8eb44a8768581511)
#define SHA384_H0_6	UINT64_C(0xdb0c2e0d64f98fa7)
#define SHA384_H0_7	UINT64_C(0x47b5481dbefa4fa4)

#define SHA512_H0_0	UINT64_C(0x6a09e667f3bcc908)
#define SHA512_H0_1	UINT64_C(0xbb67ae8584caa73b)
#define SHA512_H0_2	UINT64_C(0x3c6ef372fe94f82b)
#define SHA512_H0_3	UINT64_C(0xa54ff53a5f1d36f1)
#define SHA512_H0_4	UINT64_C(0x510e527fade682d1)
#define SHA512_H0_5	UINT64_C(0x9b05688c2b3e6c1f)
#define SHA512_H0_6	UINT64_C(0x1f83d9abfb41bd6b)
#define SHA512_H0_7	UINT64_C(0x5be0cd19137e2179)


static int
sha384_init(void *arg)
{
	struct sha512_state	*state = arg;
	size_t			 i;

	state->h0 = SHA384_H0_0;
	state->h1 = SHA384_H0_1;
	state->h2 = SHA384_H0_2;
	state->h3 = SHA384_H0_3;
	state->h4 = SHA384_H0_4;
	state->h5 = SHA384_H0_5;
	state->h6 = SHA384_H0_6;
	state->h7 = SHA384_H0_7;

	state->szhi = state->szlo = 0;

	state->mlen = 0;
	for (i = 0; i < LC_SHA512_BLOCKLEN; i++)
		state->m[i] = 0;

	return 1;
}

static int
sha512_init(void *arg)
{
	struct sha512_state	*state = arg;
	size_t			 i;

	state->h0 = SHA512_H0_0;
	state->h1 = SHA512_H0_1;
	state->h2 = SHA512_H0_2;
	state->h3 = SHA512_H0_3;
	state->h4 = SHA512_H0_4;
	state->h5 = SHA512_H0_5;
	state->h6 = SHA512_H0_6;
	state->h7 = SHA512_H0_7;

	state->szhi = state->szlo = 0;

	state->mlen = 0;
	for (i = 0; i < LC_SHA512_BLOCKLEN; i++)
		state->m[i] = 0;

	return 1;
}

static int
sha384_sha512_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct sha512_state	*state = arg;
	size_t			 i;

	if (inlen > SHA512_SZLO_MAX - state->szlo) {
		if (state->szhi == SHA512_SZHI_MAX)
			return 0;
		state->szlo += inlen;
		state->szhi++;
	} else
		state->szlo += inlen;

	for (i = 0; i + state->mlen < LC_SHA512_BLOCKLEN && i < inlen; i++)
		state->m[i + state->mlen] = in[i];
	state->mlen += i;
	in += i;
	inlen -= i;

	if (state->mlen == LC_SHA512_BLOCKLEN) {
		sha512_block(state);
		state->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= LC_SHA512_BLOCKLEN) {
		for (i = 0; i < LC_SHA512_BLOCKLEN; i++)
			state->m[i] = in[i];
		in += i;
		inlen -= i;

		sha512_block(state);
	}

	for (i = 0; i < inlen; i++)
		state->m[i] = in[i];
	state->mlen = inlen;

	return 1;
}

static int
sha384_update(void *arg, const uint8_t *in, size_t inlen)
{
	return sha384_sha512_update(arg, in, inlen);
}

static int
sha512_update(void *arg, const uint8_t *in, size_t inlen)
{
	return sha384_sha512_update(arg, in, inlen);
}

static void
sha384_sha512_final(struct sha512_state *state)
{
	size_t	i, mlen;

	mlen = state->mlen;
	state->m[mlen++] = 0x80;

	if (mlen >= LC_SHA512_BLOCKLEN - 2 * sizeof(uint64_t)) {
		for (i = mlen; i < LC_SHA512_BLOCKLEN; i++)
			state->m[i] = 0;
		sha512_block(state);
		mlen = 0;
	}

	for (i = mlen; i < LC_SHA512_BLOCKLEN - 2 * sizeof(uint64_t); i++)
		state->m[i] = 0;
	store64be(&state->m[i], (state->szhi << 3) | (state->szlo >> 63));
	store64be(&state->m[i + sizeof(uint64_t)], state->szlo << 3);
	sha512_block(state);
}

static int
sha384_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha512_state	*state = arg;

	*outlen = LC_SHA384_HASHLEN;
	if (out == NULL)
		return 1;

	sha384_sha512_final(state);
	store64be(out, state->h0);
	store64be(out + 8, state->h1);
	store64be(out + 16, state->h2);
	store64be(out + 24, state->h3);
	store64be(out + 32, state->h4);
	store64be(out + 40, state->h5);

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
sha512_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha512_state	*state = arg;

	*outlen = LC_SHA512_HASHLEN;
	if (out == NULL)
		return 1;

	sha384_sha512_final(state);
	store64be(out, state->h0);
	store64be(out + 8, state->h1);
	store64be(out + 16, state->h2);
	store64be(out + 24, state->h3);
	store64be(out + 32, state->h4);
	store64be(out + 40, state->h5);
	store64be(out + 48, state->h6);
	store64be(out + 56, state->h7);

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
sha384_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha512_state	state;

	if (out == NULL) {
		*outlen = LC_SHA384_HASHLEN;
		return 1;
	}

	return sha384_init(&state) &&
	    sha384_update(&state, in, inlen) &&
	    sha384_final(&state, out, outlen);
}

static int
sha512_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha512_state	state;

	if (out == NULL) {
		*outlen = LC_SHA512_HASHLEN;
		return 1;
	}

	return sha512_init(&state) &&
	    sha512_update(&state, in, inlen) &&
	    sha512_final(&state, out, outlen);
}


static struct lc_hash_impl	sha384_impl = {
	.init = &sha384_init,
	.update = &sha384_update,
	.final = &sha384_final,
	.hash = &sha384_hash,

	.argsz = sizeof(struct sha512_state),
	.blocklen = LC_SHA384_BLOCKLEN,
	.hashlen = LC_SHA384_HASHLEN,
};

static struct lc_hash_impl	sha512_impl = {
	.init = &sha512_init,
	.update = &sha512_update,
	.final = &sha512_final,
	.hash = &sha512_hash,

	.argsz = sizeof(struct sha512_state),
	.blocklen = LC_SHA512_BLOCKLEN,
	.hashlen = LC_SHA512_HASHLEN,
};

const struct lc_hash_impl *
lc_hash_impl_sha384(void)
{
	return &sha384_impl;
}

const struct lc_hash_impl *
lc_hash_impl_sha512(void)
{
	return &sha512_impl;
}
