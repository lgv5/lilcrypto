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
#include "auth.h"
#include "impl_poly1305.h"

#include "util.h"


static int
poly1305_init(void *arg, void *initparams)
{
	struct lc_poly1305_params	*params = initparams;
	struct poly1305_state		*state = arg;
	size_t				 i;
	uint32_t			 t0, t1, t2, t3;

	state->h0 = 0;
	state->h1 = 0;
	state->h2 = 0;
	state->h3 = 0;
	state->h4 = 0;

	t0 = load32le(&params->key[0]);
	t1 = load32le(&params->key[4]);
	t2 = load32le(&params->key[8]);
	t3 = load32le(&params->key[12]);

	state->r0 = t0 & 0x3ffffff;
	state->r1 = ((t1 << 6) | (t0 >> 26)) & 0x3ffff03;
	state->r2 = ((t2 << 12) | (t1 >> 20)) & 0x3ffc0ff;
	state->r3 = ((t3 << 18) | (t2 >> 14)) & 0x3f03fff;
	state->r4 = (t3 >> 8) & 0xfffff;

	state->x1 = 5 * state->r1;
	state->x2 = 5 * state->r2;
	state->x3 = 5 * state->r3;
	state->x4 = 5 * state->r4;

	state->s0 = load32le(&params->key[16]);
	state->s1 = load32le(&params->key[20]);
	state->s2 = load32le(&params->key[24]);
	state->s3 = load32le(&params->key[28]);

	state->blen = 0;
	for (i = 0; i < LC_POLY1305_BLOCKLEN; i++)
		state->b[i] = 0;

	return 1;
}

static int
poly1305_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct poly1305_state	*state = arg;
	size_t 			 i;

	for (i = 0; i + state->blen < LC_POLY1305_BLOCKLEN && i < inlen; i++)
		state->b[i + state->blen] = in[i];
	state->blen += i;
	in += i;
	inlen -= i;

	if (state->blen == LC_POLY1305_BLOCKLEN) {
		poly1305_block(state, 1);
		state->blen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= LC_POLY1305_BLOCKLEN) {
		for (i = 0; i < LC_POLY1305_BLOCKLEN; i++)
			state->b[i] = in[i];
		poly1305_block(state, 1);

		in += LC_POLY1305_BLOCKLEN;
		inlen -= LC_POLY1305_BLOCKLEN;
	}

	for (i = 0; i < inlen; i++)
		state->b[i] = in[i];
	state->blen = inlen;

	return 1;
}

static int
poly1305_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct poly1305_state	*state = arg;
	uint32_t		 tag[POLY1305_TAGLEN_WORDS];
	size_t 			 i;

	*outlen = LC_POLY1305_TAGLEN;
	if (out == NULL)
		return 1;

	i = state->blen;
	if (i > 0) {
		if (i < LC_POLY1305_BLOCKLEN) {
			state->b[i++] = 1;
			for (; i < LC_POLY1305_BLOCKLEN; i++)
				state->b[i] = 0;
			poly1305_block(state, 0);
		} else
			poly1305_block(state, 1);
	}
	poly1305_reduce(state, tag);

	store32le(&out[0], tag[0]);
	store32le(&out[4], tag[1]);
	store32le(&out[8], tag[2]);
	store32le(&out[12], tag[3]);

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
poly1305_auth(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *in, size_t inlen)
{
	struct poly1305_state	state;

	if (out == NULL) {
		*outlen = LC_POLY1305_TAGLEN;
		return 1;
	}

	return poly1305_init(&state, initparams) &&
	    poly1305_update(&state, in, inlen) &&
	    poly1305_final(&state, out, outlen);
}


static struct lc_auth_impl	poly1305_impl = {
	.init = &poly1305_init,
	.update = &poly1305_update,
	.final = &poly1305_final,
	.auth = &poly1305_auth,

	.argsz = sizeof(struct poly1305_state),
	.blocklen = LC_POLY1305_BLOCKLEN,
	.taglen = LC_POLY1305_TAGLEN,
};

const struct lc_auth_impl *
lc_auth_impl_poly1305(void)
{
	return &poly1305_impl;
}
