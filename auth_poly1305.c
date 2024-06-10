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
	struct poly1305_ctx		*ctx = arg;
	size_t				 i;
	uint32_t			 t0, t1, t2, t3;

	ctx->h0 = 0;
	ctx->h1 = 0;
	ctx->h2 = 0;
	ctx->h3 = 0;
	ctx->h4 = 0;

	t0 = load32le(&params->key[0]);
	t1 = load32le(&params->key[4]);
	t2 = load32le(&params->key[8]);
	t3 = load32le(&params->key[12]);

	ctx->r0 = t0 & 0x3ffffff;
	ctx->r1 = ((t1 << 6) | (t0 >> 26)) & 0x3ffff03;
	ctx->r2 = ((t2 << 12) | (t1 >> 20)) & 0x3ffc0ff;
	ctx->r3 = ((t3 << 18) | (t2 >> 14)) & 0x3f03fff;
	ctx->r4 = (t3 >> 8) & 0xfffff;

	ctx->x1 = 5 * ctx->r1;
	ctx->x2 = 5 * ctx->r2;
	ctx->x3 = 5 * ctx->r3;
	ctx->x4 = 5 * ctx->r4;

	ctx->s0 = load32le(&params->key[16]);
	ctx->s1 = load32le(&params->key[20]);
	ctx->s2 = load32le(&params->key[24]);
	ctx->s3 = load32le(&params->key[28]);

	ctx->mlen = 0;
	for (i = 0; i < LC_POLY1305_BLOCKLEN; i++)
		ctx->m[i] = 0;

	return 1;
}

static int
poly1305_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct poly1305_ctx	*ctx = arg;
	size_t 			 i;

	for (i = 0; i + ctx->mlen < LC_POLY1305_BLOCKLEN && i < inlen; i++)
		ctx->m[i + ctx->mlen] = in[i];
	ctx->mlen += i;
	in += i;
	inlen -= i;

	if (ctx->mlen == LC_POLY1305_BLOCKLEN) {
		poly1305_block(ctx, 1);
		ctx->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= LC_POLY1305_BLOCKLEN) {
		for (i = 0; i < LC_POLY1305_BLOCKLEN; i++)
			ctx->m[i] = in[i];
		poly1305_block(ctx, 1);

		in += LC_POLY1305_BLOCKLEN;
		inlen -= LC_POLY1305_BLOCKLEN;
	}

	for (i = 0; i < inlen; i++)
		ctx->m[i] = in[i];
	ctx->mlen = inlen;

	return 1;
}

static int
poly1305_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct poly1305_ctx	*ctx = arg;
	uint32_t		 tag[POLY1305_TAGLEN_WORDS];
	size_t 			 i;

	*outlen = LC_POLY1305_TAGLEN;
	if (out == NULL)
		return 1;

	i = ctx->mlen;
	if (i > 0) {
		if (i < LC_POLY1305_BLOCKLEN) {
			ctx->m[i++] = 1;
			for (; i < LC_POLY1305_BLOCKLEN; i++)
				ctx->m[i] = 0;
			poly1305_block(ctx, 0);
		} else
			poly1305_block(ctx, 1);
	}
	poly1305_reduce(ctx, tag);

	store32le(&out[0], tag[0]);
	store32le(&out[4], tag[1]);
	store32le(&out[8], tag[2]);
	store32le(&out[12], tag[3]);

	lc_scrub(ctx, sizeof(*ctx));

	return 1;
}

static int
poly1305_auth(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *in, size_t inlen)
{
	struct poly1305_ctx	ctx;

	if (out == NULL) {
		*outlen = LC_POLY1305_TAGLEN;
		return 1;
	}

	return poly1305_init(&ctx, initparams) &&
	    poly1305_update(&ctx, in, inlen) &&
	    poly1305_final(&ctx, out, outlen);
}


static struct lc_auth_impl	poly1305_impl = {
	.init = &poly1305_init,
	.update = &poly1305_update,
	.final = &poly1305_final,
	.auth = &poly1305_auth,

	.argsz = sizeof(struct poly1305_ctx),
	.blocklen = LC_POLY1305_BLOCKLEN,
	.taglen = LC_POLY1305_TAGLEN,
};

const struct lc_auth_impl *
lc_auth_impl_poly1305(void)
{
	return &poly1305_impl;
}
