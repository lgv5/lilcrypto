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
	struct sha256_ctx	*ctx = arg;
	size_t			 i;

	ctx->h0 = SHA224_H0_0;
	ctx->h1 = SHA224_H0_1;
	ctx->h2 = SHA224_H0_2;
	ctx->h3 = SHA224_H0_3;
	ctx->h4 = SHA224_H0_4;
	ctx->h5 = SHA224_H0_5;
	ctx->h6 = SHA224_H0_6;
	ctx->h7 = SHA224_H0_7;

	ctx->sz = 0;

	ctx->mlen = 0;
	for (i = 0; i < SHA256_CHUNK; i++)
		ctx->m[i] = 0;

	return 1;
}

static int
sha256_init(void *arg)
{
	struct sha256_ctx	*ctx = arg;
	size_t			 i;

	ctx->h0 = SHA256_H0_0;
	ctx->h1 = SHA256_H0_1;
	ctx->h2 = SHA256_H0_2;
	ctx->h3 = SHA256_H0_3;
	ctx->h4 = SHA256_H0_4;
	ctx->h5 = SHA256_H0_5;
	ctx->h6 = SHA256_H0_6;
	ctx->h7 = SHA256_H0_7;

	ctx->sz = 0;

	ctx->mlen = 0;
	for (i = 0; i < SHA256_CHUNK; i++)
		ctx->m[i] = 0;

	return 1;
}

static int
sha224_sha256_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct sha256_ctx	*ctx = arg;
	size_t			 i;

	if (inlen > SHA256_SZ_MAX - ctx->sz)
		return 0;
	ctx->sz += inlen;

	for (i = 0; i + ctx->mlen < SHA256_CHUNK && i < inlen; i++)
		ctx->m[i + ctx->mlen] = in[i];
	ctx->mlen += i;
	in += i;
	inlen -= i;

	if (ctx->mlen == SHA256_CHUNK) {
		sha256_block(ctx);
		ctx->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= SHA256_CHUNK) {
		for (i = 0; i < SHA256_CHUNK; i++)
			ctx->m[i] = in[i];
		in += i;
		inlen -= i;

		sha256_block(ctx);
	}

	for (i = 0; i < inlen; i++)
		ctx->m[i] = in[i];
	ctx->mlen = inlen;

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
sha224_sha256_final(struct sha256_ctx *ctx)
{
	size_t	i, mlen;

	mlen = ctx->mlen;
	ctx->m[mlen++] = 0x80;

	if (mlen >= SHA256_CHUNK - sizeof(uint64_t)) {
		for (i = mlen; i < SHA256_CHUNK; i++)
			ctx->m[i] = 0;
		sha256_block(ctx);
		mlen = 0;
	}

	for (i = mlen; i < SHA256_CHUNK - sizeof(uint64_t); i++)
		ctx->m[i] = 0;
	store64be(&ctx->m[i], ctx->sz << 3);
	sha256_block(ctx);
}

static int
sha224_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha256_ctx	*ctx = arg;

	*outlen = LC_SHA224_HASHLEN;
	if (out == NULL)
		return 1;

	sha224_sha256_final(ctx);
	store32be(out, ctx->h0);
	store32be(out + 4, ctx->h1);
	store32be(out + 8, ctx->h2);
	store32be(out + 12, ctx->h3);
	store32be(out + 16, ctx->h4);
	store32be(out + 20, ctx->h5);
	store32be(out + 24, ctx->h6);

	lc_scrub(ctx, sizeof(*ctx));

	return 1;
}

static int
sha256_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct sha256_ctx	*ctx = arg;

	*outlen = LC_SHA256_HASHLEN;
	if (out == NULL)
		return 1;

	sha224_sha256_final(ctx);
	store32be(out, ctx->h0);
	store32be(out + 4, ctx->h1);
	store32be(out + 8, ctx->h2);
	store32be(out + 12, ctx->h3);
	store32be(out + 16, ctx->h4);
	store32be(out + 20, ctx->h5);
	store32be(out + 24, ctx->h6);
	store32be(out + 28, ctx->h7);

	lc_scrub(ctx, sizeof(*ctx));

	return 1;
}

static int
sha224_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha256_ctx	ctx;

	if (out == NULL) {
		*outlen = LC_SHA224_HASHLEN;
		return 1;
	}

	return sha224_init(&ctx) &&
	    sha224_update(&ctx, in, inlen) &&
	    sha224_final(&ctx, out, outlen);
}

static int
sha256_hash(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
{
	struct sha256_ctx	ctx;

	if (out == NULL) {
		*outlen = LC_SHA256_HASHLEN;
		return 1;
	}

	return sha256_init(&ctx) &&
	    sha256_update(&ctx, in, inlen) &&
	    sha256_final(&ctx, out, outlen);
}

static void *
sha224_sha256_ctx_new(void)
{
	return malloc(sizeof(struct sha256_ctx));
}


static struct lc_hash_impl	sha224_impl = {
	.init = &sha224_init,
	.update = &sha224_update,
	.final = &sha224_final,
	.hash = &sha224_hash,

	.ctx_new = &sha224_sha256_ctx_new,
	.ctx_free = NULL,
};

static struct lc_hash_impl	sha256_impl = {
	.init = &sha256_init,
	.update = &sha256_update,
	.final = &sha256_final,
	.hash = &sha256_hash,

	.ctx_new = &sha224_sha256_ctx_new,
	.ctx_free = NULL,
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
