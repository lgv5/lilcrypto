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

#include <limits.h>
#include <stdlib.h>

#include "lilcrypto.h"
#include "cipher.h"
#include "impl_chacha20.h"

#include "util.h"


/*
 * Implements ChaCha20 according to RFC 8439, XChaCha20 according to
 * draft-irtf-cfrg-xchacha-03.
 */


static int
chacha20_anycrypt_init(void *arg, const void *initparams)
{
	const struct lc_chacha20_params	*params = initparams;
	struct chacha20_ctx		*ctx = arg;
	size_t				 i;

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		ctx->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		ctx->k[i] = load32le(&params->key[i * 4]);
	ctx->n[0] = params->counter;
	for (i = 1; i < CHACHA20_NONCE_WORDS; i++)
		ctx->n[i] = load32le(&params->nonce[(i - 1) * 4]);
	ctx->mlen = 0;

	return 1;
}

static int
xchacha20_anycrypt_init(void *arg, const void *initparams)
{
	const struct lc_xchacha20_params	*params = initparams;
	struct chacha20_ctx			*ctx = arg;
	size_t					 i;

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		ctx->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		ctx->k[i] = load32le(&params->key[i * 4]);
	for (i = 0; i < CHACHA20_NONCE_WORDS; i++)
		ctx->n[i] = load32le(&params->nonce[i * 4]);
	ctx->mlen = 0;

	hchacha20_block(ctx);

	ctx->k[0] = ctx->s[0];
	ctx->k[1] = ctx->s[1];
	ctx->k[2] = ctx->s[2];
	ctx->k[3] = ctx->s[3];
	ctx->k[4] = ctx->s[12];
	ctx->k[5] = ctx->s[13];
	ctx->k[6] = ctx->s[14];
	ctx->k[7] = ctx->s[15];
	ctx->n[0] = params->counter;
	ctx->n[1] = 0;
	ctx->n[2] = load32le(&params->nonce[16]);
	ctx->n[3] = load32le(&params->nonce[20]);

	return 1;
}

static int
chacha20_anycrypt_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_ctx	*ctx = arg;
	size_t			 i, blocks;
	uint32_t		 h;

	*outlen = 0;
	if (inlen > SIZE_MAX - (CHACHA20_BLOCKLEN - 1) - ctx->mlen)
		return 0;
	blocks = (inlen + ctx->mlen + CHACHA20_BLOCKLEN - 1) /
	    CHACHA20_BLOCKLEN;
	if (blocks + ctx->n[0] > CHACHA20_CTRMAX)
		return 0;

	*outlen = ctx->mlen + inlen -
	    ((ctx->mlen + inlen) % CHACHA20_BLOCKLEN);
	if (out == NULL)
		return 1;

	for (i = 0; i + ctx->mlen < CHACHA20_BLOCKLEN && i < inlen; i++)
		ctx->m[i + ctx->mlen] = in[i];
	ctx->mlen += i;
	in += i;
	inlen -= i;

	if (ctx->mlen == CHACHA20_BLOCKLEN) {
		chacha20_block(ctx);
		ctx->n[0]++;

		for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++) {
			h = load32le(&ctx->m[i * 4]);
			h ^= ctx->s[i];
			store32le(&out[i * 4], h);
		}
		out += CHACHA20_BLOCKLEN;
		ctx->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= CHACHA20_BLOCKLEN) {
		chacha20_block(ctx);
		ctx->n[0]++;

		for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++) {
			h = load32le(&in[i * 4]);
			h ^= ctx->s[i];
			store32le(&out[i * 4], h);
		}
		out += CHACHA20_BLOCKLEN;
		in += CHACHA20_BLOCKLEN;
		inlen -= CHACHA20_BLOCKLEN;
	}

	for (i = 0; i < inlen; i++)
		ctx->m[i] = in[i];
	ctx->mlen = inlen;

	return 1;
}

static int
chacha20_anycrypt_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct chacha20_ctx	*ctx = arg;
	size_t			 i, off;
	uint32_t		 h;
	uint8_t			 s[4];

	*outlen = ctx->mlen;
	if (out == NULL)
		return 1;

	if (ctx->mlen > 0)
		chacha20_block(ctx);

	for (i = 0; i < ctx->mlen / 4; i++) {
		h = load32le(&ctx->m[i * 4]);
		h ^= ctx->s[i];
		store32le(&out[i * 4], h);
	}
	off = i * 4;
	ctx->mlen -= off;
	out += off;

	store32le(&s[0], ctx->s[i]);
	for (i = 0; i < ctx->mlen; i++)
		out[i] = ctx->m[i + off] ^ s[i];

	lc_scrub(ctx, sizeof(*ctx));

	return 1;
}

static int
chacha20_anycrypt(uint8_t *out, size_t *outlen, const void *initparams,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_ctx	ctx;
	size_t			l0, l1;
	int			rc;

	*outlen = 0;

	if (inlen > SIZE_MAX - (CHACHA20_BLOCKLEN - 1) ||
	    (inlen + CHACHA20_BLOCKLEN - 1) / CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	rc = chacha20_anycrypt_init(&ctx, initparams) &&
	    chacha20_anycrypt_update(&ctx, out, &l0, in, inlen) &&
	    chacha20_anycrypt_final(&ctx, out + l0, &l1);

	if (rc)
		*outlen = l0 + l1;

	return rc;
}

static void *
chacha20_ctx_new(void)
{
	return malloc(sizeof(struct chacha20_ctx));
}


static struct lc_cipher_impl	chacha20_impl = {
	.encrypt_init = &chacha20_anycrypt_init,
	.encrypt_update = &chacha20_anycrypt_update,
	.encrypt_final = &chacha20_anycrypt_final,
	.encrypt = &chacha20_anycrypt,

	.decrypt_init = &chacha20_anycrypt_init,
	.decrypt_update = &chacha20_anycrypt_update,
	.decrypt_final = &chacha20_anycrypt_final,
	.decrypt = &chacha20_anycrypt,

	.ctx_new = &chacha20_ctx_new,
	.ctx_free = NULL,
};

static struct lc_cipher_impl	xchacha20_impl = {
	.encrypt_init = &xchacha20_anycrypt_init,
	.encrypt_update = &chacha20_anycrypt_update,
	.encrypt_final = &chacha20_anycrypt_final,
	.encrypt = &chacha20_anycrypt,

	.decrypt_init = &xchacha20_anycrypt_init,
	.decrypt_update = &chacha20_anycrypt_update,
	.decrypt_final = &chacha20_anycrypt_final,
	.decrypt = &chacha20_anycrypt,

	.ctx_new = &chacha20_ctx_new,
	.ctx_free = NULL,
};

const struct lc_cipher_impl *
lc_cipher_impl_chacha20(void)
{
	return &chacha20_impl;
}

const struct lc_cipher_impl *
lc_cipher_impl_xchacha20(void)
{
	return &xchacha20_impl;
}
