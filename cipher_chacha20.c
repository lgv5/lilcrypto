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
#include "cipher_chacha20.h"
#include "impl_chacha20.h"

#include "util.h"


int
chacha20_common_init_from(void *arg, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen, uint32_t counter)
{
	struct chacha20_ctx	*ctx = arg;
	size_t			 i;

	if (keylen != LC_CHACHA20_KEYLEN || ivlen != LC_CHACHA20_IVLEN)
		return 0;

	for (i = 0; i < CHACHA20_CHUNK_WORDS; i++)
		ctx->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		ctx->k[i] = load32le(&key[i * 4]);
	ctx->n[0] = counter;
	for (i = 1; i < CHACHA20_NONCE_WORDS; i++)
		ctx->n[i] = load32le(&iv[(i - 1) * 4]);
	ctx->mlen = 0;

	return 1;
}

int
chacha20_common_init(void *arg, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen)
{
	return chacha20_common_init_from(arg, key, keylen, iv, ivlen, 0);
}

int
xchacha20_common_init_from(void *arg, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen, uint64_t counter)
{
	struct chacha20_ctx	*ctx = arg;
	size_t			 i;

	if (keylen != LC_XCHACHA20_KEYLEN || ivlen != LC_XCHACHA20_IVLEN)
		return 0;

	for (i = 0; i < CHACHA20_CHUNK_WORDS; i++)
		ctx->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		ctx->k[i] = load32le(&key[i * 4]);
	for (i = 0; i < CHACHA20_NONCE_WORDS; i++)
		ctx->n[i] = load32le(&iv[i * 4]);
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
	ctx->n[0] = counter;
	ctx->n[1] = counter >> 32;
	ctx->n[2] = load32le(&iv[16]);
	ctx->n[3] = load32le(&iv[20]);

	return 1;
}

int
xchacha20_common_init(void *arg, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen)
{
	return xchacha20_common_init_from(arg, key, keylen, iv, ivlen, 0);
}

int
chacha20_common_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_ctx	*ctx = arg;
	size_t			 i, blocks;
	uint32_t		 h;

	*outlen = 0;
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) - ctx->mlen)
		return 0;
	blocks = (inlen + ctx->mlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK;
	if (blocks + ctx->n[0] > CHACHA20_CTRMAX)
		return 0;

	*outlen = ctx->mlen + inlen - ((ctx->mlen + inlen) % CHACHA20_CHUNK);
	if (out == NULL)
		return 1;

	for (i = 0; i + ctx->mlen < CHACHA20_CHUNK && i < inlen; i++)
		ctx->m[i + ctx->mlen] = in[i];
	ctx->mlen += i;
	in += i;
	inlen -= i;

	if (ctx->mlen == CHACHA20_CHUNK) {
		chacha20_block(ctx);
		ctx->n[0]++;

		for (i = 0; i < CHACHA20_CHUNK_WORDS; i++) {
			h = load32le(&ctx->m[i * 4]);
			h ^= ctx->s[i];
			store32le(&out[i * 4], h);
		}
		out += CHACHA20_CHUNK;
		ctx->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= CHACHA20_CHUNK) {
		chacha20_block(ctx);
		ctx->n[0]++;

		for (i = 0; i < CHACHA20_CHUNK_WORDS; i++) {
			h = load32le(&in[i * 4]);
			h ^= ctx->s[i];
			store32le(&out[i * 4], h);
		}
		out += CHACHA20_CHUNK;
		in += CHACHA20_CHUNK;
		inlen -= CHACHA20_CHUNK;
	}

	for (i = 0; i < inlen; i++)
		ctx->m[i] = in[i];
	ctx->mlen = inlen;

	return 1;
}

int
chacha20_common_final(void *arg, uint8_t *out, size_t *outlen)
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

int
chacha20_common(const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, uint8_t *out, size_t *outlen, const uint8_t *in,
    size_t inlen)
{
	struct chacha20_ctx	ctx;
	size_t			l0, l1;
	int			rc;

	*outlen = 0;

	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK > CHACHA20_CTRMAX)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	rc = chacha20_common_init(&ctx, key, keylen, iv, ivlen) &&
	    chacha20_common_update(&ctx, out, &l0, in, inlen) &&
	    chacha20_common_final(&ctx, out + l0, &l1);

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
	.encrypt_init = &chacha20_common_init,
	.encrypt_update = &chacha20_common_update,
	.encrypt_final = &chacha20_common_final,
	.encrypt = &chacha20_common,

	.decrypt_init = &chacha20_common_init,
	.decrypt_update = &chacha20_common_update,
	.decrypt_final = &chacha20_common_final,
	.decrypt = &chacha20_common,

	.ctx_new = &chacha20_ctx_new,
	.ctx_free = NULL,
};

static struct lc_cipher_impl	xchacha20_impl = {
	.encrypt_init = &xchacha20_common_init,
	.encrypt_update = &chacha20_common_update,
	.encrypt_final = &chacha20_common_final,
	.encrypt = &chacha20_common,

	.decrypt_init = &xchacha20_common_init,
	.decrypt_update = &chacha20_common_update,
	.decrypt_final = &chacha20_common_final,
	.decrypt = &chacha20_common,

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
