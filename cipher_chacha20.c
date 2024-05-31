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

#include "lilcrypto.h"
#include "cipher.h"
#include "cipher_chacha20.h"
#include "impl_chacha20.h"

#include "util.h"


int
chacha20_x_init_from(void *arg, const uint8_t *key, size_t keylen,
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
	ctx->c = counter;
	for (i = 0; i < CHACHA20_NONCE_WORDS; i++)
		ctx->n[i] = load32le(&iv[i * 4]);
	ctx->blen = 0;

	return 1;
}

int
chacha20_x_init(void *arg, const uint8_t *key, size_t keylen,
    const uint8_t *iv, size_t ivlen)
{
	return chacha20_x_init_from(arg, key, keylen, iv, ivlen, 0);
}

int
chacha20_x_update(void *arg, uint8_t *out, size_t *outlen, const uint8_t *in,
    size_t inlen)
{
	struct chacha20_ctx	*ctx = arg;
	uint32_t		 h;
	uint8_t			 s[4];
	size_t			 i, blocks, off, pad;

	*outlen = 0;
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) - ctx->blen)
		return 0;
	blocks = inlen + ctx->blen + CHACHA20_CHUNK - 1;
	if (blocks / CHACHA20_CHUNK + ctx->c > CHACHA20_CTRMAX)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	*outlen = inlen;

	if (ctx->blen == 0)
		goto fullblock;

	off = ctx->blen % 4;
	if (off != 0) {
		store32le(s, ctx->s[ctx->blen / 4]);
		for (i = 0; i + off < 4 && i < inlen; i++)
			out[i] = in[i] ^ s[i + off];
		ctx->blen += i;
		out += i;
		in += i;
		inlen -= i;
	}

	pad = inlen % 4;
	for (i = 0; i + ctx->blen < CHACHA20_CHUNK && i < inlen - pad; i += 4) {
		h = load32le(&in[i * 4]);
		h ^= ctx->s[(i + ctx->blen) / 4];
		store32le(&out[i * 4], h);
	}
	ctx->blen += i * 4;
	out += i * 4;
	in += i * 4;
	inlen -= i * 4;

 fullblock:
	while (inlen >= CHACHA20_CHUNK) {
		chacha20_block(ctx);
		ctx->c++;

		for (i = 0; i < CHACHA20_CHUNK_WORDS; i++) {
			h = load32le(&in[i * 4]);
			h ^= ctx->s[i];
			store32le(&out[i * 4], h);
		}
		out += CHACHA20_CHUNK;
		in += CHACHA20_CHUNK;
		inlen -= CHACHA20_CHUNK;
	}

	chacha20_block(ctx);
	ctx->c++;
	ctx->blen = inlen;

	pad = inlen % 4;
	for (i = 0; i < (inlen - pad) / 4; i++) {
		h = load32le(&in[i * 4]);
		h ^= ctx->s[i];
		store32le(&out[i * 4], h);
	}
	out += i * 4;
	in += i * 4;
	inlen -= i * 4;

	store32le(s, ctx->s[i]);
	for (i = 0; i < pad; i++)
		out[i] = in[i] ^ s[i];

	return 1;
}

int
chacha20_x_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct chacha20_ctx	*ctx = arg;

	*outlen = 0;
	lc_scrub(ctx, sizeof(*ctx));

	return 1;
}

int
chacha20_x(const uint8_t *key, size_t keylen, const uint8_t *iv, size_t ivlen,
    uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen)
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

	rc = chacha20_x_init(&ctx, key, keylen, iv, ivlen) &&
	    chacha20_x_update(&ctx, out, &l0, in, inlen) &
	    chacha20_x_final(&ctx, out + l0, &l1);

	if (rc)
		*outlen = l0 + l1;

	return rc;
}


static struct lc_cipher_impl	chacha20_impl = {
	.encrypt_init = &chacha20_x_init,
	.encrypt_update = &chacha20_x_update,
	.encrypt_final = &chacha20_x_final,
	.encrypt = &chacha20_x,

	.decrypt_init = &chacha20_x_init,
	.decrypt_update = &chacha20_x_update,
	.decrypt_final = &chacha20_x_final,
	.decrypt = &chacha20_x,

	.argsz = sizeof(struct chacha20_ctx),
};

const struct lc_cipher_impl *
lc_cipher_impl_chacha20(void)
{
	return &chacha20_impl;
}
