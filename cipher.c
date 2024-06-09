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
#include "cipher.h"


int
lc_cipher_encrypt_init(struct lc_cipher_ctx *ctx, void *initparams)
{
	return ctx->impl->encrypt_init(ctx->arg, initparams);
}

int
lc_cipher_encrypt_update(struct lc_cipher_ctx *ctx, uint8_t *out,
    size_t *outlen, const uint8_t *in, size_t inlen)
{
	return ctx->impl->encrypt_update(ctx->arg, out, outlen, in, inlen);
}

int
lc_cipher_encrypt_final(struct lc_cipher_ctx *ctx, uint8_t *out,
    size_t *outlen)
{
	return ctx->impl->encrypt_final(ctx->arg, out, outlen);
}

int
lc_cipher_encrypt(const struct lc_cipher_impl *impl, uint8_t *out,
    size_t *outlen, void *initparams, const uint8_t *in, size_t inlen)
{
	return impl->encrypt(out, outlen, initparams, in, inlen);
}

int
lc_cipher_decrypt_init(struct lc_cipher_ctx *ctx, void *initparams)
{
	return ctx->impl->decrypt_init(ctx->arg, initparams);
}

int
lc_cipher_decrypt_update(struct lc_cipher_ctx *ctx, uint8_t *out,
    size_t *outlen, const uint8_t *in, size_t inlen)
{
	return ctx->impl->decrypt_update(ctx->arg, out, outlen, in, inlen);
}

int
lc_cipher_decrypt_final(struct lc_cipher_ctx *ctx, uint8_t *out,
    size_t *outlen)
{
	return ctx->impl->decrypt_final(ctx->arg, out, outlen);
}

int
lc_cipher_decrypt(const struct lc_cipher_impl *impl, uint8_t *out,
    size_t *outlen, void *initparams, const uint8_t *in, size_t inlen)
{
	return impl->decrypt(out, outlen, initparams, in, inlen);
}

struct lc_cipher_ctx *
lc_cipher_ctx_new(const struct lc_cipher_impl *impl)
{
	struct lc_cipher_ctx	*ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	if (impl->ctx_new != NULL) {
		ctx->arg = impl->ctx_new();
		if (ctx->arg == NULL) {
			free(ctx);
			return NULL;
		}
	} else
		ctx->arg = NULL;
	ctx->impl = impl;

	return ctx;
}

void
lc_cipher_ctx_free(struct lc_cipher_ctx *ctx)
{
	if (ctx != NULL) {
		if (ctx->impl != NULL && ctx->impl->ctx_free != NULL)
			ctx->impl->ctx_free(ctx->arg);
		free(ctx->arg);
	}
	free(ctx);
}
