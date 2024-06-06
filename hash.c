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
#include <string.h>

#include "lilcrypto.h"
#include "hash.h"


int
lc_hash_init(struct lc_hash_ctx *ctx)
{
	return ctx->impl->init(ctx->arg);
}

int
lc_hash_update(struct lc_hash_ctx *ctx, const uint8_t *in, size_t inlen)
{
	return ctx->impl->update(ctx->arg, in, inlen);
}

int
lc_hash_final(struct lc_hash_ctx *ctx, uint8_t *out, size_t *outlen)
{
	return ctx->impl->final(ctx->arg, out, outlen);
}

int
lc_hash(const struct lc_hash_impl *impl, uint8_t *out, size_t *outlen,
    const uint8_t *in, size_t inlen)
{
	return impl->hash(out, outlen, in, inlen);
}

struct lc_hash_ctx *
lc_hash_ctx_new(const struct lc_hash_impl *impl)
{
	struct lc_hash_ctx	*ctx;

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
lc_hash_ctx_free(struct lc_hash_ctx *ctx)
{
	if (ctx != NULL) {
		if (ctx->impl != NULL && ctx->impl->ctx_free != NULL)
			ctx->impl->ctx_free(ctx->arg);
		free(ctx->arg);
	}
	free(ctx);
}
