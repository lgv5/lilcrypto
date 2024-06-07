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
#include "hash.h"
#include "impl_hmac.h"
#include "impl_sha256.h"
#include "impl_sha512.h"

#include "util.h"


#define HMAC_IPAD		UINT8_C(0x36)
#define HMAC_OPAD		UINT8_C(0x5c)


static int
hmac_common_init(void *arg, const uint8_t *key, size_t keylen)
{
	struct hmac_ctx	*ctx = arg;
	uint8_t		 ikeypad[HMAC_BLOCKSZ_MAX];
	size_t		 i, olen;

	if (keylen > ctx->blocksz) {
		if (!lc_hash_init(ctx->hctx) ||
		    !lc_hash_update(ctx->hctx, key, keylen) ||
		    !lc_hash_final(ctx->hctx, ctx->key, &olen))
			return 0;
		keylen = olen;
	} else
		for (i = 0; i < keylen; i++)
			ctx->key[i] = key[i];

	for (i = keylen; i < ctx->blocksz; i++)
		ctx->key[i] = 0;

	for (i = 0; i < ctx->blocksz; i++)
		ikeypad[i] = ctx->key[i] ^ HMAC_IPAD;

	return lc_hash_init(ctx->hctx) &&
	    lc_hash_update(ctx->hctx, ikeypad, ctx->blocksz);
}

static int
hmac_sha224_sha256_init(void *arg, const void *initparams)
{
	const struct lc_hmac_params	*params = initparams;
	struct hmac_ctx			*ctx = arg;

	ctx->blocksz = SHA256_CHUNK;

	return hmac_common_init(ctx, params->key, params->keylen);
}

static int
hmac_sha384_sha512_init(void *arg, const void *initparams)
{
	const struct lc_hmac_params	*params = initparams;
	struct hmac_ctx			*ctx = arg;

	ctx->blocksz = SHA512_CHUNK;

	return hmac_common_init(ctx, params->key, params->keylen);
}

static int
hmac_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct hmac_ctx	*ctx = arg;

	return lc_hash_update(ctx->hctx, in, inlen);
}

static int
hmac_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct hmac_ctx		*ctx = arg;
	struct lc_hash_ctx	*hctx;
	uint8_t			 m[HMAC_BLOCKSZ_MAX],
				    okeypad[HMAC_BLOCKSZ_MAX];
	size_t			 i, olen;
	int			 rc;

	if (out == NULL) {
		(void)lc_hash_final(ctx->hctx, NULL, outlen);
		return 1;
	}

	hctx = ctx->hctx;

	*outlen = 0;
	for (i = 0; i < ctx->blocksz; i++)
		okeypad[i] = ctx->key[i] ^ HMAC_OPAD;

	rc = lc_hash_final(ctx->hctx, m, &olen) &&
	    lc_hash_init(ctx->hctx) &&
	    lc_hash_update(ctx->hctx, okeypad, ctx->blocksz) &&
	    lc_hash_update(ctx->hctx, m, olen) &&
	    lc_hash_final(ctx->hctx, out, outlen);

	lc_scrub(ctx, sizeof(*ctx));
	ctx->hctx = hctx;

	return rc;
}

static void *
hmac_common_ctx_new(const struct lc_hash_impl *impl)
{
	struct hmac_ctx	*ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL)
		return NULL;
	ctx->hctx = lc_hash_ctx_new(impl);
	if (ctx->hctx == NULL) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

static void *
hmac_sha224_ctx_new(void)
{
	return hmac_common_ctx_new(lc_hash_impl_sha224());
}

static void *
hmac_sha256_ctx_new(void)
{
	return hmac_common_ctx_new(lc_hash_impl_sha256());
}

static void *
hmac_sha384_ctx_new(void)
{
	return hmac_common_ctx_new(lc_hash_impl_sha384());
}

static void *
hmac_sha512_ctx_new(void)
{
	return hmac_common_ctx_new(lc_hash_impl_sha512());
}

static void
hmac_ctx_free(void *arg)
{
	struct hmac_ctx	*ctx = arg;

	if (ctx != NULL)
		lc_hash_ctx_free(ctx->hctx);
}


static struct lc_auth_impl	hmac_sha224_impl = {
	.init = &hmac_sha224_sha256_init,
	.update = &hmac_update,
	.final = &hmac_final,
	.auth = NULL,

	.ctx_new = &hmac_sha224_ctx_new,
	.ctx_free = &hmac_ctx_free,
};

static struct lc_auth_impl	hmac_sha256_impl = {
	.init = &hmac_sha224_sha256_init,
	.update = &hmac_update,
	.final = &hmac_final,
	.auth = NULL,

	.ctx_new = &hmac_sha256_ctx_new,
	.ctx_free = &hmac_ctx_free,
};

static struct lc_auth_impl	hmac_sha384_impl = {
	.init = &hmac_sha384_sha512_init,
	.update = &hmac_update,
	.final = &hmac_final,
	.auth = NULL,

	.ctx_new = &hmac_sha384_ctx_new,
	.ctx_free = &hmac_ctx_free,
};

static struct lc_auth_impl	hmac_sha512_impl = {
	.init = &hmac_sha384_sha512_init,
	.update = &hmac_update,
	.final = &hmac_final,
	.auth = NULL,

	.ctx_new = &hmac_sha512_ctx_new,
	.ctx_free = &hmac_ctx_free,
};

const struct lc_auth_impl *
lc_auth_impl_hmac_sha224(void)
{
	return &hmac_sha224_impl;
}

const struct lc_auth_impl *
lc_auth_impl_hmac_sha256(void)
{
	return &hmac_sha256_impl;
}

const struct lc_auth_impl *
lc_auth_impl_hmac_sha384(void)
{
	return &hmac_sha384_impl;
}

const struct lc_auth_impl *
lc_auth_impl_hmac_sha512(void)
{
	return &hmac_sha512_impl;
}
