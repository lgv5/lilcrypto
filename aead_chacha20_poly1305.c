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

#include "lilcrypto.h"
#include "aead.h"
#include "auth_poly1305.h"
#include "cipher_chacha20.h"
#include "impl_chacha20.h"
#include "impl_poly1305.h"

#include "util.h"


/*
 * Implements ChaCha20-Poly1305 according to RFC 8439.
 */

static uint8_t	zeropad[16];

static int
chacha20_poly1305_seal(const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, uint8_t *out, size_t *outlen, const uint8_t *aad,
    size_t aadlen, const uint8_t *in, size_t inlen)
{
	struct chacha20_ctx	cctx;
	struct poly1305_ctx	pctx;
	uint8_t			poly1305_key[LC_POLY1305_KEYLEN];
	uint8_t			buf[sizeof(uint64_t) * 2];
	size_t			i, olen;

	if (inlen > UINT64_MAX || aadlen > UINT64_MAX ||
	    inlen > SIZE_MAX - LC_POLY1305_TAGLEN ||
	    inlen > SIZE_MAX - CHACHA20_CHUNK + 1 ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1) {
		if (out == NULL)
			*outlen = 0;
		return 0;
	}

	if (out == NULL) {
		*outlen = inlen + LC_POLY1305_TAGLEN;
		return 1;
	}

	*outlen = 0;

	for (i = 0; i < LC_POLY1305_KEYLEN; i++)
		poly1305_key[i] = 0;
	if (!chacha20_x_init(&cctx, key, keylen, iv, ivlen) ||
	    !chacha20_x_update(&cctx, poly1305_key, &olen, poly1305_key,
	    LC_POLY1305_KEYLEN))
		return 0;
	if (!chacha20_x_final(&cctx, poly1305_key + olen, &olen))
		return 0;

	if (!poly1305_init(&pctx, poly1305_key, LC_POLY1305_KEYLEN) ||
	    !poly1305_update(&pctx, aad, aadlen))
		return 0;
	if (aadlen % 16 != 0)
		if (!poly1305_update(&pctx, zeropad, 16 - (aadlen % 16)))
			return 0;

	if (!chacha20_x_init_from(&cctx, key, keylen, iv, ivlen, 1))
		return 0;
	if (!chacha20_x_update(&cctx, out, &olen, in, inlen))
		return 0;
	*outlen = olen;
	if (!chacha20_x_final(&cctx, out + olen, &olen))
		return 0;
	if (!poly1305_update(&pctx, out, inlen))
		return 0;
	if (inlen % 16 != 0)
		if (!poly1305_update(&pctx, zeropad, 16 - (inlen % 16)))
			return 0;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], inlen);
	if (!poly1305_update(&pctx, buf, sizeof(buf)) ||
	    !poly1305_final(&pctx, out + inlen, &olen))
		return 0;

	lc_scrub(buf, sizeof(buf));
	lc_scrub(poly1305_key, sizeof(poly1305_key));

	*outlen = inlen + LC_POLY1305_TAGLEN;

	return 1;
}

static int
chacha20_poly1305_open(const uint8_t *key, size_t keylen, const uint8_t *iv,
    size_t ivlen, uint8_t *out, size_t *outlen, const uint8_t *aad,
    size_t aadlen, const uint8_t *in, size_t inlen)
{
	const uint8_t		*tagp;
	struct chacha20_ctx	 cctx;
	struct poly1305_ctx	 pctx;
	uint8_t			 poly1305_key[LC_POLY1305_KEYLEN];
	uint8_t			 tag[LC_POLY1305_TAGLEN];
	uint8_t			 buf[sizeof(uint64_t) * 2];
	size_t			 i, olen, ctlen;

	if (inlen < LC_POLY1305_TAGLEN ||
	    inlen > UINT64_MAX || aadlen > UINT64_MAX ||
	    inlen > SIZE_MAX - LC_POLY1305_TAGLEN ||
	    inlen > SIZE_MAX - CHACHA20_CHUNK + 1 ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1) {
		if (out == NULL)
			*outlen = 0;
		return 0;
	}

	if (out == NULL) {
		*outlen = inlen - LC_POLY1305_TAGLEN;
		return 1;
	}

	*outlen = 0;
	ctlen = inlen - LC_POLY1305_TAGLEN;
	tagp = in + ctlen;

	for (i = 0; i < LC_POLY1305_KEYLEN; i++)
		poly1305_key[i] = 0;
	if (!chacha20_x_init(&cctx, key, keylen, iv, ivlen) ||
	    !chacha20_x_update(&cctx, poly1305_key, &olen, poly1305_key,
	    LC_POLY1305_KEYLEN))
		return 0;
	if (!chacha20_x_final(&cctx, poly1305_key + olen, &olen))
		return 0;

	if (!poly1305_init(&pctx, poly1305_key, LC_POLY1305_KEYLEN) ||
	    !poly1305_update(&pctx, aad, aadlen))
		return 0;
	if (aadlen % 16 != 0)
		if (!poly1305_update(&pctx, zeropad, 16 - (aadlen % 16)))
			return 0;

	if (!poly1305_update(&pctx, in, ctlen))
		return 0;
	if (ctlen % 16 != 0)
		if (!poly1305_update(&pctx, zeropad, 16 - (ctlen % 16)))
			return 0;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], ctlen);
	if (!poly1305_update(&pctx, buf, sizeof(buf)) ||
	    !poly1305_final(&pctx, tag, &olen))
		return 0;

	if (!lc_ct_cmp(tag, tagp, LC_POLY1305_TAGLEN))
		return 0;

	lc_scrub(buf, sizeof(buf));
	lc_scrub(poly1305_key, sizeof(poly1305_key));

	if (!chacha20_x_init_from(&cctx, key, keylen, iv, ivlen, 1))
		return 0;
	if (!chacha20_x_update(&cctx, out, &olen, in, ctlen))
		return 0;
	*outlen = olen;
	if (!chacha20_x_final(&cctx, out + olen, &olen))
		return 0;
	*outlen += olen;

	return 1;
}


static struct lc_aead_impl	chacha20_poly1305_impl = {
	.seal = &chacha20_poly1305_seal,
	.open = &chacha20_poly1305_open,
};

const struct lc_aead_impl *
lc_aead_impl_chacha20_poly1305(void)
{
	return &chacha20_poly1305_impl;
}
