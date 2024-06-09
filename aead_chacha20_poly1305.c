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
#include "impl_chacha20.h"

#include "util.h"


/*
 * Implements ChaCha20-Poly1305 according to RFC 8439, XChaCha20-Poly1305
 * according to draft-irtf-cfrg-xchacha-03.
 */

static const uint8_t	zeropad[16];

static int
aead_poly1305_keysetup(struct lc_cipher_ctx *cctx,
    uint8_t akey[LC_POLY1305_KEYLEN], const void *initparams)
{
	size_t	i, olen, akeylen;

	for (i = 0; i < LC_POLY1305_KEYLEN; i++)
		akey[i] = 0;
	if (!lc_cipher_encrypt_init(cctx, initparams) ||
	    !lc_cipher_encrypt_update(cctx, akey, &olen, akey,
	    LC_POLY1305_KEYLEN))
		return 0;
	akeylen = olen;
	if (!lc_cipher_encrypt_final(cctx, akey + olen, &olen))
		return 0;
	akeylen += olen;

	return akeylen == LC_POLY1305_KEYLEN;
}

static int
chacha20_poly1305_seal(uint8_t *out, size_t *outlen, const void *initparams,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	const struct lc_chacha20_poly1305_params	*params = initparams;
	struct lc_cipher_ctx		*cctx = NULL;
	struct lc_auth_ctx		*actx = NULL;
	struct lc_chacha20_params	 cparams;
	struct lc_poly1305_params	 aparams;
	uint8_t				 buf[sizeof(uint64_t) * 2];
	size_t				 i, olen;
	int				 ret = 0;

	*outlen = 0;
	/* inlen and aadlen are capped by design; enough space of tag. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX ||
	    inlen > SIZE_MAX - LC_POLY1305_TAGLEN)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL) {
		*outlen = inlen + LC_POLY1305_TAGLEN;
		return 1;
	}

	cctx = lc_cipher_ctx_new(lc_cipher_impl_chacha20());
	if (cctx == NULL)
		goto cleanup;
	actx = lc_auth_ctx_new(lc_auth_impl_poly1305());
	if (actx == NULL)
		goto cleanup;

	for (i = 0; i < sizeof(params->key); i++)
		cparams.key[i] = params->key[i];
	for (i = 0; i < sizeof(params->nonce); i++)
		cparams.nonce[i] = params->nonce[i];

	cparams.counter = 0;
	if (!aead_poly1305_keysetup(cctx, aparams.key, &cparams))
		goto cleanup;

	if (!lc_auth_init(actx, &aparams) ||
	    !lc_auth_update(actx, aad, aadlen))
		goto cleanup;
	if (aadlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (aadlen % 16)))
			goto cleanup;

	cparams.counter = 1;
	if (!lc_cipher_encrypt_init(cctx, &cparams) ||
	    !lc_cipher_encrypt_update(cctx, out, &olen, in, inlen))
		goto cleanup;
	*outlen = olen;
	if (!lc_cipher_encrypt_final(cctx, out + olen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != inlen)
		goto cleanup;

	if (!lc_auth_update(actx, out, inlen))
		goto cleanup;
	if (inlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (inlen % 16)))
			goto cleanup;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], inlen);
	if (!lc_auth_update(actx, buf, sizeof(buf)) ||
	    !lc_auth_final(actx, out + inlen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != inlen + LC_POLY1305_TAGLEN)
		goto cleanup;
	ret = 1;

 cleanup:
	lc_scrub(buf, sizeof(buf));
	lc_scrub(&aparams, sizeof(aparams));
	lc_scrub(&cparams, sizeof(cparams));
	lc_auth_ctx_free(actx);
	lc_cipher_ctx_free(cctx);

	return ret;
}

static int
xchacha20_poly1305_seal(uint8_t *out, size_t *outlen, const void *initparams,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	const struct lc_xchacha20_poly1305_params	*params = initparams;
	struct lc_cipher_ctx		*cctx = NULL;
	struct lc_auth_ctx		*actx = NULL;
	struct lc_xchacha20_params	 cparams;
	struct lc_poly1305_params	 aparams;
	uint8_t				 buf[sizeof(uint64_t) * 2];
	size_t				 i, olen;
	int				 ret = 0;

	*outlen = 0;
	/* inlen and aadlen are capped by design; enough space of tag. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX ||
	    inlen > SIZE_MAX - LC_POLY1305_TAGLEN)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL) {
		*outlen = inlen + LC_POLY1305_TAGLEN;
		return 1;
	}

	cctx = lc_cipher_ctx_new(lc_cipher_impl_xchacha20());
	if (cctx == NULL)
		goto cleanup;
	actx = lc_auth_ctx_new(lc_auth_impl_poly1305());
	if (actx == NULL)
		goto cleanup;

	for (i = 0; i < sizeof(params->key); i++)
		cparams.key[i] = params->key[i];
	for (i = 0; i < sizeof(params->nonce); i++)
		cparams.nonce[i] = params->nonce[i];

	cparams.counter = 0;
	if (!aead_poly1305_keysetup(cctx, aparams.key, &cparams))
		goto cleanup;

	if (!lc_auth_init(actx, &aparams) ||
	    !lc_auth_update(actx, aad, aadlen))
		goto cleanup;
	if (aadlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (aadlen % 16)))
			goto cleanup;

	cparams.counter = 1;
	if (!lc_cipher_encrypt_init(cctx, &cparams) ||
	    !lc_cipher_encrypt_update(cctx, out, &olen, in, inlen))
		goto cleanup;
	*outlen = olen;
	if (!lc_cipher_encrypt_final(cctx, out + olen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != inlen)
		goto cleanup;

	if (!lc_auth_update(actx, out, inlen))
		goto cleanup;
	if (inlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (inlen % 16)))
			goto cleanup;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], inlen);
	if (!lc_auth_update(actx, buf, sizeof(buf)) ||
	    !lc_auth_final(actx, out + inlen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != inlen + LC_POLY1305_TAGLEN)
		goto cleanup;
	ret = 1;

 cleanup:
	lc_scrub(buf, sizeof(buf));
	lc_scrub(&aparams, sizeof(aparams));
	lc_scrub(&cparams, sizeof(cparams));
	lc_auth_ctx_free(actx);
	lc_cipher_ctx_free(cctx);

	return ret;
}

static int
chacha20_poly1305_open(uint8_t *out, size_t *outlen, const void *initparams,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	const struct lc_chacha20_poly1305_params	*params = initparams;
	struct lc_cipher_ctx		*cctx = NULL;
	struct lc_auth_ctx		*actx = NULL;
	struct lc_chacha20_params	 cparams;
	struct lc_poly1305_params	 aparams;
	uint8_t				 tag[LC_POLY1305_TAGLEN];
	uint8_t				 buf[sizeof(uint64_t) * 2];
	size_t				 i, olen, ctlen;
	int				 ret = 0;

	*outlen = 0;
	/* inlen includes the tag; inlen and aadlen are capped by design. */
	if (inlen < LC_POLY1305_TAGLEN ||
	    inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1) {
		return 0;
	}

	if (out == NULL) {
		*outlen = inlen - LC_POLY1305_TAGLEN;
		return 1;
	}

	cctx = lc_cipher_ctx_new(lc_cipher_impl_chacha20());
	if (cctx == NULL)
		goto cleanup;
	actx = lc_auth_ctx_new(lc_auth_impl_poly1305());
	if (actx == NULL)
		goto cleanup;

	for (i = 0; i < sizeof(params->key); i++)
		cparams.key[i] = params->key[i];
	for (i = 0; i < sizeof(params->nonce); i++)
		cparams.nonce[i] = params->nonce[i];

	cparams.counter = 0;
	if (!aead_poly1305_keysetup(cctx, aparams.key, &cparams))
		goto cleanup;

	if (!lc_auth_init(actx, &aparams) ||
	    !lc_auth_update(actx, aad, aadlen))
		goto cleanup;
	if (aadlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (aadlen % 16)))
			goto cleanup;

	ctlen = inlen - LC_POLY1305_TAGLEN;
	if (!lc_auth_update(actx, in, ctlen))
		goto cleanup;
	if (ctlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (ctlen % 16)))
			goto cleanup;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], ctlen);
	if (!lc_auth_update(actx, buf, sizeof(buf)) ||
	    !lc_auth_final(actx, tag, &olen))
		goto cleanup;
	if (olen != LC_POLY1305_TAGLEN)
		goto cleanup;
	if (!lc_ct_cmp(tag, in + ctlen, LC_POLY1305_TAGLEN))
		goto cleanup;

	cparams.counter = 1;
	if (!lc_cipher_decrypt_init(cctx, &cparams) ||
	    !lc_cipher_decrypt_update(cctx, out, &olen, in, ctlen))
		goto cleanup;
	*outlen = olen;
	if (!lc_cipher_decrypt_final(cctx, out + olen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != ctlen)
		goto cleanup;

	ret = 1;

 cleanup:
	lc_scrub(buf, sizeof(buf));
	lc_scrub(&aparams, sizeof(aparams));
	lc_scrub(&cparams, sizeof(cparams));
	lc_scrub(tag, sizeof(tag));
	lc_auth_ctx_free(actx);
	lc_cipher_ctx_free(cctx);

	return ret;
}

static int
xchacha20_poly1305_open(uint8_t *out, size_t *outlen, const void *initparams,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	const struct lc_xchacha20_poly1305_params	*params = initparams;
	struct lc_cipher_ctx		*cctx = NULL;
	struct lc_auth_ctx		*actx = NULL;
	struct lc_xchacha20_params	 cparams;
	struct lc_poly1305_params	 aparams;
	uint8_t				 tag[LC_POLY1305_TAGLEN];
	uint8_t				 buf[sizeof(uint64_t) * 2];
	size_t				 i, olen, ctlen;
	int				 ret = 0;

	*outlen = 0;
	/* inlen includes the tag; inlen and aadlen are capped by design. */
	if (inlen < LC_POLY1305_TAGLEN ||
	    inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (CHACHA20_CHUNK - 1) ||
	    (inlen + CHACHA20_CHUNK - 1) / CHACHA20_CHUNK >
	    CHACHA20_CTRMAX - 1) {
		return 0;
	}

	if (out == NULL) {
		*outlen = inlen - LC_POLY1305_TAGLEN;
		return 1;
	}

	cctx = lc_cipher_ctx_new(lc_cipher_impl_xchacha20());
	if (cctx == NULL)
		goto cleanup;
	actx = lc_auth_ctx_new(lc_auth_impl_poly1305());
	if (actx == NULL)
		goto cleanup;

	for (i = 0; i < sizeof(params->key); i++)
		cparams.key[i] = params->key[i];
	for (i = 0; i < sizeof(params->nonce); i++)
		cparams.nonce[i] = params->nonce[i];

	cparams.counter = 0;
	if (!aead_poly1305_keysetup(cctx, aparams.key, &cparams))
		goto cleanup;

	if (!lc_auth_init(actx, &aparams) ||
	    !lc_auth_update(actx, aad, aadlen))
		goto cleanup;
	if (aadlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (aadlen % 16)))
			goto cleanup;

	ctlen = inlen - LC_POLY1305_TAGLEN;
	if (!lc_auth_update(actx, in, ctlen))
		goto cleanup;
	if (ctlen % 16 != 0)
		if (!lc_auth_update(actx, zeropad, 16 - (ctlen % 16)))
			goto cleanup;

	store64le(&buf[0], aadlen);
	store64le(&buf[sizeof(uint64_t)], ctlen);
	if (!lc_auth_update(actx, buf, sizeof(buf)) ||
	    !lc_auth_final(actx, tag, &olen))
		goto cleanup;
	if (olen != LC_POLY1305_TAGLEN)
		goto cleanup;
	if (!lc_ct_cmp(tag, in + ctlen, LC_POLY1305_TAGLEN))
		goto cleanup;

	cparams.counter = 1;
	if (!lc_cipher_decrypt_init(cctx, &cparams) ||
	    !lc_cipher_decrypt_update(cctx, out, &olen, in, ctlen))
		goto cleanup;
	*outlen = olen;
	if (!lc_cipher_decrypt_final(cctx, out + olen, &olen))
		goto cleanup;
	*outlen += olen;
	if (*outlen != ctlen)
		goto cleanup;
	ret = 1;

 cleanup:
	lc_scrub(buf, sizeof(buf));
	lc_scrub(&aparams, sizeof(aparams));
	lc_scrub(&cparams, sizeof(cparams));
	lc_scrub(tag, sizeof(tag));
	lc_auth_ctx_free(actx);
	lc_cipher_ctx_free(cctx);

	return ret;
}


static struct lc_aead_impl	chacha20_poly1305_impl = {
	.seal = &chacha20_poly1305_seal,
	.open = &chacha20_poly1305_open,
};

static struct lc_aead_impl	xchacha20_poly1305_impl = {
	.seal = &xchacha20_poly1305_seal,
	.open = &xchacha20_poly1305_open,
};

const struct lc_aead_impl *
lc_aead_impl_chacha20_poly1305(void)
{
	return &chacha20_poly1305_impl;
}

const struct lc_aead_impl *
lc_aead_impl_xchacha20_poly1305(void)
{
	return &xchacha20_poly1305_impl;
}
