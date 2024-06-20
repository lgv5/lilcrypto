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
#include <string.h>

#include "internal.h"
#include "util.h"


/*
 * Implements ChaCha20-Poly1305 according to RFC 8439, XChaCha20-Poly1305
 * according to draft-irtf-cfrg-xchacha-03.
 */

enum aead_mode {
	AEAD_SEAL,
	AEAD_OPEN,
};


static int
chacha20_poly1305_anycrypt_init(void *arg, void *initparams, enum aead_mode m)
{
	struct lc_chacha20_poly1305_params	*params = initparams;
	struct chacha20_poly1305_state		*state = arg;
	struct lc_chacha20_params		 cparams;
	struct lc_poly1305_params		 aparams;
	size_t					 olen;

	if (params->cipher->impl != lc_cipher_impl_chacha20() ||
	    params->auth->impl != lc_auth_impl_poly1305())
		return 0;

	state->auth = params->auth;
	state->cipher = params->cipher;
	state->aadlen = state->ctlen = 0;
	state->aaddone = 0;

	memcpy(cparams.key, params->key, sizeof(params->key));
	memcpy(cparams.nonce, params->nonce, sizeof(params->nonce));

	cparams.counter = 0;
	if (!lc_cipher_encrypt(state->cipher->impl, aparams.key, &olen,
	    &cparams, zerobuf, LC_POLY1305_KEYLEN))
		return 0;

	if (!lc_auth_init(state->auth, &aparams))
		return 0;
	cparams.counter = 1;

	switch (m) {
	case AEAD_SEAL:
		if (!lc_cipher_encrypt_init(state->cipher, &cparams))
			return 0;
		break;
	case AEAD_OPEN:
		if (!lc_cipher_decrypt_init(state->cipher, &cparams))
			return 0;
		break;
	default:
		return 0;
	}

	return 1;
}

static int
xchacha20_poly1305_anycrypt_init(void *arg, void *initparams, enum aead_mode m)
{
	struct lc_xchacha20_poly1305_params	*params = initparams;
	struct chacha20_poly1305_state		*state = arg;
	struct lc_xchacha20_params		 cparams;
	struct lc_poly1305_params		 aparams;
	size_t					 olen;

	if (params->cipher->impl != lc_cipher_impl_xchacha20() ||
	    params->auth->impl != lc_auth_impl_poly1305())
		return 0;

	state->auth = params->auth;
	state->cipher = params->cipher;
	state->aadlen = state->ctlen = 0;
	state->aaddone = 0;

	memcpy(cparams.key, params->key, sizeof(params->key));
	memcpy(cparams.nonce, params->nonce, sizeof(params->nonce));

	cparams.counter = 0;
	if (!lc_cipher_encrypt(state->cipher->impl, aparams.key, &olen,
	    &cparams, zerobuf, LC_POLY1305_KEYLEN))
		return 0;

	if (!lc_auth_init(state->auth, &aparams))
		return 0;
	cparams.counter = 1;

	switch (m) {
	case AEAD_SEAL:
		if (!lc_cipher_encrypt_init(state->cipher, &cparams))
			return 0;
		break;
	case AEAD_OPEN:
		if (!lc_cipher_decrypt_init(state->cipher, &cparams))
			return 0;
		break;
	default:
		return 0;
	}

	return 1;
}

static int
c20_xc20_poly1305_anycrypt_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen,
    enum aead_mode m)
{
	struct chacha20_poly1305_state	*state = arg;
	size_t				 ctlen;

	*outlen = 0;
	switch (m) {
	case AEAD_SEAL:
		if (!lc_cipher_encrypt_update(state->cipher, NULL, &ctlen, in,
		    inlen))
			return 0;
		break;
	case AEAD_OPEN:
		if (!lc_cipher_decrypt_update(state->cipher, NULL, &ctlen, in,
		    inlen))
			return 0;
		break;
	default:
		if (!lc_cipher_decrypt_update(state->cipher, NULL, &ctlen, in,
		    inlen))
			return 0;
		return 0;
	}

	if (aadlen > UINT64_MAX - state->aadlen ||
	    ctlen > UINT64_MAX - state->ctlen)
		return 0;
	if (aadlen > 0 && state->aaddone)
		return 0;

	if (out == NULL) {
		*outlen = ctlen;
		return 1;
	}

	if (aadlen > 0) {
		if (!lc_auth_update(state->auth, aad, aadlen))
			return 0;
		state->aadlen += aadlen;
	}

	if (inlen > 0) {
		if (!state->aaddone) {
			if (state->aadlen % 16 != 0 &&
			    !lc_auth_update(state->auth, zerobuf,
			    16 - (state->aadlen % 16)))
					return 0;
			state->aaddone = 1;
		}

		switch (m) {
		case AEAD_SEAL:
			if (!lc_cipher_encrypt_update(state->cipher, out,
			    outlen, in, inlen))
				return 0;
			if (!lc_auth_update(state->auth, out, *outlen))
				return 0;
			state->ctlen += *outlen;
			break;
		case AEAD_OPEN:
			if (!lc_auth_update(state->auth, in, inlen))
				return 0;
			if (!lc_cipher_decrypt_update(state->cipher, out,
			    outlen, in, inlen))
				return 0;
			state->ctlen += inlen;
			break;
		default:
			return 0;
		}
	}

	return 1;
}

static int
chacha20_poly1305_seal_init(void *arg, void *initparams)
{
	return chacha20_poly1305_anycrypt_init(arg, initparams, AEAD_SEAL);
}

static int
xchacha20_poly1305_seal_init(void *arg, void *initparams)
{
	return xchacha20_poly1305_anycrypt_init(arg, initparams, AEAD_SEAL);
}

static int
c20_xc20_poly1305_seal_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	return c20_xc20_poly1305_anycrypt_update(arg, out, outlen, aad, aadlen,
	    in, inlen, AEAD_SEAL);
}

static int
c20_xc20_poly1305_seal_final(void *arg, uint8_t *out, size_t *outlen,
    uint8_t *tag, size_t *taglen)
{
	struct chacha20_poly1305_state	*state = arg;
	uint8_t				 buf[sizeof(uint64_t) * 2];
	size_t				 ctlen;

	*outlen = *taglen = 0;
	if (!lc_cipher_encrypt_final(state->cipher, NULL, &ctlen))
		return 0;
	if (ctlen > UINT64_MAX - state->ctlen)
		return 0;

	if (out == NULL || tag == NULL) {
		*outlen = ctlen;
		*taglen = LC_POLY1305_TAGLEN;
		return 1;
	}

	if (!state->aaddone) {
		if (state->aadlen % 16 != 0 &&
		    !lc_auth_update(state->auth, zerobuf,
		    16 - (state->aadlen % 16)))
				return 0;
		state->aaddone = 1;
	}

	if (!lc_cipher_encrypt_final(state->cipher, out, outlen))
		return 0;

	if (!lc_auth_update(state->auth, out, *outlen))
		return 0;
	state->ctlen += *outlen;
	if (state->ctlen % 16 != 0 &&
	    !lc_auth_update(state->auth, zerobuf, 16 - (state->ctlen % 16)))
		return 0;

	store64le(&buf[0], state->aadlen);
	store64le(&buf[sizeof(uint64_t)], state->ctlen);
	if (!lc_auth_update(state->auth, buf, sizeof(buf)) ||
	    !lc_auth_final(state->auth, tag, taglen))
		return 0;

	return 1;
}

static int
chacha20_poly1305_seal(uint8_t *out, size_t *outlen, uint8_t *tag,
    size_t *taglen, void *initparams, const uint8_t *aad, size_t aadlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_poly1305_state	state;
	size_t				olen;

	*outlen = *taglen = 0;
	/* inlen and aadlen are capped by design. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL || tag == NULL) {
		*outlen = inlen;
		*taglen = LC_POLY1305_TAGLEN;
		return 1;
	}

	if (!chacha20_poly1305_anycrypt_init(&state, initparams, AEAD_SEAL))
		return 0;
	if (!c20_xc20_poly1305_anycrypt_update(&state, out, &olen, aad, aadlen,
	    in, inlen, AEAD_SEAL))
		return 0;
	*outlen = olen;
	if (!c20_xc20_poly1305_seal_final(&state, out + olen, &olen, tag,
	    taglen))
		return 0;
	*outlen += olen;

	return 1;
}

static int
xchacha20_poly1305_seal(uint8_t *out, size_t *outlen, uint8_t *tag,
    size_t *taglen, void *initparams, const uint8_t *aad, size_t aadlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_poly1305_state	state;
	size_t				olen;

	*outlen = *taglen = 0;
	/* inlen and aadlen are capped by design. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL || tag == NULL) {
		*outlen = inlen;
		*taglen = LC_POLY1305_TAGLEN;
		return 1;
	}

	if (!xchacha20_poly1305_anycrypt_init(&state, initparams, AEAD_SEAL))
		return 0;
	if (!c20_xc20_poly1305_anycrypt_update(&state, out, &olen, aad, aadlen,
	    in, inlen, AEAD_SEAL))
		return 0;
	*outlen = olen;
	if (!c20_xc20_poly1305_seal_final(&state, out + olen, &olen, tag,
	    taglen))
		return 0;
	*outlen += olen;

	return 1;
}

static int
chacha20_poly1305_open_init(void *arg, void *initparams)
{
	return chacha20_poly1305_anycrypt_init(arg, initparams, AEAD_OPEN);
}

static int
xchacha20_poly1305_open_init(void *arg, void *initparams)
{
	return xchacha20_poly1305_anycrypt_init(arg, initparams, AEAD_OPEN);
}

static int
c20_xc20_poly1305_open_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *aad, size_t aadlen, const uint8_t *in, size_t inlen)
{
	return c20_xc20_poly1305_anycrypt_update(arg, out, outlen, aad, aadlen,
	    in, inlen, AEAD_OPEN);
}

static int
c20_xc20_poly1305_open_final(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *tag, size_t taglen)
{
	struct chacha20_poly1305_state	*state = arg;
	uint8_t				 buf[sizeof(uint64_t) * 2],
					    ctag[LC_POLY1305_TAGLEN];
	size_t				 ctlen, ctaglen;

	*outlen = 0;
	if (!lc_cipher_decrypt_final(state->cipher, NULL, &ctlen))
		return 0;
	if (ctlen > UINT64_MAX - state->ctlen ||
	    taglen != LC_POLY1305_TAGLEN)
		return 0;

	if (out == NULL) {
		*outlen = ctlen;
		return 1;
	}

	if (!state->aaddone) {
		if (state->aadlen % 16 != 0 &&
		    !lc_auth_update(state->auth, zerobuf,
		    16 - (state->aadlen % 16)))
				return 0;
		state->aaddone = 1;
	}

	if (state->ctlen % 16 != 0 &&
	    !lc_auth_update(state->auth, zerobuf, 16 - (state->ctlen % 16)))
		return 0;

	store64le(&buf[0], state->aadlen);
	store64le(&buf[sizeof(uint64_t)], state->ctlen);
	if (!lc_auth_update(state->auth, buf, sizeof(buf)) ||
	    !lc_auth_final(state->auth, ctag, &ctaglen))
		return 0;
	if (!lc_ct_cmp(ctag, tag, LC_POLY1305_TAGLEN))
		return 0;

	return lc_cipher_decrypt_final(state->cipher, out, outlen);
}

static int
chacha20_poly1305_open(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *tag, size_t taglen, const uint8_t *aad, size_t aadlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_poly1305_state	state;
	size_t				olen;

	*outlen = 0;
	/* inlen and aadlen are capped by design. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	if (!chacha20_poly1305_anycrypt_init(&state, initparams, AEAD_OPEN))
		return 0;
	if (!c20_xc20_poly1305_anycrypt_update(&state, out, &olen, aad, aadlen,
	    in, inlen, AEAD_OPEN))
		return 0;
	*outlen = olen;
	if (!c20_xc20_poly1305_open_final(&state, out + olen, &olen, tag,
	    taglen))
		return 0;
	*outlen += olen;

	return 1;
}

static int
xchacha20_poly1305_open(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *tag, size_t taglen, const uint8_t *aad, size_t aadlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_poly1305_state	state;
	size_t				olen;

	*outlen = 0;
	/* inlen and aadlen are capped by design. */
	if (inlen > UINT64_MAX || aadlen > UINT64_MAX)
		return 0;
	/* Counter 0 is used for deriving Poly1305 key. */
	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX - 1)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	if (!xchacha20_poly1305_anycrypt_init(&state, initparams, AEAD_OPEN))
		return 0;
	if (!c20_xc20_poly1305_anycrypt_update(&state, out, &olen, aad, aadlen,
	    in, inlen, AEAD_OPEN))
		return 0;
	*outlen = olen;
	if (!c20_xc20_poly1305_open_final(&state, out + olen, &olen, tag,
	    taglen))
		return 0;
	*outlen += olen;

	return 1;
}


const struct lc_aead_impl *
lc_aead_impl_chacha20_poly1305(void)
{
	static struct lc_aead_impl	chacha20_poly1305_impl = {
		.seal_init = &chacha20_poly1305_seal_init,
		.seal_update = &c20_xc20_poly1305_seal_update,
		.seal_final = &c20_xc20_poly1305_seal_final,
		.seal = &chacha20_poly1305_seal,

		.open_init = &chacha20_poly1305_open_init,
		.open_update = &c20_xc20_poly1305_open_update,
		.open_final = &c20_xc20_poly1305_open_final,
		.open = &chacha20_poly1305_open,

		.argsz = sizeof(struct chacha20_poly1305_state),
		.blocklen = LC_CHACHA20_BLOCKLEN,
	};

	return &chacha20_poly1305_impl;
}

const struct lc_aead_impl *
lc_aead_impl_xchacha20_poly1305(void)
{
	static struct lc_aead_impl	xchacha20_poly1305_impl = {
		.seal_init = &xchacha20_poly1305_seal_init,
		.seal_update = &c20_xc20_poly1305_seal_update,
		.seal_final = &c20_xc20_poly1305_seal_final,
		.seal = &xchacha20_poly1305_seal,

		.open_init = &xchacha20_poly1305_open_init,
		.open_update = &c20_xc20_poly1305_open_update,
		.open_final = &c20_xc20_poly1305_open_final,
		.open = &xchacha20_poly1305_open,

		.argsz = sizeof(struct chacha20_poly1305_state),
		.blocklen = LC_CHACHA20_BLOCKLEN,
	};

	return &xchacha20_poly1305_impl;
}
