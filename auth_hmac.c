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

#include "internal.h"
#include "util.h"


#define HMAC_IPAD		UINT8_C(0x36)
#define HMAC_OPAD		UINT8_C(0x5c)


static int
hmac_init(void *arg, void *initparams)
{
	struct hmac_state	*state = arg;
	struct lc_hmac_params	*params = initparams;
	uint8_t			 ikeypad[HMAC_BLOCKLEN_MAX];
	size_t			 i, olen, blen, keylen;

	state->hash = params->hash;
	keylen = params->keylen;
	blen = params->hash->impl->blocklen;

	if (keylen > blen) {
		if (!lc_hash(state->hash->impl, state->key, &olen, params->key,
		    keylen))
			return 0;
		keylen = olen;
	} else
		for (i = 0; i < keylen; i++)
			state->key[i] = params->key[i];

	for (i = keylen; i < blen; i++)
		state->key[i] = 0;

	for (i = 0; i < blen; i++)
		ikeypad[i] = state->key[i] ^ HMAC_IPAD;

	return lc_hash_init(state->hash) &&
	    lc_hash_update(state->hash, ikeypad, blen);
}

static int
hmac_update(void *arg, const uint8_t *in, size_t inlen)
{
	struct hmac_state	*state = arg;

	return lc_hash_update(state->hash, in, inlen);
}

static int
hmac_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct lc_hash_ctx	*hash;
	struct hmac_state	*state = arg;
	uint8_t			 m[HMAC_BLOCKLEN_MAX],
				    okeypad[HMAC_BLOCKLEN_MAX];
	size_t			 i, olen, blen;
	int			 rc;

	if (out == NULL) {
		*outlen = state->hash->impl->hashlen;
		return 1;
	}

	*outlen = 0;
	blen = state->hash->impl->blocklen;

	for (i = 0; i < blen; i++)
		okeypad[i] = state->key[i] ^ HMAC_OPAD;

	rc = lc_hash_final(state->hash, m, &olen) &&
	    lc_hash_init(state->hash) &&
	    lc_hash_update(state->hash, okeypad, blen) &&
	    lc_hash_update(state->hash, m, olen) &&
	    lc_hash_final(state->hash, out, outlen);

	hash = state->hash;
	lc_scrub(state, sizeof(*state));
	state->hash = hash;

	return rc;
}

static int
hmac_auth(uint8_t *out, size_t *outlen, void *initparams, const uint8_t *in,
    size_t inlen)
{
	struct lc_hmac_params	*params = initparams;
	struct hmac_state	 state;

	if (out == NULL) {
		*outlen = params->hash->impl->hashlen;
		return 1;
	}

	return hmac_init(&state, initparams) &&
	    hmac_update(&state, in, inlen) &&
	    hmac_final(&state, out, outlen);
}


const struct lc_auth_impl *
lc_auth_impl_hmac(void)
{
	static struct lc_auth_impl	hmac_impl = {
		.init = &hmac_init,
		.update = &hmac_update,
		.final = &hmac_final,
		.auth = &hmac_auth,

		.argsz = sizeof(struct hmac_state),
		.blocklen = 0,
		.taglen = 0,
	};

	return &hmac_impl;
}
