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

#include <string.h>

#include "internal.h"


static int
hkdf_kdf(uint8_t *out, size_t *outlen, void *initparams, size_t len)
{
	struct lc_hkdf_params	*params = initparams;
	struct lc_hmac_params	 hmacparams;
	uint8_t			 prk[HMAC_HASHLEN_MAX];
	uint8_t			 t[HMAC_HASHLEN_MAX], tn[HMAC_HASHLEN_MAX];
	size_t			 hashlen, olen;
	uint8_t			 ctr;

	/* Only accept HMAC as auth_impl. */
	if (params->hmac == NULL ||
	    params->hmac->impl != lc_auth_impl_hmac())
		return 0;

	hashlen = params->hash->impl->hashlen;

	/* XXX *outlen = 0 ? */
	if (len > hashlen * 255)
		return 0;

	if (out == NULL) {
		*outlen = len;
		return 1;
	}
	*outlen = 0;

	hmacparams.hash = params->hash;
	if (params->saltlen == 0) {
		hmacparams.key = zerobuf;
		hmacparams.keylen = hashlen;
	} else {
		hmacparams.key = params->salt;
		hmacparams.keylen = params->saltlen;
	}

	if (!lc_auth(params->hmac->impl, prk, &olen, &hmacparams, params->ikm,
	    params->ikmlen))
		return 0;

	hmacparams.key = prk;
	hmacparams.keylen = olen;
	olen = 0;
	ctr = 1;
	while (len >= hashlen) {
		memcpy(t, tn, olen);
		if (!lc_auth_init(params->hmac, &hmacparams) ||
		    !lc_auth_update(params->hmac, t, olen) ||
		    !lc_auth_update(params->hmac, params->info,
		    params->infolen) ||
		    !lc_auth_update(params->hmac, &ctr, sizeof(ctr)) ||
		    !lc_auth_final(params->hmac, tn, &olen))
			return 0;
		ctr++;

		memcpy(out, tn, hashlen);
		*outlen += hashlen;
		out += hashlen;
		len -= hashlen;
	}

	memcpy(t, tn, olen);
	if (!lc_auth_init(params->hmac, &hmacparams) ||
	    !lc_auth_update(params->hmac, t, olen) ||
	    !lc_auth_update(params->hmac, params->info, params->infolen) ||
	    !lc_auth_update(params->hmac, &ctr, sizeof(ctr)) ||
	    !lc_auth_final(params->hmac, tn, &olen))
		return 0;

	memcpy(out, tn, len);
	*outlen += len;

	return 1;
}


const struct lc_kdf_impl *
lc_kdf_impl_hkdf(void)
{
	static struct lc_kdf_impl	hkdf_impl = {
		.kdf = &hkdf_kdf,
	};

	return &hkdf_impl;
}
