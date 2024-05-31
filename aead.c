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


int
lc_aead_seal(const struct lc_aead_impl *impl, const uint8_t *key,
    size_t keylen, const uint8_t *iv, size_t ivlen, uint8_t *out,
    size_t *outlen, const uint8_t *aad, size_t aadlen, const uint8_t *in,
    size_t inlen)
{
	return impl->seal(key, keylen, iv, ivlen, out, outlen, aad, aadlen, in,
	    inlen);
}

int
lc_aead_open(const struct lc_aead_impl *impl, const uint8_t *key,
    size_t keylen, const uint8_t *iv, size_t ivlen, uint8_t *out,
    size_t *outlen, const uint8_t *aad, size_t aadlen, const uint8_t *in,
    size_t inlen)
{
	return impl->open(key, keylen, iv, ivlen, out, outlen, aad, aadlen, in,
	    inlen);
}
