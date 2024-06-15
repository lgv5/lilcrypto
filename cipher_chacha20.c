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
#include <stdlib.h>

#include "lilcrypto.h"
#include "cipher.h"
#include "impl_chacha20.h"

#include "util.h"


/*
 * Implements ChaCha20 according to RFC 8439, XChaCha20 according to
 * draft-irtf-cfrg-xchacha-03.
 */


static int
chacha20_anycrypt_init(void *arg, void *initparams)
{
	struct lc_chacha20_params	*params = initparams;
	struct chacha20_state		*state = arg;
	size_t				 i;

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		state->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		state->k[i] = load32le(&params->key[i * 4]);
	state->n[0] = params->counter;
	for (i = 1; i < CHACHA20_NONCE_WORDS; i++)
		state->n[i] = load32le(&params->nonce[(i - 1) * 4]);
	state->mlen = 0;

	return 1;
}

static int
xchacha20_anycrypt_init(void *arg, void *initparams)
{
	struct lc_xchacha20_params	*params = initparams;
	struct chacha20_state		*state = arg;
	size_t				 i;

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		state->s[i] = 0;
	for (i = 0; i < CHACHA20_KEY_WORDS; i++)
		state->k[i] = load32le(&params->key[i * 4]);
	for (i = 0; i < CHACHA20_NONCE_WORDS; i++)
		state->n[i] = load32le(&params->nonce[i * 4]);
	state->mlen = 0;

	hchacha20_block(state);

	state->k[0] = state->s[0];
	state->k[1] = state->s[1];
	state->k[2] = state->s[2];
	state->k[3] = state->s[3];
	state->k[4] = state->s[12];
	state->k[5] = state->s[13];
	state->k[6] = state->s[14];
	state->k[7] = state->s[15];
	state->n[0] = params->counter;
	state->n[1] = 0;
	state->n[2] = load32le(&params->nonce[16]);
	state->n[3] = load32le(&params->nonce[20]);

	return 1;
}

static int
chacha20_anycrypt_update(void *arg, uint8_t *out, size_t *outlen,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_state	*state = arg;
	size_t			 i, blocks;
	uint32_t		 h;

	*outlen = 0;
	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) - state->mlen)
		return 0;
	blocks = (inlen + state->mlen + LC_CHACHA20_BLOCKLEN - 1) /
	    LC_CHACHA20_BLOCKLEN;
	if (blocks + state->n[0] > CHACHA20_CTRMAX)
		return 0;

	*outlen = state->mlen + inlen -
	    ((state->mlen + inlen) % LC_CHACHA20_BLOCKLEN);
	if (out == NULL)
		return 1;

	for (i = 0; i + state->mlen < LC_CHACHA20_BLOCKLEN && i < inlen; i++)
		state->m[i + state->mlen] = in[i];
	state->mlen += i;
	in += i;
	inlen -= i;

	if (state->mlen == LC_CHACHA20_BLOCKLEN) {
		chacha20_block(state);
		state->n[0]++;

		for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++) {
			h = load32le(&state->m[i * 4]);
			h ^= state->s[i];
			store32le(&out[i * 4], h);
		}
		out += LC_CHACHA20_BLOCKLEN;
		state->mlen = 0;
	}

	if (inlen == 0)
		return 1;

	while (inlen >= LC_CHACHA20_BLOCKLEN) {
		chacha20_block(state);
		state->n[0]++;

		for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++) {
			h = load32le(&in[i * 4]);
			h ^= state->s[i];
			store32le(&out[i * 4], h);
		}
		out += LC_CHACHA20_BLOCKLEN;
		in += LC_CHACHA20_BLOCKLEN;
		inlen -= LC_CHACHA20_BLOCKLEN;
	}

	for (i = 0; i < inlen; i++)
		state->m[i] = in[i];
	state->mlen = inlen;

	return 1;
}

static int
chacha20_anycrypt_final(void *arg, uint8_t *out, size_t *outlen)
{
	struct chacha20_state	*state = arg;
	size_t			 i, off;
	uint32_t		 h;
	uint8_t			 s[4];

	*outlen = state->mlen;
	if (out == NULL)
		return 1;

	if (state->mlen > 0)
		chacha20_block(state);

	for (i = 0; i < state->mlen / 4; i++) {
		h = load32le(&state->m[i * 4]);
		h ^= state->s[i];
		store32le(&out[i * 4], h);
	}
	off = i * 4;
	state->mlen -= off;
	out += off;

	store32le(&s[0], state->s[i]);
	for (i = 0; i < state->mlen; i++)
		out[i] = state->m[i + off] ^ s[i];

	lc_scrub(state, sizeof(*state));

	return 1;
}

static int
chacha20_anycrypt(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_state	state;
	size_t			l0, l1;
	int			rc;

	*outlen = 0;

	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	rc = chacha20_anycrypt_init(&state, initparams) &&
	    chacha20_anycrypt_update(&state, out, &l0, in, inlen) &&
	    chacha20_anycrypt_final(&state, out + l0, &l1);

	if (rc)
		*outlen = l0 + l1;

	return rc;
}

static int
xchacha20_anycrypt(uint8_t *out, size_t *outlen, void *initparams,
    const uint8_t *in, size_t inlen)
{
	struct chacha20_state	state;
	size_t			l0, l1;
	int			rc;

	*outlen = 0;

	if (inlen > SIZE_MAX - (LC_CHACHA20_BLOCKLEN - 1) ||
	    (inlen + LC_CHACHA20_BLOCKLEN - 1) / LC_CHACHA20_BLOCKLEN >
	    CHACHA20_CTRMAX)
		return 0;

	if (out == NULL) {
		*outlen = inlen;
		return 1;
	}

	rc = xchacha20_anycrypt_init(&state, initparams) &&
	    chacha20_anycrypt_update(&state, out, &l0, in, inlen) &&
	    chacha20_anycrypt_final(&state, out + l0, &l1);

	if (rc)
		*outlen = l0 + l1;

	return rc;
}


static struct lc_cipher_impl	chacha20_impl = {
	.encrypt_init = &chacha20_anycrypt_init,
	.encrypt_update = &chacha20_anycrypt_update,
	.encrypt_final = &chacha20_anycrypt_final,
	.encrypt = &chacha20_anycrypt,

	.decrypt_init = &chacha20_anycrypt_init,
	.decrypt_update = &chacha20_anycrypt_update,
	.decrypt_final = &chacha20_anycrypt_final,
	.decrypt = &chacha20_anycrypt,

	.argsz = sizeof(struct chacha20_state),
	.blocklen = LC_CHACHA20_BLOCKLEN,
};

static struct lc_cipher_impl	xchacha20_impl = {
	.encrypt_init = &xchacha20_anycrypt_init,
	.encrypt_update = &chacha20_anycrypt_update,
	.encrypt_final = &chacha20_anycrypt_final,
	.encrypt = &xchacha20_anycrypt,

	.decrypt_init = &xchacha20_anycrypt_init,
	.decrypt_update = &chacha20_anycrypt_update,
	.decrypt_final = &chacha20_anycrypt_final,
	.decrypt = &xchacha20_anycrypt,

 	.argsz = sizeof(struct chacha20_state),
	.blocklen = LC_XCHACHA20_BLOCKLEN,
};

const struct lc_cipher_impl *
lc_cipher_impl_chacha20(void)
{
	return &chacha20_impl;
}

const struct lc_cipher_impl *
lc_cipher_impl_xchacha20(void)
{
	return &xchacha20_impl;
}
