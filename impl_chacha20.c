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


/*
 * ChaCha20 implementation.
 *
 * ChaCha originally designed by Daniel J. Bernstein, "ChaCha, a variant of
 * Salsa20", https://cr.yp.to/chacha/chacha-20080128.pdf .
 */

/* "expand 32-byte k" */
#define SIGMA0	UINT32_C(0x61707865)
#define SIGMA1	UINT32_C(0x3320646e)
#define SIGMA2	UINT32_C(0x79622d32)
#define SIGMA3	UINT32_C(0x6b206574)

#define QUARTERROUND(a, b, c, d) do {			\
		a += b; d ^= a; d = rotl32(d, 16);	\
		c += d; b ^= c; b = rotl32(b, 12);	\
		a += b; d ^= a; d = rotl32(d, 8);	\
		c += d; b ^= c; b = rotl32(b, 7);	\
	} while (0)


void
chacha20_block(struct chacha20_state *state)
{
	uint32_t	x[CHACHA20_BLOCKLEN_WORDS];
	size_t		i;

	x[0] = SIGMA0;
	x[1] = SIGMA1;
	x[2] = SIGMA2;
	x[3] = SIGMA3;
	x[4] = state->k[0];
	x[5] = state->k[1];
	x[6] = state->k[2];
	x[7] = state->k[3];
	x[8] = state->k[4];
	x[9] = state->k[5];
	x[10] = state->k[6];
	x[11] = state->k[7];
	x[12] = state->n[0];
	x[13] = state->n[1];
	x[14] = state->n[2];
	x[15] = state->n[3];

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		state->s[i] = x[i];

	for (i = 0; i < CHACHA20_ROUNDS; i++) {
		QUARTERROUND(x[0], x[4], x[8], x[12]);
		QUARTERROUND(x[1], x[5], x[9], x[13]);
		QUARTERROUND(x[2], x[6], x[10], x[14]);
		QUARTERROUND(x[3], x[7], x[11], x[15]);

		QUARTERROUND(x[0], x[5], x[10], x[15]);
		QUARTERROUND(x[1], x[6], x[11], x[12]);
		QUARTERROUND(x[2], x[7], x[8], x[13]);
		QUARTERROUND(x[3], x[4], x[9], x[14]);
	}

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		state->s[i] += x[i];
}

void
hchacha20_block(struct chacha20_state *state)
{
	uint32_t	x[CHACHA20_BLOCKLEN_WORDS];
	size_t		i;

	x[0] = SIGMA0;
	x[1] = SIGMA1;
	x[2] = SIGMA2;
	x[3] = SIGMA3;
	x[4] = state->k[0];
	x[5] = state->k[1];
	x[6] = state->k[2];
	x[7] = state->k[3];
	x[8] = state->k[4];
	x[9] = state->k[5];
	x[10] = state->k[6];
	x[11] = state->k[7];
	x[12] = state->n[0];
	x[13] = state->n[1];
	x[14] = state->n[2];
	x[15] = state->n[3];

	for (i = 0; i < CHACHA20_ROUNDS; i++) {
		QUARTERROUND(x[0], x[4], x[8], x[12]);
		QUARTERROUND(x[1], x[5], x[9], x[13]);
		QUARTERROUND(x[2], x[6], x[10], x[14]);
		QUARTERROUND(x[3], x[7], x[11], x[15]);

		QUARTERROUND(x[0], x[5], x[10], x[15]);
		QUARTERROUND(x[1], x[6], x[11], x[12]);
		QUARTERROUND(x[2], x[7], x[8], x[13]);
		QUARTERROUND(x[3], x[4], x[9], x[14]);
	}

	for (i = 0; i < CHACHA20_BLOCKLEN_WORDS; i++)
		state->s[i] = x[i];
}
