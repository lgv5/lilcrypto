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

#include <stddef.h>
#include <stdint.h>

#include "impl_sha256.h"
#include "util.h"


static const uint32_t K[SHA256_ROUNDS] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define CH(x, y, z)	((x & y) ^ (~x & z))
#define MAJ(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)	(rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22))
#define BSIG1(x)	(rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25))
#define SSIG0(x)	(rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3))
#define SSIG1(x)	(rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10))

void
sha256_block(struct sha256_ctx *ctx)
{
	uint32_t	m[SHA256_BLOCKLEN_WORDS], W[SHA256_ROUNDS];
	uint32_t	a, b, c, d, e, f, g, h, T1, T2;
	size_t		i;

	for (i = 0; i < SHA256_BLOCKLEN_WORDS; i++)
		W[i] = m[i] = load32be(&ctx->m[i * 4]);
	for (; i < SHA256_ROUNDS; i++)
		W[i] = SSIG1(W[i - 2]) + W[i - 7] + SSIG0(W[i - 15]) +
		    W[i - 16];

	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;
	f = ctx->h5;
	g = ctx->h6;
	h = ctx->h7;

	for (i = 0; i < SHA256_ROUNDS; i++) {
		T1 = h + BSIG1(e) + CH(e, f, g) + K[i] + W[i];
		T2 = BSIG0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	ctx->h5 += f;
	ctx->h6 += g;
	ctx->h7 += h;
}
