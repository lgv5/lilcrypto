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

#include "impl_poly1305.h"
#include "util.h"


/*
 * Poly1305 implementation.
 *
 * Poly1305 originally designed by Daniel J. Bernstein, "The Poly1305-AES
 * message-authentication code", https://cr.yp.to/mac/poly1305-20050329.pdf .
 *
 * This implementation is written from scratch, but consulting poly1305-donna
 * by Andrew Moon, https://github.com/floodyberry/poly1305-donna, released
 * under MIT license. Similarities are to be expected.
 */

/*
 * Copyright 2011-2016 Andrew Moon <liquidsun@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/*
 * To ease reduction modulo p = 2^130 - 5, work in base 2^130, as 2^130 = 5 mod
 * p, allowing for easier operations. 2^130 splits evenly into 5 limbs of 26
 * bits.
 *
 * Addition is performed limb-wise:
 *
 * h   =    h4    h3    h2    h1    h0
 * c   =    c4    c3    c2    c1    c0
 * -----------------------------------
 * h+c = h4+c4 h3+c3 h2+c2 h1+c1 h0+c0
 *
 * Carry won't be propagated at this step.
 *
 * Considering h = h + c, multiplication is performed as school multiplication
 * / long multiplication:
 *
 * h   =                            h4    h3    h2    h1    h0
 * r   =                            r4    r3    r2    r1    r0
 * -----------------------------------------------------------
 *                               h4*r0 h3*r0 h2*r0 h1*r0 h0*r0
 *                         h4*r1 h3*r1 h2*r1 h1*r1 h0*r1
 *                   h4*r2 h3*r2 h2*r2 h1*r2 h0*r2
 *             h4*r3 h3*r3 h2*r3 h1*r3 h0*r3
 *       h4*r4 h3*r4 h2*r4 h1*r4 h0*r4
 *
 * Each hn*rn fits in 53 bits. Carry won't be propagated at this step. Partial
 * reduction modulo p starts here:
 *
 *                             2^130
 * h   =                         |    h4    h3    h2    h1    h0
 * r   =                         |    r4    r3    r2    r1    r0
 * ------------------------------|------------------------------
 *                               | h4*r0 h3*r0 h2*r0 h1*r0 h0*r0
 *                         h4*r1 | h3*r1 h2*r1 h1*r1 h0*r1
 *                   h4*r2 h3*r2 | h2*r2 h1*r2 h0*r2
 *             h4*r3 h3*r3 h2*r3 | h1*r3 h0*r3
 *       h4*r4 h3*r4 h2*r4 h1*r4 | h0*r4
 *
 *       2^130
 * h   =   |    h4      h3      h2      h1      h0
 * r   =   |    r4      r3      r2      r1      r0
 * --------|--------------------------------------
 *         | h4*r0   h3*r0   h2*r0   h1*r0   h0*r0
 *         | h3*r1   h2*r1   h1*r1   h0*r1 5*h4*r1
 *         | h2*r2   h1*r2   h0*r2 5*h4*r2 5*h3*r2
 *         | h1*r3   h0*r3 5*h4*r3 5*h3*r3 5*h2*r3
 *         | h0*r4 5*h4*r4 5*h3*r4 5*h2*r4 5*h1*r4
 * --------|--------------------------------------
 * h*r =   |    t4      t3      t2      t1      t0
 *
 * All the carry propagations are performed after this step. h0 is set t0 low
 * 26 bits of t0; h1 thru h4 are set to tn + (tn-1 >> 26) to propagate the
 * carry. t4 might overflow so it needs to be backpropagated to h0 and h1. h1
 * won't carry into h2: given the highest possible h, c, and r,
 *
 * h =  0xffffffffffffffffffffffffffffffff
 * c = 0x1ffffffffffffffffffffffffffffffff
 * r =  0x0ffffffc0ffffffc0ffffffc0fffffff
 *
 * the limbs and t4 before h0 and h1 second propagation are
 *
 * h4 = 0x257ffff
 * h3 = 0x3a95fff
 * h2 = 0x3fea57f
 * h1 = 0x3fffa70
 * h0 = 0x2000002
 * t4 = 0x77fffffa57ffff
 *
 * which becomes
 *
 * h4 = 0x257ffff
 * h3 = 0x3a95fff
 * h2 = 0x3fea57f
 * h1 = 0x3fffa95
 * h0 = 0x3fffff8
 *
 * To perform the final reduction modulo p, observe that each hn is bound by
 * 2^26, which means that h is bound by 2^130. Define minusp = 2^136 - p.
 * - If h < p, minusp + h < 2^136.
 * - If h >= p, then h = p + k with k in {0,1,2,3,4}, and minusp + h =
 *   2^136 - p + p + k = 2^136 + k >= 2^136, and both minusp + h = k mod 2^136
 *   and h = k mod p for all possible values of k.
 *
 * To avoid information leaking via side channels, define g = minusp + h, and
 * select g if bit 136 is set, h otherwise. In particular, define a 32-bit
 * mask = ~(g >> 136) + 1.
 * - If bit 136 of g is 1, mask = ~1 + 1 = 0xffffffff.
 * - If bit 136 of g is 0, mask = ~0 + 1 = 0.
 * Then perform (h & ~mask) | (g & mask).
 */

void
poly1305_block(struct poly1305_ctx *ctx, uint32_t hibit)
{
	uint64_t h0, h1, h2, h3, h4, t0, t1, t2, t3, t4;
	uint32_t r0, r1, r2, r3, r4, x1, x2, x3, x4;

	h0 = ctx->h0;
	h1 = ctx->h1;
	h2 = ctx->h2;
	h3 = ctx->h3;
	h4 = ctx->h4;
	r0 = ctx->r0;
	r1 = ctx->r1;
	r2 = ctx->r2;
	r3 = ctx->r3;
	r4 = ctx->r4;
	x1 = ctx->x1;
	x2 = ctx->x2;
	x3 = ctx->x3;
	x4 = ctx->x4;

	t0 = load32le(&ctx->m[0]);
	t1 = load32le(&ctx->m[4]);
	t2 = load32le(&ctx->m[8]);
	t3 = load32le(&ctx->m[12]);
	t4 = hibit;

	h0 += t0 & 0x3ffffff;
	h1 += ((t1 << 6) | (t0 >> 26)) & 0x3ffffff;
	h2 += ((t2 << 12) | (t1 >> 20)) & 0x3ffffff;
	h3 += ((t3 << 18) | (t2 >> 14)) & 0x3ffffff;
	h4 += (t4 << 24) | (t3 >> 8);

	t0 = h0 * r0 + h4 * x1 + h3 * x2 + h2 * x3 + h1 * x4;
	t1 = h1 * r0 + h0 * r1 + h4 * x2 + h3 * x3 + h2 * x4;
	t2 = h2 * r0 + h1 * r1 + h0 * r2 + h4 * x3 + h3 * x4;
	t3 = h3 * r0 + h2 * r1 + h1 * r2 + h0 * r3 + h4 * x4;
	t4 = h4 * r0 + h3 * r1 + h2 * r2 + h1 * r3 + h0 * r4;

	h0 = t0 & 0x3ffffff;
	t1 += t0 >> 26;
	h1 = t1 & 0x3ffffff;
	t2 += t1 >> 26;
	h2 = t2 & 0x3ffffff;
	t3 += t2 >> 26;
	h3 = t3 & 0x3ffffff;
	t4 += t3 >> 26;
	h4 = t4 & 0x3ffffff;

	h0 += 5 * (t4 >> 26);
	h1 += h0 >> 26;
	h0 &= 0x3ffffff;

	ctx->h0 = h0;
	ctx->h1 = h1;
	ctx->h2 = h2;
	ctx->h3 = h3;
	ctx->h4 = h4;
}

void
poly1305_reduce(struct poly1305_ctx *ctx, uint32_t a[POLY1305_TAGLEN_WORDS])
{
	uint64_t t0, t1, t2, t3, t4, g0, g1, g2, g3, g4;
	uint32_t mask;

	t0 = (ctx->h0 | (ctx->h1 << 26)) & 0xffffffff;
	t1 = ((ctx->h1 >> 6) | (ctx->h2 << 20)) & 0xffffffff;
	t2 = ((ctx->h2 >> 12) | (ctx->h3 << 14)) & 0xffffffff;
	t3 = ((ctx->h3 >> 18) | (ctx->h4 << 8)) & 0xffffffff;
	t4 = ctx->h4 >> 24;

	g0 = t0 + 5;
	g1 = t1 + (g0 >> 32);
	g2 = t2 + (g1 >> 32);
	g3 = t3 + (g2 >> 32);
	g4 = t4 + (g3 >> 32) + 252;

	mask = ~(g4 >> 8) + 1;

	t0 = (t0 & ~mask) | (g0 & mask);
	t1 = (t1 & ~mask) | (g1 & mask);
	t2 = (t2 & ~mask) | (g2 & mask);
	t3 = (t3 & ~mask) | (g3 & mask);

	t0 += ctx->s0;
	t1 += ctx->s1 + (t0 >> 32);
	t2 += ctx->s2 + (t1 >> 32);
	t3 += ctx->s3 + (t2 >> 32);

	a[0] = t0 & 0xffffffff;
	a[1] = t1 & 0xffffffff;
	a[2] = t2 & 0xffffffff;
	a[3] = t3 & 0xffffffff;
}
