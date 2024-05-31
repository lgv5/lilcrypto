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

#include "lilcrypto.h"


#define POLY1305_CHUNK		16
#define POLY1305_TAGLEN_WORDS	(LC_POLY1305_TAGLEN / sizeof(uint32_t))


struct poly1305_ctx {
	uint32_t	h0, h1, h2, h3, h4;
	uint32_t	r0, r1, r2, r3, r4;
	uint32_t	x1, x2, x3, x4;
	uint32_t	s0, s1, s2, s3;
	size_t		mlen;
	uint8_t		m[POLY1305_CHUNK];
};


void	poly1305_block(struct poly1305_ctx *, uint32_t);
void	poly1305_reduce(struct poly1305_ctx *,
	    uint32_t [POLY1305_TAGLEN_WORDS]);
