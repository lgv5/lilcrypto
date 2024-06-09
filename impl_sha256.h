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


#define SHA256_BLOCKLEN		64
#define SHA256_BLOCKLEN_WORDS	(SHA256_BLOCKLEN / sizeof(uint32_t))
#define SHA256_ROUNDS		64


struct sha256_ctx {
	uint32_t	h0, h1, h2, h3, h4, h5, h6, h7;
	uint64_t	sz;
	size_t		mlen;
	uint8_t		m[SHA256_BLOCKLEN];
};


void	sha256_block(struct sha256_ctx *);
