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


#define CHACHA20_BLOCKLEN_WORDS	(LC_CHACHA20_BLOCKLEN / sizeof(uint32_t))
#define CHACHA20_CTRMAX		4294967295	/* 2^32 - 1 */
#define CHACHA20_KEY_WORDS	(LC_CHACHA20_KEYLEN / sizeof(uint32_t))
#define CHACHA20_NONCE_WORDS	4
#define CHACHA20_ROUNDS		10


struct chacha20_ctx {
	uint32_t	s[CHACHA20_BLOCKLEN_WORDS];
	uint32_t	k[CHACHA20_KEY_WORDS];
	uint32_t	n[CHACHA20_NONCE_WORDS];
	size_t		mlen;
	uint8_t		m[LC_CHACHA20_BLOCKLEN];
};


void	chacha20_block(struct chacha20_ctx *);
void	hchacha20_block(struct chacha20_ctx *);
