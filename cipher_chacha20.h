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


int	chacha20_common_init_from(void *, const uint8_t *, size_t,
	    const uint8_t *, size_t, uint32_t);
int	chacha20_common_init(void *, const uint8_t *, size_t, const uint8_t *,
	    size_t);
int	xchacha20_common_init_from(void *, const uint8_t *, size_t,
	    const uint8_t *, size_t, uint64_t);
int	xchacha20_common_init(void *, const uint8_t *, size_t, const uint8_t *,
	    size_t);
int	chacha20_common_update(void *, uint8_t *, size_t *, const uint8_t *,
	    size_t);
int	chacha20_common_final(void *, uint8_t *, size_t *);
int	chacha20_common(uint8_t *, size_t *, const uint8_t *, size_t,
	    const uint8_t *, size_t, const uint8_t *, size_t);
