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


struct lc_auth_impl {
	int	 (*init)(void *, void *);
	int	 (*update)(void *, const uint8_t *, size_t);
	int	 (*final)(void *, uint8_t *, size_t *);
	int	 (*auth)(uint8_t *, size_t *, void *, const uint8_t *, size_t);

	void	*(*ctx_new)(void);
	void	 (*ctx_free)(void *);

	size_t	   blocklen;
	size_t	   taglen;
};

struct lc_auth_ctx {
	const struct lc_auth_impl	*impl;
	void				*arg;
};
