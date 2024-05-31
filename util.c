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

#include <ctype.h>
#include <string.h>

#include "lilcrypto.h"


#define HEXDUMP_BUFSZ	128


static size_t
hexdump_line(char *buf, const uint8_t *blob, size_t len, size_t off, int pad)
{
	/*
	 * Format is
	 * - 16-char hex offset (at most) 
	 * - 2 spaces
	 * - 2-char hex byte and a space (16 times)
	 * - 2 spaces
	 * - 2 pipe chars + 16 renders of the blobs
	 *
	 * That accounts for, at most, 16 + 2 + 16 * 3 + 2 + 18. Adding an
	 * extra byte for the NUL ending byte, that amounts for 87.
	 *
	 * Callers MUST provide a buffer at least HEXDUMP_BUFSZ long in buf0.
	 */

	char	*bufp;
	size_t	 i, buflen;
	int	 w;

	bufp = buf;
	buflen = HEXDUMP_BUFSZ;

	if (len == 0)
		(void)snprintf(bufp, buflen, "%0*zx\n", pad, off);
	else {
		w = snprintf(bufp, buflen, "%0*zx  ", pad, off);
		bufp += w;
		buflen -= w;
		for (i = 0; i < len && i < 8; i++) {
			w = snprintf(bufp, buflen, "%02x ", blob[i]);
			bufp += w;
			buflen -= w;
		}
		if (i < 8) {
			memset(bufp, ' ', 3 * (16 - i));
			bufp += 3 * (16 - i);
			buflen -= 3 * (16 - i);
		}
		for (; i < len && i < 16; i++) {
			w = snprintf(bufp, buflen, " %02x", blob[i]);
			bufp += w;
			buflen -= w;
		}
		if (i < 16) {
			memset(bufp, ' ', 3 * (16 - i));
			bufp += 3 * (16 - i);
			buflen -= 3 * (16 - i);
		}
		w = snprintf(bufp, buflen, "  |");
		bufp += w;
		buflen -= w;
		for (i = 0; i < len && i < 16; i++) {
			w = snprintf(bufp, buflen, "%c",
			    isprint(blob[i]) ? blob[i] : '.');
			bufp += w;
			buflen -= w;
		}
		(void)snprintf(bufp, buflen, "|\n");
	}

	return len < 16 ? len : 16;
}

int
lc_hexdump_fp(FILE *fp, const void *blob, size_t len)
{
	const uint8_t	*p = blob;
	char		 buf[HEXDUMP_BUFSZ];
	size_t		 l, off;
	int		 pad;

	for (pad = 1; len > (1 << (8 * pad)); pad++)
		continue;
	pad *= 2;

	off = 0;
	while (len > 0) {
		l = hexdump_line(buf, p, len, off, pad);
		if (fputs(buf, fp) == EOF)
			return 0;
		off += l;
		len -= l;
	}
	(void)hexdump_line(buf, p, len, off, pad);
	if (fputs(buf, fp) == EOF)
		return 0;

	return 1;
}

void
lc_scrub(void *b, size_t len)
{
	explicit_bzero(b, len);
}
