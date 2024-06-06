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
#include <err.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lilcrypto.h"


#define nelems(_a)	(sizeof((_a)) / sizeof((_a)[0]))


static inline uint8_t
hex2num(char s)
{
	return s >= 'A' ? 10 + (s >= 'a' ? s - 'a' : s - 'A') : s - '0';
}

static int
hexparse(const char *s, uint8_t *out, size_t *outlen)
{
	size_t	l;

	l = strlen(s);
	if (l % 2 != 0)
		return 0;

	if (out == NULL) {
		*outlen = l / 2;
		return 1;
	}

	*outlen = 0;
	while (*s != '\0') {
		if (!isxdigit(s[0]) || !isxdigit(s[1]))
			return 0;
		*out++ = (hex2num(s[0]) << 4) | hex2num(s[1]);
		(*outlen)++;
		s += 2;
	}

	return 1;
}

struct kwimpl {
	const char			*kw;
	const struct lc_auth_impl	*(*impl)(void);
};

static int
kwimpl_cmp(const void *k0, const void *h0)
{
	const struct kwimpl	*h = h0;
	const char		*k = k0;

	return strcmp(k, h->kw);
}

static const struct lc_auth_impl *
kw2impl(const char *s)
{
	/* Needs to be sorted. */
	static const struct kwimpl	tbl[] = {
		{ "HMACSHA384", &lc_auth_impl_hmac_sha384 },
		{ "HMACSHA512", &lc_auth_impl_hmac_sha512 },
	};
	struct kwimpl	*match;

	match = bsearch(s, tbl, nelems(tbl), sizeof(struct kwimpl),
	    &kwimpl_cmp);

	return match != NULL ? match->impl() : NULL;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: %s [options]\n", getprogname());
	exit(1);
}

int
main(int argc, char *argv[])
{
	const struct lc_auth_impl	*impl;
	struct lc_auth_ctx		*ctx;
	uint8_t		*key, *msg, *tag, *buf;
	const char	*errstr;
	size_t		 keylen, msglen, taglen;
	size_t		 keylenarg, taglenarg;
	size_t		 l, olen;
	int		 Kflag, kflag, mflag, Tflag, tflag;
	int		 ch, verbose;

	if (argc < 2)
		usage();

	impl = kw2impl(argv[1]);
	if (impl == NULL)
		errx(1, "unsupported algorithm: %s", argv[1]);

	optind = 2;
	Kflag = kflag = mflag = Tflag = tflag = 0;
	verbose = 0;
	while ((ch = getopt(argc, argv, "K:k:m:T:t:v")) != -1) {
		switch (ch) {
		case 'K':
			Kflag = 1;
			keylenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "keylen is %s: %s", errstr, optarg);
			if (keylenarg % 8 != 0)
				errx(1, "unsupport K value: %zu", keylenarg);
			keylenarg /= 8;
			break;
		case 'k':
			kflag = 1;
			(void)hexparse(optarg, NULL, &keylen);
			if (keylen != 0) {
				key = malloc(keylen);
				if (key == NULL)
					err(1, "out of memory");
			} else
				key = NULL;
			if (!hexparse(optarg, key, &l) || l != keylen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'm':
			mflag = 1;
			(void)hexparse(optarg, NULL, &msglen);
			if (msglen != 0) {
				msg = malloc(msglen);
				if (msg == NULL)
					err(1, "out of memory");
			} else
				msg = NULL;
			if (!hexparse(optarg, msg, &l) || l != msglen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'T':
			Tflag = 1;
			taglenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "taglen is %s: %s", errstr, optarg);
			taglenarg /= 8;
			break;
		case 't':
			tflag = 1;
			(void)hexparse(optarg, NULL, &taglen);
			if (taglen != 0) {
				tag = malloc(taglen);
				if (tag == NULL)
					err(1, "out of memory");
			} else
				tag = NULL;
			if (!hexparse(optarg, tag, &l) || l != taglen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (!(Kflag && kflag && mflag && Tflag && tflag))
		errx(1, "missing required arguments");

	ctx = lc_auth_ctx_new(impl);
	if (ctx == NULL)
		errx(1, "can't allocate ctx");
	if (!lc_auth_init(ctx, key, keylenarg) ||
	    !lc_auth_update(ctx, msg, msglen) ||
	    !lc_auth_final(ctx, NULL, &olen)) {
		puts("invalid");
		return 1;
	}

	buf = malloc(olen);
	if (buf == NULL)
		err(1, "out of memory");

	if (!lc_auth_final(ctx, buf, &olen)) {
		puts("invalid");
		return 1;
	}

	/*
	 * Tests include truncated output. Skip checking olen as it'll always
	 * be the full-length hash.
	 */
	if (taglen != taglenarg ||
	    !lc_ct_cmp(buf, tag, taglen)) {
		if (verbose) {
			fprintf(stderr, "tag (%zu, %zu, %zu)\n", taglen,
			    taglenarg, olen);
			lc_hexdump_fp(stderr, tag, taglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, buf, olen);
			fprintf(stderr, "\n");
		}
		puts("invalid");
		return 1;
	}

	free(buf);
	lc_auth_ctx_free(ctx);

	puts("valid");
	return 0;
}
