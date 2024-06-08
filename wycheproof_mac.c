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


struct testcase {
	uint8_t	*key;
	size_t	 keylen;
	size_t	 keylenarg;
	uint8_t	*tag;
	size_t	 taglen;
	size_t	 taglenarg;
	uint8_t	*msg;
	size_t	 msglen;
};

struct kwrunner {
	const char	 *kw;
	int		(*runner)(const struct testcase *, int);
};


static int	hmac_sha2_runner(const struct lc_auth_impl *,
		    const struct testcase *, int);
static int	hmac_sha224_runner(const struct testcase *, int);
static int	hmac_sha256_runner(const struct testcase *, int);
static int	hmac_sha384_runner(const struct testcase *, int);
static int	hmac_sha512_runner(const struct testcase *, int);


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

static int
kwrunner_cmp(const void *k0, const void *h0)
{
	const struct kwrunner	*h = h0;
	const char		*k = k0;

	return strcmp(k, h->kw);
}

static int
(*kw2runner(const char *s))(const struct testcase *, int)
{
	/* Needs to be sorted. */
	static const struct kwrunner	 tbl[] = {
		{ "HMACSHA224", &hmac_sha224_runner },
		{ "HMACSHA256", &hmac_sha256_runner },
		{ "HMACSHA384", &hmac_sha384_runner },
		{ "HMACSHA512", &hmac_sha512_runner },
	};
	struct kwrunner			*match;

	match = bsearch(s, tbl, nelems(tbl), sizeof(struct kwrunner),
	    &kwrunner_cmp);

	return match != NULL ? match->runner : NULL;
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
	int		(*runner)(const struct testcase *, int);
	const char	 *errstr;
	struct testcase	  c;
	size_t		  l;
	int		  Kflag, kflag, mflag, Tflag, tflag;
	int		  ch, verbose;

	if (argc < 2)
		usage();

	runner = kw2runner(argv[1]);
	if (runner == NULL)
		errx(1, "unsupported algorithm: %s", argv[1]);

	optind = 2;
	Kflag = kflag = mflag = Tflag = tflag = 0;
	verbose = 0;
	while ((ch = getopt(argc, argv, "K:k:m:T:t:v")) != -1) {
		switch (ch) {
		case 'K':
			Kflag = 1;
			c.keylenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "keylen is %s: %s", errstr, optarg);
			if (c.keylenarg % 8 != 0)
				errx(1, "unsupport K value: %zu", c.keylenarg);
			c.keylenarg /= 8;
			break;
		case 'k':
			kflag = 1;
			(void)hexparse(optarg, NULL, &c.keylen);
			if (c.keylen != 0) {
				c.key = malloc(c.keylen);
				if (c.key == NULL)
					err(1, "out of memory");
			} else
				c.key = NULL;
			if (!hexparse(optarg, c.key, &l) || l != c.keylen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'm':
			mflag = 1;
			(void)hexparse(optarg, NULL, &c.msglen);
			if (c.msglen != 0) {
				c.msg = malloc(c.msglen);
				if (c.msg == NULL)
					err(1, "out of memory");
			} else
				c.msg = NULL;
			if (!hexparse(optarg, c.msg, &l) || l != c.msglen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'T':
			Tflag = 1;
			c.taglenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "taglen is %s: %s", errstr, optarg);
			c.taglenarg /= 8;
			break;
		case 't':
			tflag = 1;
			(void)hexparse(optarg, NULL, &c.taglen);
			if (c.taglen != 0) {
				c.tag = malloc(c.taglen);
				if (c.tag == NULL)
					err(1, "out of memory");
			} else
				c.tag = NULL;
			if (!hexparse(optarg, c.tag, &l) || l != c.taglen)
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

	if (runner(&c, verbose)) {
		puts("valid");
		return 0;
	} else {
		puts("invalid");
		return 0;
	}

	puts("valid");
	return 0;
}

static int
hmac_sha2_runner(const struct lc_auth_impl *impl, const struct testcase *c,
    int verbose)
{
	struct lc_hmac_params	 params;
	struct lc_auth_ctx	*ctx;
	uint8_t			*buf;
	size_t			 olen;

	if (c->keylen != c->keylenarg)
		return 0;
	params.key = c->key;
	params.keylen = c->keylen;

	ctx = lc_auth_ctx_new(impl);
	if (ctx == NULL)
		errx(1, "can't allocate ctx");

	if (!lc_auth_init(ctx, &params) ||
	    !lc_auth_update(ctx, c->msg, c->msglen) ||
	    !lc_auth_final(ctx, NULL, &olen))
		return 0;

	buf = malloc(olen);
	if (buf == NULL)
		err(1, "out of memory");

	if (!lc_auth_final(ctx, buf, &olen))
		return 0;

	/*
	 * Tests include truncated output. Skip checking olen as it'll always
	 * be the full-length hash.
	 */
	if (c->taglen != c->taglenarg ||
	    !lc_ct_cmp(buf, c->tag, c->taglen)) {
		if (verbose) {
			fprintf(stderr, "tag (%zu, %zu, %zu)\n", c->taglen,
			    c->taglenarg, olen);
			lc_hexdump_fp(stderr, c->tag, c->taglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, buf, olen);
			fprintf(stderr, "\n");
		}
		return 0;
	}

	free(buf);
	lc_auth_ctx_free(ctx);

	return 1;
}

static int
hmac_sha224_runner(const struct testcase *c, int verbose)
{
	return hmac_sha2_runner(lc_auth_impl_hmac_sha224(), c, verbose);
}

static int
hmac_sha256_runner(const struct testcase *c, int verbose)
{
	return hmac_sha2_runner(lc_auth_impl_hmac_sha256(), c, verbose);
}

static int
hmac_sha384_runner(const struct testcase *c, int verbose)
{
	return hmac_sha2_runner(lc_auth_impl_hmac_sha384(), c, verbose);
}

static int
hmac_sha512_runner(const struct testcase *c, int verbose)
{
	return hmac_sha2_runner(lc_auth_impl_hmac_sha512(), c, verbose);
}
