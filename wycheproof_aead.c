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
	uint8_t	*iv;
	size_t	 ivlen;
	size_t	 ivlenarg;
	uint8_t	*tag;
	size_t	 taglen;
	size_t	 taglenarg;
	uint8_t	*aad;
	size_t	 aadlen;
	uint8_t	*msg;
	size_t	 msglen;
	uint8_t *ct;
	size_t	 ctlen;
};

struct kwrunner {
	const char	 *kw;
	int		(*runner)(const struct testcase *, int);
};


static int	aead_poly1305_runner(const struct lc_aead_impl *,
		    const struct testcase *, const void *, int);
static int	chacha20_poly1305_runner(const struct testcase *, int);
static int	xchacha20_poly1305_runner(const struct testcase *, int);


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
	static const struct kwrunner	 tbl[] = {
		{ "CHACHA20-POLY1305", &chacha20_poly1305_runner },
		{ "XCHACHA20-POLY1305", &xchacha20_poly1305_runner },
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
	int		  aflag, cflag, Iflag, iflag, Kflag, kflag, mflag,
			    Tflag, tflag;
	int		  ch, verbose;

	if (argc < 2)
		usage();

	runner = kw2runner(argv[1]);
	if (runner == NULL)
		errx(1, "unsupported algorithm: %s", argv[1]);

	optind = 2;
	aflag = cflag = Iflag = iflag = Kflag = kflag = mflag = Tflag = tflag =
	    0;
	verbose = 0;
	while ((ch = getopt(argc, argv, "a:c:I:i:K:k:m:T:t:v")) != -1) {
		switch (ch) {
		case 'a':
			aflag = 1;
			(void)hexparse(optarg, NULL, &c.aadlen);
			if (c.aadlen != 0) {
				c.aad = malloc(c.aadlen);
				if (c.aad == NULL)
					err(1, "out of memory");
			} else
				c.aad = NULL;
			if (!hexparse(optarg, c.aad, &l) || l != c.aadlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'c':
			cflag = 1;
			(void)hexparse(optarg, NULL, &c.ctlen);
			if (c.ctlen != 0) {
				c.ct = malloc(c.ctlen);
				if (c.ct == NULL)
					err(1, "out of memory");
			} else
				c.ct = NULL;
			if (!hexparse(optarg, c.ct, &l) || l != c.ctlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'I':
			Iflag = 1;
			c.ivlenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "ivlen is %s: %s", errstr, optarg);
			c.ivlenarg /= 8;
			break;
		case 'i':
			iflag = 1;
			(void)hexparse(optarg, NULL, &c.ivlen);
			if (c.ivlen != 0) {
				c.iv = malloc(c.ivlen);
				if (c.iv == NULL)
					err(1, "out of memory");
			} else
				c.iv = NULL;
			if (!hexparse(optarg, c.iv, &l) || l != c.ivlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
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

	if (!(aflag && cflag && Iflag && iflag && Kflag && kflag && mflag &&
	    Tflag && tflag))
		errx(1, "missing required arguments");

	if (runner(&c, verbose)) {
		puts("valid");
		return 0;
	} else {
		puts("invalid");
		return 0;
	}
}

static int
aead_poly1305_runner(const struct lc_aead_impl *impl, const struct testcase *c,
    const void *params, int verbose)
{
	uint8_t	*buf, *encout, *decout;
	size_t	 aeadlen, encoutlen, decoutlen;

	if (!lc_aead_seal(impl, NULL, &encoutlen, params, c->aad, c->aadlen,
	    c->msg, c->msglen))
		return 0;
	encout = malloc(encoutlen);
	if (encout == NULL)
		err(1, "out of memory");
	if (!lc_aead_seal(impl, encout, &encoutlen, params, c->aad, c->aadlen,
	    c->msg, c->msglen))
		return 0;

	if (c->ctlen != encoutlen - LC_POLY1305_TAGLEN ||
	    !lc_ct_cmp(encout, c->ct, c->ctlen)) {
		if (verbose) {
			fprintf(stderr, "ct (%zu, %zu)\n", c->ctlen,
			    encoutlen - LC_POLY1305_TAGLEN);
			lc_hexdump_fp(stderr, c->msg, c->msglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, c->ct, c->ctlen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, encout,
			    encoutlen - LC_POLY1305_TAGLEN);
			fprintf(stderr, "\n");
		}
		return 0;
	}
	if (c->taglenarg != LC_POLY1305_TAGLEN ||
	    !lc_ct_cmp(encout + c->ctlen, c->tag, LC_POLY1305_TAGLEN)) {
		if (verbose) {
			fprintf(stderr, "tag (%zu, %zu)\n", c->taglenarg,
			    (size_t)LC_POLY1305_TAGLEN);
			lc_hexdump_fp(stderr, c->tag, c->taglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, encout + c->ctlen,
			    LC_POLY1305_TAGLEN);
			fprintf(stderr, "\n");
		}
		return 0;
	}

	/* Decryption. */

	aeadlen = c->msglen + c->taglen;
	buf = malloc(aeadlen);
	if (buf == NULL)
		err(1, "out of memory");
	memcpy(buf, c->ct, c->ctlen);
	memcpy(buf + c->ctlen, c->tag, c->taglen);

	if (!lc_aead_open(impl, NULL, &decoutlen, params, c->aad, c->aadlen,
	    buf, aeadlen))
		return 0;
	decout = malloc(decoutlen);
	if (decout == NULL)
		err(1, "out of memory");
	if (!lc_aead_open(impl, decout, &decoutlen, params, c->aad, c->aadlen,
	    buf, aeadlen))
		return 0;

	if (c->msglen != decoutlen || !lc_ct_cmp(decout, c->msg, c->msglen)) {
		if (verbose) {
			fprintf(stderr, "ct (%zu, %zu)\n", c->msglen,
			    decoutlen);
			lc_hexdump_fp(stderr, c->msg, c->msglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, c->ct, c->ctlen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, decout, decoutlen);
			fprintf(stderr, "\n");
		}
		return 0;
	}
	/* Tag isn't checked, as it's already validated by lc_aead_open. */

	return 1;
}

static int
chacha20_poly1305_runner(const struct testcase *c, int verbose)
{
	struct lc_chacha20_poly1305_params	params;

	if (c->keylenarg != LC_CHACHA20_KEYLEN ||
	    c->keylen != LC_CHACHA20_KEYLEN)
		return 0;
	memcpy(params.key, c->key, LC_CHACHA20_KEYLEN);

	if (c->ivlenarg != LC_CHACHA20_NONCELEN ||
	    c->ivlen != LC_CHACHA20_NONCELEN)
		return 0;
	memcpy(params.nonce, c->iv, LC_CHACHA20_NONCELEN);

	return aead_poly1305_runner(lc_aead_impl_chacha20_poly1305(), c,
	    &params, verbose);
}

static int
xchacha20_poly1305_runner(const struct testcase *c, int verbose)
{
	struct lc_xchacha20_poly1305_params	params;

	if (c->keylenarg != LC_XCHACHA20_KEYLEN ||
	    c->keylen != LC_XCHACHA20_KEYLEN)
		return 0;
	memcpy(params.key, c->key, LC_XCHACHA20_KEYLEN);

	if (c->ivlenarg != LC_XCHACHA20_NONCELEN ||
	    c->ivlen != LC_XCHACHA20_NONCELEN)
		return 0;
	memcpy(params.nonce, c->iv, LC_XCHACHA20_NONCELEN);

	return aead_poly1305_runner(lc_aead_impl_xchacha20_poly1305(), c,
	    &params, verbose);
}
