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
	const struct lc_aead_impl	*(*impl)(void);
};

static int
kwimpl_cmp(const void *k0, const void *h0)
{
	const struct kwimpl	*h = h0;
	const char		*k = k0;

	return strcmp(k, h->kw);
}

static const struct lc_aead_impl *
kw2impl(const char *s)
{
	static const struct kwimpl	tbl[] = {
		{ "CHACHA20-POLY1305", &lc_aead_impl_chacha20_poly1305 },
		{ "XCHACHA20-POLY1305", &lc_aead_impl_xchacha20_poly1305 },
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
	const struct lc_aead_impl	*impl;
	uint8_t		*aad, *ct, *iv, *key, *msg, *tag, *encout, *decout,
			    *buf;
	const char	*errstr;
	size_t		 aadlen, ctlen, ivlen, keylen, msglen, taglen;
	size_t		 ivlenarg, keylenarg, taglenarg;
	size_t		 l, encoutlen, decoutlen;
	int		 aflag, cflag, Iflag, iflag, Kflag, kflag, mflag,
			    Tflag, tflag;
	int		 ch, verbose;

	if (argc < 2)
		usage();

	impl = kw2impl(argv[1]);
	if (impl == NULL)
		errx(1, "unsupported algorithm: %s", argv[1]);

	optind = 2;
	aflag = cflag = Iflag = iflag = Kflag = kflag = mflag = Tflag = tflag =
	    0;
	verbose = 0;
	while ((ch = getopt(argc, argv, "a:c:I:i:K:k:m:T:t:v")) != -1) {
		switch (ch) {
		case 'a':
			aflag = 1;
			(void)hexparse(optarg, NULL, &aadlen);
			if (aadlen != 0) {
				aad = malloc(aadlen);
				if (aad == NULL)
					err(1, "out of memory");
			} else
				aad = NULL;
			if (!hexparse(optarg, aad, &l) || l != aadlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'c':
			cflag = 1;
			(void)hexparse(optarg, NULL, &ctlen);
			if (ctlen != 0) {
				ct = malloc(ctlen);
				if (ct == NULL)
					err(1, "out of memory");
			} else
				ct = NULL;
			if (!hexparse(optarg, ct, &l) || l != ctlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
		case 'I':
			Iflag = 1;
			ivlenarg = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "ivlen is %s: %s", errstr, optarg);
			ivlenarg /= 8;
			break;
		case 'i':
			iflag = 1;
			(void)hexparse(optarg, NULL, &ivlen);
			if (ivlen != 0) {
				iv = malloc(ivlen);
				if (iv == NULL)
					err(1, "out of memory");
			} else
				iv = NULL;
			if (!hexparse(optarg, iv, &l) || l != ivlen)
				errx(1, "invalid hex string: %s", optarg);
			break;
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

	if (!(aflag && cflag && Iflag && iflag && Kflag && kflag && mflag &&
	    Tflag && tflag))
		errx(1, "missing required arguments");

	/* Encryption. */

	if (!lc_aead_seal(impl, key, keylenarg, iv, ivlenarg, NULL, &encoutlen,
	    aad, aadlen, msg, msglen)) {
		puts("invalid");
		return 1;
	}
	encout = malloc(encoutlen);
	if (encout == NULL)
		err(1, "out of memory");
	if (!lc_aead_seal(impl, key, keylenarg, iv, ivlenarg, encout,
	    &encoutlen, aad, aadlen, msg, msglen)) {
		puts("invalid");
		return 1;
	}

	if (ctlen != encoutlen - LC_POLY1305_TAGLEN ||
	    !lc_ct_cmp(encout, ct, ctlen)) {
		if (verbose) {
			fprintf(stderr, "ct (%zu, %zu)\n", ctlen,
			    encoutlen - LC_POLY1305_TAGLEN);
			lc_hexdump_fp(stderr, msg, msglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, ct, ctlen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, encout,
			    encoutlen - LC_POLY1305_TAGLEN);
			fprintf(stderr, "\n");
		}
		puts("invalid");
		return 1;
	}
	if (taglenarg != LC_POLY1305_TAGLEN ||
	    !lc_ct_cmp(encout + ctlen, tag, LC_POLY1305_TAGLEN)) {
		if (verbose) {
			fprintf(stderr, "tag (%zu, %zu)\n", taglenarg,
			    (size_t)LC_POLY1305_TAGLEN);
			lc_hexdump_fp(stderr, tag, taglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, encout + ctlen, LC_POLY1305_TAGLEN);
			fprintf(stderr, "\n");
		}
		puts("invalid");
		return 1;
	}

	/* Decryption. */

	buf = malloc(msglen + taglen);
	if (buf == NULL)
		err(1, "out of memory");
	memcpy(buf, ct, ctlen);
	memcpy(buf + ctlen, tag, taglen);

	if (!lc_aead_open(impl, key, keylenarg, iv, ivlenarg, NULL, &decoutlen,
	    aad, aadlen, buf, ctlen + taglen)) {
		puts("invalid");
		return 1;
	}
	decout = malloc(decoutlen);
	if (encout == NULL)
		err(1, "out of memory");
	if (!lc_aead_open(impl, key, keylenarg, iv, ivlenarg, decout,
	    &decoutlen, aad, aadlen, buf, ctlen + taglen)) {
		puts("invalid");
		return 1;
	}

	if (msglen != decoutlen || !lc_ct_cmp(decout, msg, msglen)) {
		if (verbose) {
			fprintf(stderr, "ct (%zu, %zu)\n", msglen, decoutlen);
			lc_hexdump_fp(stderr, msg, msglen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, ct, ctlen);
			fprintf(stderr, "\n");
			lc_hexdump_fp(stderr, decout, decoutlen);
			fprintf(stderr, "\n");
		}
		puts("invalid");
		return 1;
	}
	/* Tag isn't checked, as it's already validated by lc_aead_open. */

	puts("valid");
	return 0;
}
