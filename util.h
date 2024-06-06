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


#define nelems(_a)	(sizeof((_a)) / sizeof((_a)[0]))


/*
 * Endianness.
 */

static inline uint16_t
load16le(const uint8_t *x)
{
	return x[0] | (x[1] << 8);
}

static inline uint32_t
load32le(const uint8_t *x)
{
	return x[0] | (x[1] << 8) | (x[2] << 16) | (x[3] << 24);
}

static inline uint64_t
load64le(const uint8_t *x)
{
	return load32le(x) | (((uint64_t)load32le(x + 4)) << 32);
}

static inline void
store16le(uint8_t *x, uint64_t v)
{
	x[0] = v & 0xff;
	x[1] = v >> 8;
}

static inline void
store32le(uint8_t *x, uint32_t v)
{
	x[0] = v & 0xff;
	x[1] = (v >> 8) & 0xff;
	x[2] = (v >> 16) & 0xff;
	x[3] = v >> 24;
}

static inline void
store64le(uint8_t *x, uint64_t v)
{
	x[0] = v & 0xff;
	x[1] = (v >> 8) & 0xff;
	x[2] = (v >> 16) & 0xff;
	x[3] = (v >> 24) & 0xff;
	x[4] = (v >> 32) & 0xff;
	x[5] = (v >> 40) & 0xff;
	x[6] = (v >> 48) & 0xff;
	x[7] = v >> 56;
}

static inline uint16_t
load16be(const uint8_t *x)
{
	return (x[0] << 8) | x[1];
}

static inline uint32_t
load32be(const uint8_t *x)
{
	return (x[0] << 24) | (x[1] << 16) | (x[2] << 8) | x[3];
}

static inline uint64_t
load64be(const uint8_t *x)
{
	return ((uint64_t)load32be(x) << 32) | load32be(x + 4);
}

static inline void
store16be(uint8_t *x, uint64_t v)
{
	x[0] = v >> 8;
	x[1] = v & 0xff;
}

static inline void
store32be(uint8_t *x, uint32_t v)
{
	x[0] = v >> 24;
	x[1] = (v >> 16) & 0xff;
	x[2] = (v >> 8) & 0xff;
	x[3] = v & 0xff;
}

static inline void
store64be(uint8_t *x, uint64_t v)
{
	x[0] = v >> 56;
	x[1] = (v >> 48) & 0xff;
	x[2] = (v >> 40) & 0xff;
	x[3] = (v >> 32) & 0xff;
	x[4] = (v >> 24) & 0xff;
	x[5] = (v >> 16) & 0xff;
	x[6] = (v >> 8) & 0xff;
	x[7] = v & 0xff;
}


/*
 * rotr and rotl.
 */

static inline uint32_t
rotl32(uint32_t x, uint32_t r)
{
	return (x << r) | (x >> (32 - r));
}

static inline uint64_t
rotl64(uint64_t x, uint64_t r)
{
	return (x << r) | (x >> (64 - r));
}

static inline uint32_t
rotr32(uint32_t x, uint32_t r)
{
	return (x >> r) | (x << (32 - r));
}

static inline uint64_t
rotr64(uint64_t x, uint64_t r)
{
	return (x >> r) | (x << (64 - r));
}
