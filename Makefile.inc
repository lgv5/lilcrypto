# Constant time.
LC_SRCS+=	ct.c

# Utilities.
LC_SRCS+=	util.c

# AEAD.
LC_SRCS+=	aead.c
LC_SRCS+=	aead_chacha20_poly1305.c

# Authentication.
LC_SRCS+=	auth.c
LC_SRCS+=	auth_hmac.c
LC_SRCS+=	auth_poly1305.c

# Ciphers.
LC_SRCS+=	cipher.c
LC_SRCS+=	cipher_chacha20.c

# Hashes.
LC_SRCS+=	hash.c
LC_SRCS+=	hash_sha224_sha256.c
LC_SRCS+=	hash_sha384_sha512.c

# Key-derivation functions.
LC_SRCS+=	kdf.c
LC_SRCS+=	kdf_hkdf.c

# Implementations.
LC_SRCS+=	impl_chacha20.c
LC_SRCS+=	impl_poly1305.c
LC_SRCS+=	impl_sha256.c
LC_SRCS+=	impl_sha512.c

WARNINGS=	Yes

.include <bsd.own.mk>
