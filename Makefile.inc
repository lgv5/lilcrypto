LC_SRCS+=	aead.c aead_chacha20_poly1305.c
LC_SRCS+=	auth.c auth_hmac.c auth_poly1305.c
LC_SRCS+=	cipher.c cipher_chacha20.c
LC_SRCS+=	hash.c hash_sha224_sha256.c hash_sha384_sha512.c
LC_SRCS+=	impl_chacha20.c impl_poly1305.c impl_sha256.c impl_sha512.c
LC_SRCS+=	ct.c util.c

WARNINGS=	Yes

.include <bsd.own.mk>
