LC_SRCS+=	auth.c auth_poly1305.c
LC_SRCS+=	cipher.c cipher_chacha20.c
LC_SRCS+=	aead.c aead_chacha20_poly1305.c
LC_SRCS+=	impl_chacha20.c impl_poly1305.c
LC_SRCS+=	ct.c util.c

CFLAGS+=	-Wall
CFLAGS+=	-Wextra
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wmissing-prototypes
CFLAGS+=	-Wpointer-arith
CFLAGS+=	-Wshadow
CFLAGS+=	-Wstrict-prototypes
CFLAGS+=	-Wunused
CFLAGS+=	-Wno-unused-parameter

.include <bsd.own.mk>
