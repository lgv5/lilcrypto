.PATH:	${.CURDIR}/..

AEAD=	wycheproof_aead

PROGS=	${AEAD}
NOMAN=	noman

SRCS_wycheproof_aead=	wycheproof_aead.c

LDADD+=	${.CURDIR}/../lib/obj/liblilcrypto.a


tests: all tests-aead

tests-aead:
.ifndef WYCHEPROOF_DIR
	@echo Undefined WYCHEPROOF_DIR; false
.endif
.for p in ${AEAD}
	perl ${.CURDIR}/aead.pl -x ./${p} \
	    ${WYCHEPROOF_DIR}/testvectors/chacha20_poly1305_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/chacha20_poly1305_test.json
.endfor

.include <bsd.prog.mk>
