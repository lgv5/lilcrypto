.PATH:	${.CURDIR}/..

AEAD=	wycheproof_aead
MAC=	wycheproof_mac

PROGS=	${AEAD} ${MAC}
NOMAN=	noman

SRCS_wycheproof_aead=	wycheproof_aead.c
SRCS_wycheproof_mac=	wycheproof_mac.c

DPADD+=	${.CURDIR}/../lib/obj/liblilcrypto.a
LDADD+=	${.CURDIR}/../lib/obj/liblilcrypto.a


tests: all tests-aead tests-mac

tests-aead:
.ifndef WYCHEPROOF_DIR
	@echo Undefined WYCHEPROOF_DIR; false
.endif
.for p in ${AEAD}
	perl ${.CURDIR}/aead.pl ${TESTOPTS} -x ./${p} \
	    ${WYCHEPROOF_DIR}/testvectors/chacha20_poly1305_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/chacha20_poly1305_test.json \
	    ${WYCHEPROOF_DIR}/testvectors/xchacha20_poly1305_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/xchacha20_poly1305_test.json
.endfor

tests-mac:
.ifndef WYCHEPROOF_DIR
	@echo Undefined WYCHEPROOF_DIR; false
.endif
.for p in ${MAC}
	perl ${.CURDIR}/mac.pl ${TESTOPTS} -x ./${p} \
	    ${WYCHEPROOF_DIR}/testvectors/hmac_sha224_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/hmac_sha224_test.json \
	    ${WYCHEPROOF_DIR}/testvectors/hmac_sha256_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/hmac_sha256_test.json \
	    ${WYCHEPROOF_DIR}/testvectors/hmac_sha384_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/hmac_sha384_test.json \
	    ${WYCHEPROOF_DIR}/testvectors/hmac_sha512_test.json \
	    ${WYCHEPROOF_DIR}/testvectors_v1/hmac_sha512_test.json
.endfor

.include <bsd.prog.mk>
