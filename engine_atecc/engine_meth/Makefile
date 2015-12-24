CC=		gcc
CFLAGS_EXT=
CWD:=		$(shell pwd)
OPENSSL_VER?=   _1_0_2
OPENSSL=	openssl$(OPENSSL_VER)
#HW?= 		-DECC_DEBUG
HW?=		-DUSE_ECCX08 -DECC_DEBUG

CFLAGS= -I. -I.. -I../.. \
	-I../../$(OPENSSL) \
        -I../../$(OPENSSL)/include \
        -I../../$(OPENSSL)/include/openssl \
        -I../../$(OPENSSL)/crypto/crypto \
        -I../../$(OPENSSL)/crypto/engine \
        -I../../$(OPENSSL)/crypto/include/internal \
	-I../cryptoauthlib/lib \
	-I../cryptoauthlib/lib/tls \
	-fPIC -g -O0 $(HW) -DATCA_HAL_KIT_CDC $(CFLAGS_EXT)

SRC=	$(wildcard *.c)

.PHONY:	clean

MODULES=	$(patsubst %.c,%.o,$(SRC))
LIBNAME=	libeccx08_meth

all:	$(MODULES) Makefile
	ar -r $(LIBNAME).a $(MODULES)
	ranlib $(LIBNAME).a

%.o: %.c
	@echo "Compiling $<. CFLAGS = $(CFLAGS)"
	@$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a
