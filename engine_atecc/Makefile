OPENSSL_VER?=   _1_0_2
CFLAGS_EXT=
OPENSSL=	openssl$(OPENSSL_VER)
LIBNAME=	libateccx08
SRC=		engine_atecc_binder.c
OBJ=		engine_atecc_binder.o 
HEADER=		ecc-crypto_openssl.h
#HW?= 		-DECC_DEBUG
HW?=		-DUSE_ECCX08 -DECC_DEBUG
#HW?=		-DUSE_SW_ECDHE -DUSE_ECCX08 -DECC_DEBUG
#HW?=		-DUSE_SLOT2_FOR_CERT -DUSE_ECCX08 -DECC_DEBUG

CC=		gcc
PIC=		-fPIC
CFLAGS=		-g -O0 -Iengine_meth -Icryptoauthlib/test -Icryptoauthlib/lib \
		-I./cryptoauthlib -Icryptoauthlib/lib/tls \
		-I../install_dir/include -I../../../include -I../$(OPENSSL) \
		$(PIC) -DENGINE_DYNAMIC_SUPPORT -DFLAT_INC -DATCA_HAL_KIT_CDC \
		$(HW) $(CFLAGS_EXT)
AR=		ar r
RANLIB=		ranlib

LIB=		$(LIBNAME).a
SHLIB=		$(LIBNAME).so

all:
		@echo 'Please choose a system to build on:'
		@echo ''
		@echo 'tru64:    Tru64 Unix, Digital Unix, Digital OSF/1'
		@echo 'solaris:  Solaris'
		@echo 'irix:     IRIX'
		@echo 'hpux32:   32-bit HP/UX'
		@echo 'hpux64:   64-bit HP/UX'
		@echo 'aix:      AIX'
		@echo 'gnu:      Generic GNU-based system (gcc and GNU ld)'
		@echo ''

tgt_cryptoauthlib:
	make -w -C cryptoauthlib HW='$(HW)' 

tgt_engine_meth:
	make -w -C engine_meth HW='$(HW)' CFLAGS_EXT='$(CFLAGS_EXT)'

# CHANGE
ecc-test: tgt_engine_meth tgt_cryptoauthlib Makefile
	$(CC) -c ecc-test-main.c $(CFLAGS) -I./cryptoauthlib -I. -I..
	$(CC) -o ecc-test-main ecc-test-main.o cryptoauthlib/test/tls/atcatls_tests.o -Lengine_meth -Lcryptoauthlib/lib -leccx08_meth -lcryptoauth  -Lcryptoauthlib/test -lunity -lm -lc -lrt

clean:
	rm -f *.o *.a ecc-test-main *.so* *.exp
	make -w -C engine_meth clean
	make -w -C cryptoauthlib clean

install:
	cp -f $(SHLIB) ../install_dir/lib/engines

FORCE.update:
update:		FORCE.update
		perl ../../../util/mkerr.pl -conf ecc-crypto.ec \
			-nostatic -staticloader -write ecc-crypto.c

gnu:		$(SHLIB).gnu  
tru64:		$(SHLIB).tru64
solaris:	$(SHLIB).solaris
irix:		$(SHLIB).irix
hpux32:		$(SHLIB).hpux32
hpux64:		$(SHLIB).hpux64
aix:		$(SHLIB).aix

$(LIB):		$(OBJ)
		$(AR) $(LIB) $(OBJ)
		- $(RANLIB) $(LIB)
LIBAMETH=engine_meth/libeccx08_meth.a

LINK_SO=	\
  ld -r -o $(LIBNAME).o $$ALLSYMSFLAGS $(LIB) $(LIBAMETH) && \
  (nm -Pg $(LIBNAME).o | grep ' [BDT] ' | cut -f1 -d' ' > $(LIBNAME).exp; \
   $$SHAREDCMD $$SHAREDFLAGS -o $(SHLIB) $(LIBNAME).o -L ../install_dir/lib -lcrypto -lc \
   -Lengine_meth -Lcryptoauthlib/lib -leccx08_meth -lcryptoauth -lm -lrt)

$(SHLIB).gnu:	$(LIB) ecc-test tgt_engine_meth
		ALLSYMSFLAGS='--whole-archive' \
		SHAREDFLAGS='-shared -Wl,-soname=$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).gnu
$(SHLIB).tru64:	$(LIB)
		A-Wl,-soname=engine_eccx08.so-Wl,-soname=engine_eccx08.so  LLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).tru64
$(SHLIB).solaris:	$(LIB)
		ALLSYMSFLAGS='-z allextract' \
		SHAREDFLAGS='-G -h $(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).solaris
$(SHLIB).irix:	$(LIB)
		ALLSYMSFLAGS='-all' \
		SHAREDFLAGS='-shared -Wl,-soname,$(SHLIB)' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).irix
$(SHLIB).hpux32:	$(LIB)
		ALLSYMSFLAGS='-Fl' \
		SHAREDFLAGS='+vnocompatwarnings -b -z +s +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux32
$(SHLIB).hpux64:	$(LIB)
		ALLSYMSFLAGS='+forceload' \
		SHAREDFLAGS='-b -z +h $(SHLIB)' \
		SHAREDCMD='/usr/ccs/bin/ld'; \
		$(LINK_SO)
		touch $(SHLIB).hpux64
$(SHLIB).aix:	$(LIB)
		ALLSYMSFLAGS='-bnogc' \
		SHAREDFLAGS='-G -bE:$(LIBNAME).exp -bM:SRE' \
		SHAREDCMD='$(CC)'; \
		$(LINK_SO)
		touch $(SHLIB).aix

depend:
		sed -e '/^# DO NOT DELETE.*/,$$d' < Makefile > Makefile.tmp
		echo '# DO NOT DELETE THIS LINE -- make depend depends on it.' >> Makefile.tmp
		$(CC) -M $(CFLAGS) $(SRC) >> Makefile.tmp
		perl ../../../util/clean-depend.pl < Makefile.tmp > Makefile.new
		rm -f Makefile.tmp Makefile
		mv Makefile.new Makefile

# DO NOT DELETE THIS LINE -- make depend depends on it.
