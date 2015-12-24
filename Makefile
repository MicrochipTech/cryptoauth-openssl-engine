#
# Makefile
#

#
# Support for submodule repository operations including:
# init, build, clean, dclean, install
#

OPENSSL_VER=	_1_0_2
OPENSSL=	openssl$(OPENSSL_VER)
CWD:=		$(shell pwd)
UNAME_S:= 	$(shell uname -s)
ARCH:= 		$(shell arch)
#HW= 		-DECC_DEBUG
#HW=		-DUSE_SLOT2_FOR_CERT -DUSE_ECCX08 -DECC_DEBUG
HW=		-DUSE_ECCX08 -DECC_DEBUG
CFLAGS_EXT=	

ifeq ($(UNAME_S),Darwin)
OPENSSL_OS=	darwin64-x86_64-cc
else
ifeq ($(ARCH),armv7l)
OPENSSL_OS=	debug-linux-generic32
else
ifeq ($(UNAME_S),Linux)
OPENSSL_OS=	debug-linux-x86_64
else
#error Not supported OS
endif
endif
endif

.PHONY:	init_submodule \
	tgt_openssl tgt_engine_atecc tgt_unity \
	init_openssl patch_openssl build_openssl install_openssl clean_openssl dclean_openssl test_openssl \
	build_engine_atecc clean_engine_atecc install_engine_atecc \
	build_unity clean_unity install_unity \
	tgt_tlsdemo clean_tlsdemo 

all:	init_submodule tgt_openssl tgt_unity tgt_engine_atecc tgt_tlsdemo

tgt_engine_atecc:	build_engine_atecc install_engine_atecc

tgt_unity:	build_unity install_unity

tgt_openssl:	init_openssl patch_openssl build_openssl install_openssl

clean:	clean_openssl clean_engine_atecc clean_unity clean_tlsdemo
dclean:	dclean_openssl 
test:	test_openssl
install: install_openssl install_engine_atecc install_unity

# OpenSSL
init_openssl:
	@echo "initializing OpenSSL"
	@echo $(UNAME_S)
	cd $(OPENSSL);./Configure $(OPENSSL_OS) --shared --openssldir=$(CWD)/install_dir -DTLS_DEBUG -DSSL_DEBUG -DKSSL_DEBUG -DCIPHER_DEBUG -DOPENSSL_ALGORITHM_DEFINES -DOPENSSL_NO_SHA512; sed -i'' -e 's/\-O0 -g/\-O0 -g/g' Makefile; cd -

patch_openssl:
	@echo "Patching OpenSSL"
#	These next few lines make the patch procedure idempotent
	cd $(OPENSSL);git checkout crypto/ecdh/ecdh.h;cd -
	cd $(OPENSSL);git checkout crypto/ecdh/ech_key.c;cd -
	cd $(OPENSSL);git checkout crypto/ecdh/ech_locl.h;cd -
	cd $(OPENSSL);git checkout ssl/s3_srvr.c;cd -
	cd $(OPENSSL);git checkout ssl/t1_lib.c;cd -
	cd $(OPENSSL);patch -p1 -i ../patches/ecdhe_patch.diff
#	patch $(OPENSSL)/ssl/t1_lib.c patches/Fix_OPENSSL_NO_SHA512$(OPENSSL_VER).patch

build_openssl:
	@echo "Building OpenSSL"
	make -w -C $(OPENSSL)

install_openssl: #Note this is hacked to copy over working OpenSSL include dir
	mkdir -p ${CWD}/install_dir/install_dir
	make -w -C $(OPENSSL) install
	rm -f ${CWD}/install_dir/install_dir/openssl.cnf
	ln -s ${CWD}/openssl.cnf ${CWD}/install_dir/install_dir/openssl.cnf

clean_openssl:
	- make -w -C $(OPENSSL) $(OPENSSL_VER)=$(OPENSSL_VER) clean

dclean_openssl:
	- make -w -C $(OPENSSL) dclean

test_openssl:
	make -w -C $(OPENSSL) test

init_submodule:
	@echo "initializing submodules"
	-git submodule init
	-git submodule update
	@echo "completed submodule init"

#OpenSSL main branch
tgt_openssl_main:
	@echo "Cloning OpenSSL from main"
	- git clone https://github.com/openssl/openssl.git openssl_main
	make -w OPENSSL_VER=_main HW='$(HW)' CFLAGS_EXT='-DOPENSSL_DEVEL'

# ENGINE_ATECC
build_engine_atecc:
	make -w -C engine_atecc OPENSSL_VER=$(OPENSSL_VER) HW='$(HW)' CFLAGS_EXT='$(CFLAGS_EXT)' gnu

clean_engine_atecc:
	make -w -C engine_atecc clean

install_engine_atecc:
	make -w -C engine_atecc install

# UNITY
build_unity:
	make -w -C unity OPENSSL_VER=$(OPENSSL_VER) HW='$(HW)' gnu

clean_unity:
	make -w -C unity clean

install_unity:
	make -w -C unity install

# TLS demo client/server
tgt_tlsdemo:
	make -w -C client-server OPENSSL_VER=$(OPENSSL_VER) HW='$(HW)'

clean_tlsdemo:
	make -w -C client-server clean

