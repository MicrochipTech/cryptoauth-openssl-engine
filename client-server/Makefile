# To compile exchange-tls12 utility
CC=		gcc
CWD:=		$(shell pwd)
OPENSSL_VER?=	_1_0_2
OPENSSL=	openssl$(OPENSSL_VER)
#HW?= 		-DECC_DEBUG
HW?=		-DUSE_ECCX08 -DECC_DEBUG

CFLAGS  += 	-g -O0 -ggdb -Wall \
		-I$(CWD)/../engine_atecc \
		-I$(CWD)/../install_dir/include \
		-I$(CWD)/../$(OPENSSL)/crypto \
		-I$(CWD)/../$(OPENSSL)/crypto/bn \
		-I$(CWD)/../engine_atecc/cryptoauthlib \
		-I$(CWD)/../engine_atecc/cryptoauthlib/lib \
		-I$(CWD)/../engine_atecc/cryptoauthlib/lib/tls \
		${HW}

LDFLAGS += -L$(CWD)/../install_dir/lib -lssl -lcrypto

.SILENT:

SRC=	$(wildcard *.c)
APPS=	$(patsubst %.c,%.o,$(SRC))

all: $(APPS)
	@$(CC) $(CFLAGS) $(OFLAGS) $(APPS) $(LDFLAGS) -o exchange-tls12

%.o: %.c
	@echo "Compiling $<. CFLAGS = $(CFLAGS)"
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ -c $<

clean:
	echo "Deleting -> rm -f $(APPS)"
	rm -f $(APPS) exchange-tls12

list:
	echo $(APPS)
