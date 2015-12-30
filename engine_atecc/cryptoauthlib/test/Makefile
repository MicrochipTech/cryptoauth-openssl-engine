LIBNAME=        libunity
LIB=            $(LIBNAME).a
AR=             ar r
RANLIB=         ranlib

include ../Makefile.generic

tgt_local:
	$(CC) -o unity.o -c unity.c
	$(AR) $(LIB) unity.o
