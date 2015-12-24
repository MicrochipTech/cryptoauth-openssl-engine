CWD:=$(shell pwd)
CFLAGS=-I. -I../.. -I./host -fPIC -g -O0
SRC:=$(wildcard *.c)
CC=	gcc

DIRECTORIES=$(shell find . -maxdepth 1 ! -path . -type d)
SUBDIRS=$(DIRECTORIES)

.PHONY:	clean

MODULES=$(patsubst %.c,%.o,$(SRC))
#O_FILES=$(shell find . -name \*.o)
O_FILES=$(wildcard **/**/*.o)
O_FILES+=$(wildcard **/*.o)
LIBNAME=libcryptoauth

all:	$(MODULES)
	- $(foreach subdir,$(basename $(SUBDIRS)),$(shell make -w -C $(subdir)))
	@echo "OFILES: $(O_FILES)"
	ar -r $(LIBNAME).a $(MODULES) $(O_FILES) 
	ranlib $(LIBNAME).a

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a
	$(foreach subdir,$(basename $(SUBDIRS)),$(MAKE) -w -C $(subdir) clean;)

