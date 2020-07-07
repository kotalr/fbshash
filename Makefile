IBASE=		/opt/firebird

# ---------------------------------------------------------------------
# General Compiler and linker Defines for Linux
# ---------------------------------------------------------------------
CC=		gcc
LINK=		gcc
LIB_LINK=	ld
CFLAGS=		-c -w -I$(IBASE)/include 
LIB_CFLAGS=	-fPIC $(CFLAGS)
LINK_FLAGS=	-ldl -lcrypt -lcrypto
LIB_LINK_FLAGS=	-shared -lib_util -lcrypto
RM=		rm -f

.SUFFIXES: .o .c 


.c.o:
	$(CC) $< $(CFLAGS) $@



all:	fb_shash

fb_shash.o:fb_shash.c config.h inc.uuencode.c inc.utils.c  inc.hash.c inc.hmac.c
	$(CC) $< $(LIB_CFLAGS) -o $@

fb_shash: fb_shash.o
	$(LIB_LINK) $@.o -o $@ $(LIB_LINK_FLAGS)
	@echo ------------------------------------------------------
	@echo You need to copy fb_shash to the interbase lib directory
	@echo in order for the server to load it. 
	@echo ------------------------------------------------------
