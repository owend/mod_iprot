##
##  Makefile for iPortect Apache module
##
## Copyright 1999-2003, Digital Concepts
## http://www.digital-concepts.net

SERVER_ROOT=/usr/local/test/apache

IPROT_VERSION=1.9.0-beta17

# build tools
APXS=$(SERVER_ROOT)/bin/apxs
APACHECTL=$(SERVER_ROOT)/bin/apachectl

#   the directory where the distribution archive is assembled
DIST_DIR=../iprot

CFLAGS= -O3 -Wall -fno-strict-aliasing -fpic -DEAPI -DSHARED_MODULE -DLINUX=22 -DUSE_HSREGEX -I$(SERVER_ROOT)/include

#   the default target
all: mod_iprot.so

libiprot.a: iprot_admin.o iprot_db.o
	ar rcs libiprot.a iprot_admin.o iprot_db.o

iprot_db.o: iprot_db.c mod_iprot.h Makefile
	gcc -c $(CFLAGS) -o iprot_db.o iprot_db.c

iprot_admin.o: iprot_admin.c mod_iprot.h Makefile
	gcc -c $(CFLAGS) -o iprot_admin.o iprot_admin.c

mod_iprot.o: mod_iprot.c mod_iprot.h Makefile
	gcc $(CFLAGS) -c mod_iprot.c

#   link the DSO file
mod_iprot.so: mod_iprot.o libiprot.a
	gcc -shared -o mod_iprot.so mod_iprot.o libiprot.a -ldb

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	cp mod_iprot.so $(SERVER_ROOT)/libexec/mod_iprot-1.9.0.so
#	$(APXS) -i -a -n 'iprot' mod_iprot.so

#   cleanup
clean:
	-rm -f iprot_admin.o iprot_db.o libiprot.a mod_iprot.o mod_iprot.so

#   reload the module by installing and restarting Apache
reload: install cycle

#   the general Apache start/restart/stop procedures
start:
	$(APACHECTL) start

restart:
	$(APACHECTL) restart

stop:
	$(APACHECTL) stop

cycle: stop start
