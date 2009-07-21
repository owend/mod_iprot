##
##  Makefile v0.2 -- Build procedure for iPortect Apache module
##  Autogenerated via ``apxs -n iprot -g''.
##

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional user defines, includes and libraries
#DEF=-Dmy_define=my_value
#INC=-Imy/include/dir

# Solaris 5.7 POSIX Support Library
#LIB=-lrt



#   the default target
all: mod_iprot.so

#   compile the DSO file
mod_iprot.so: mod_iprot.c
	$(APXS) -c $(DEF) $(INC) $(LIB) mod_iprot.c

#   install the DSO file into the Apache installation
#   and activate it in the Apache configuration
install: all
	$(APXS) -i -a -n 'iprot' mod_iprot.so

#   cleanup
clean:
	-rm -f mod_iprot.o mod_iprot.so

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

