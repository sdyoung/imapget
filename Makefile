# Root Makefile for imapget.  You probably want to edit src/Makefile,
# not this one.
all:
	(cd src/; make)
install:
	(cd src/; make install)
	(cd doc/; make install)
clean:
	(cd src/; make clean)
