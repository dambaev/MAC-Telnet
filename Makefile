AUTOMAKE_OPTIONS = foreign
SUBDIRS = src doc config po

CFLAGS = --pedantic -Wall -std=c99 -O3 
LDFLAGS =


ACLOCAL_AMFLAGS =

EXTRA_DIST = config.rpath README.markdown LICENSE

all:
	CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" make -C src all

install:
	make -C src install

clean:
	make -C src clean
