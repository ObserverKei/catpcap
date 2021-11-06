ifneq ($(MAKECMDGOALS),runenv)
include tools/makefiles/env.mk
endif

BASEDIR := $(shell pwd)
OUTDIR ?= _out

all: build

build: 
	cd tools && $(MAKE) all
	cd source && $(MAKE) all

clean:
	cd tools && $(MAKE) clean
	cd source && $(MAKE) clean
	rm -rf $(OUTDIR)

test: 
	cd source && $(MAKE) test

install:
	if [ ! -d ${DESTDIR} ]; then install -d ${DESTDIR}; fi
	if [ ! -d ${OUTDIR} ]; then install -d ${OUTDIR}; fi
	if [ ! -d ${OUTDIR}/bin ]; then install -d ${OUTDIR}/bin; fi
	if [ ! -d ${OUTDIR}/lib ]; then install -d ${OUTDIR}/lib; fi
	cp -rvf $(OUTDIR)/* $(DESTDIR)
