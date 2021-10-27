ifneq ($(MAKECMDGOALS),runenv)
include tools/makefiles/env.mk
endif

OUTDIR ?= _out

all: build

build: 
	cd source && $(MAKE) all

clean:
	cd source && $(MAKE) clean

test: 
	cd source && $(MAKE) test

install:
	if [ ! -d ${DESTDIR} ]; then install -d ${DESTDIR}; fi
	cp -rvf $(OUTDIR)/* $(DESTDIR)
