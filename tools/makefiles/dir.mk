MYDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include $(MYDIR)/env.mk

.PHONY: all clean

all: $(SUBDIRS:=.all)

clean: $(SUBDIRS:=.clean)

test: $(SUBDIRS:=.test)

%.all:
	cd $* && $(MAKE)

%.clean :
	cd $* && $(MAKE) clean

%.test:
	cd $* && $(MAKE) test

%.install:
	cd $* && $(MAKE) install