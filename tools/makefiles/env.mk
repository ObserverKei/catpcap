export DESTDIR ?= /usr/lib/
export CFILE ?= *.C
export CFILES ?= $(wildcard *.c)
export OBJS ?= $(CFILES:.c=.o)
export GCOV_FILE ?= $(OBHS:.c=.gcno) $(CFILE:.C=.gcno)
export FLAG := -fPIC -Wall -g -fprofile-arcs -ftest-coverage -lstdc++ 
export BASEDIR := $(shell cd ../../ && pwd)
export OUTDIR ?= $(BASEDIR)/_out
export GCOV_PREFIX := $(OUTDIR)
export LIBS += -L$(BASEDIR)/_out/lib
export INCLUDES += -I$(BASEDIR)/source/include -I$(BASEDIR)/tools