TYPE   := app
CFILES 	= $(wildcard *.c)
OBJS    = $(CFILES:.c=.o)
CC		= gcc
DEFIN	= -Ilibxtest
LIBS	= -Llibxtest -lxtest -ldl
CFLAGS	= $(FLAG) -Wall $(DEFIN)
TARGET	= xtest

OUTDIR ?= _out

.PHONY: all clean cleanall libxtest

$(TARGET): $(OBJS) libxtest
	if [ ! -d ${OUTDIR} ]; then install -d ${OUTDIR}; fi
	gcc $(CFLAGS) -o $(OUTDIR)/$(TARGET) $(OBJS) $(LIBS)

libxtest:
	(cd libxtest && make)

debug: 
	gcc -g -Wall $(DEFIN) -o $(TARGET) $(CFILES) $(LIBS)

clean:
	(cd libxtest && make clean)
	rm -f *.o *.output *.stackdump $(OUTDIR)/$(TARGET) 

install:
	(cd libxtest && make install)
	cp -f $(OUTDIR)/$(TARGET) /usr/bin && chmod a+x /usr/bin/$(TARGET)

CUTDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include ../../tools/makefiles/app.mk
