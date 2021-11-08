TYPE := so
TARGET = libldapexpr.so
OBHS=$(wildcard *.c)

OUTDIR ?= _out

PRIVATE_FLAG += -shared 

$(TARGET):$(OBHS:.c=.o)
	make build
	$(CC) -o $(OUTDIR)/$@ $^ $(FLAG) $(PRIVATE_FLAG) $(INCLUDES) $(LIBS)
	mv *.o *.gc* $(OUTDIR)

%.o:%.c
	$(CC) -c -o $@ $^ $(FLAG) $(INCLUDES)

clean: 
	rm -rf $(OUTDIR)/$(TARGET)

build:
	if [ ! -d ${OUTDIR} ]; then install -d ${OUTDIR}; fi
	
install:
	cp $(OUTDIR)/$(TARGET) $(DESTDIR)

.PHONY: clean 

	
CUTDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include ../../tools/makefiles/app.mk
