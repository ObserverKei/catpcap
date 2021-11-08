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
	rm -rf *.gc*

build:
	if [ ! -d ${OUTDIR} ]; then install -d ${OUTDIR}; fi
	
install:
	cp $(OUTDIR)/$(TARGET) $(DESTDIR)
	
meminstall:
	make build
	$(CC) -D _MEMCHEK -o $(OUTDIR)/$(TARGET) $^ $(FLAG) $(PRIVATE_FLAG) $(INCLUDES) $(LIBS)
	make install
	

.PHONY: clean memcheck

	
CUTDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include ../../tools/makefiles/app.mk
