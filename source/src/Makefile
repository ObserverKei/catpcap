TYPE := so
TARGET = libcatpcap.so

OUTDIR ?= _out
TESTFILE := $(wildcard unittest/*.c) 

OBHS=$(wildcard *.c)
INCLUDES += -I../include -I./unittest 
LIBS += -lldapexpr
PRIVATE_FLAG += -shared #-Wl
PRIVATE_COM_CODE += 
OBHS += $(PRIVATE_COM_CODE)

$(TARGET):$(OBHS:.c=.o)
	$(CC) -o $(OUTDIR)/$@ $^ $(FLAG) $(PRIVATE_FLAG) $(INCLUDES) $(LIBS)
	mv *.o $(OUTDIR)

%.o:%.c
	make build
	$(CC) -c -o $@ $^ $(FLAG) $(INCLUDES)

$(OUTDIR)/%.o:%.c
	make build
	$(CC) -c -o $@ $^ $(FLAG) $(INCLUDES)

$(OUTDIR)/demo.o:build 
	$(CC) -c -o $(OUTDIR)/$@ demo.C $(FLAG) $(INCLUDES)

clean: 
	rm -rf $(OUTDIR)/$(TARGET)

build:
	if [ ! -d ${OUTDIR} ]; then install -d ${OUTDIR}; fi

install:
	cp $(OUTDIR)/$(TARGET) $(DESTDIR)

test: build
	$(CC) -D XTEST -o $(OUTDIR)/test $(OBHS) $(TESTFILE) $(INCLUDES) $(LIBS) 
	$(OUTDIR)/test --fork

demo: 
	make &&	cd $(OUTDIR) &&	$(CC) -o $(OUTDIR)/demo $(CUTDIR)/demo.C $^ $(OBHS:.c=.o) $(INCLUDES) $(LIBS)
	echo "usg: $(OUTDIR)/demo '(src_port=481)' unittest/1.pcap"

memcheck: demo
	valgrind --leak-check=full --show-reachable=yes --trace-children=yes --log-file="$(OUTDIR)/valgrind_log.txt" $(OUTDIR)/demo  '(src_port=481)' unittest/1.pcap && cat $(OUTDIR)/valgrind_log.txt

lcov:
	lcov -d $(OUTDIR)/ -t 'demo' -o 'demo.info' -b $(OUTDIR)/. -c
	genhtml -o $(OUTDIR)/demo_web demo.info

.PHONY: def clean test memcheck lcov build demo

CUTDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include ../../tools/makefiles/app.mk
