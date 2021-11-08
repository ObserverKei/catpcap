CFILES 	= $(wildcard *.c)
OBJS    = $(CFILES:.c=.o)
CC		= gcc
PICFLAG	:= $(shell if [ `uname -o` != 'Cygwin' ]; then echo '-fPIC'; fi)
DEFIN	= $(PICFLAG)
LIBS	= 
CFLAGS	= $(FLAG) -Wall $(DEFIN)
MNAME	= libxtest
SUFFIX	:= $(shell if [ `uname -o` == 'Cygwin' ]; then echo dll; else echo so; fi)
INSTALL_DIR := $(shell if [ `uname -o` == 'Cygwin' ]; then echo '/usr/bin'; else echo '/usr/lib'; fi)
TARGET	= $(MNAME).$(SUFFIX)
 
.PHONY: all clean cleanall dll dynamic static debug install

$(TARGET): $(OBJS)
	gcc -shared $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)
	mv -f *.gc* $(OUTDIR)

static: $(OBJS)
	ar -r $(MNAME).a $(OBJS)
	
debug:
	gcc -g -Wall -shared $(DEFIN) -o $(TARGET) $(CFILES) $(LIBS)

clean:
	rm -f *.o *.output *.stackdump $(TARGET) $(MNAME).a $(MNAME).so $(MNAME).dll

install:
	cp -f $(TARGET) $(INSTALL_DIR)
	cp -f xtest.h /usr/include
	
