CFILES 	= $(wildcard *.c)
OBJS    = $(CFILES:.c=.o)
CC		= gcc
DEFIN	= -Ilibxtest
LIBS	= -Llibxtest -lxtest -ldl
CFLAGS	= $(FLAG) -Wall $(DEFIN)
TARGET	= xtest

.PHONY: all clean cleanall libxtest

$(TARGET): $(OBJS) libxtest
	gcc $(CFLAGS) -o $(TARGET) $(OBJS) $(LIBS)

libxtest:
	(cd libxtest && make)

debug: 
	gcc -g -Wall $(DEFIN) -o $(TARGET) $(CFILES) $(LIBS)

clean:
	(cd libxtest && make clean)
	rm -f *.o *.output *.stackdump $(TARGET)

install:
	(cd libxtest && make install)
	cp -f $(TARGET) /usr/bin && chmod a+x /usr/bin/$(TARGET)
