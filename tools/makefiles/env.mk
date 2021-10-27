export DESTDIR ?= /usr/lib/
export CFILE ?= *.C
export GCOV_FILE ?= $(OBHS:.c=.gcno) $(CFILE:.C=.gcno)
export FLAG := -fPIC -Wall -g #-fprofile-arcs -ftest-coverage 