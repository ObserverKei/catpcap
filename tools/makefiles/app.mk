MYDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
include $(MYDIR)/env.mk

ifeq ($(findstring .so, $(TARGET)),)
TYPE ?= app
INSTALL_DIR ?= bin
TYPE ?= so
INSTALL_DIR ?= $(LIBDIR)

endif##($(findstring .so, $(TARGET)),)

ifeq ($(TYPE),so)
OUTDIR := $(BASEDIR)/_out/lib
else ifeq ($(TYPE),app)
OUTDIR := $(BASEDIR)/_out/bin
endif##($(TYPE),so)

ifeq ($(findstring .c, $(OBJS)),)
CC = gcc
else##($(findstring .c, $(OBJS)),)
CC = gcc
endif##($(findstring .c, $(OBJS)),)
