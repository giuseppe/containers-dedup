SUBDIRS = lib

bin_PROGRAMS = dedup

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = autogen.sh m4/gnulib-cache.m4

dedup_CFLAGS = -I . -I lib
dedup_LDFLAGS =
dedup_LDADD = lib/libgnu.a
dedup_SOURCES = main.c bupsplit.c
