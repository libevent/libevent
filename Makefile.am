AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = . sample

EXTRA_DIST = acconfig.h test/Makefile.in compat/err.h compat/sys/queue.h \
             compat/sys/tree.h compat/sys/_time.h

lib_LIBRARIES = libevent.a

libevent_a_SOURCES = event.c
libevent_a_LIBADD = @LIBOBJS@

include_HEADERS = event.h

INCLUDES = -Icompat

man_MANS = event.3

DISTCLEANFILES = *~
