AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = . sample

EXTRA_DIST = acconfig.h

lib_LIBRARIES = libevent.a

libevent_a_SOURCES = event.c
libevent_a_LIBADD = @LIBOBJS@

include_HEADERS = event.h

INCLUDES = -I/usr/include -Icompat

man_MANS = event.3

DISTCLEANFILES = *~
