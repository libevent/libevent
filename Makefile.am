AUTOMAKE_OPTIONS = foreign no-dependencies

EXTRA_DIST = acconfig.h

lib_LIBRARIES = libevent.a

libevent_a_SOURCES = event.c select.c @EVSRCS@

include_HEADERS = event.h

man_MANS = event.3
