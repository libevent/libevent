AUTOMAKE_OPTIONS = foreign no-dependencies

CFLAGS += -Wall -g -O2
SUBDIRS = . sample test

EXTRA_DIST = acconfig.h epoll.c err.c event.h kqueue.c select.c \
	epoll_sub.c evsignal.h poll.c signal.c event.3 \
	sample/Makefile.am sample/Makefile.in sample/event-test.c \
	sample/signal-test.c sample/time-test.c \
	test/Makefile.am test/Makefile.in test/bench.c test/regress.c \
	test/test-eof.c test/test-weof.c test/test-time.c \
	compat/err.h compat/sys/queue.h compat/sys/tree.h compat/sys/_time.h

lib_LIBRARIES = libevent.a

libevent_a_SOURCES = event.c
libevent_a_LIBADD = @LIBOBJS@

include_HEADERS = event.h

INCLUDES = -Icompat

man_MANS = event.3

DISTCLEANFILES = *~
