AUTOMAKE_OPTIONS = foreign no-dependencies

SUBDIRS = . sample test

EXTRA_DIST = acconfig.h event.h event-internal.h log.h evsignal.h event.3 \
	kqueue.c epoll_sub.c epoll.c select.c rtsig.c poll.c signal.c \
	devpoll.c \
	sample/Makefile.am sample/Makefile.in sample/event-test.c \
	sample/signal-test.c sample/time-test.c \
	test/Makefile.am test/Makefile.in test/bench.c test/regress.c \
	test/test-eof.c test/test-weof.c test/test-time.c \
	test/test-init.c test/test.sh \
	compat/sys/queue.h compat/sys/tree.h compat/sys/_time.h \
	WIN32-Code WIN32-Code/config.h WIN32-Code/misc.c \
	WIN32-Code/win32.c WIN32-Code/misc.h \
	WIN32-Prj WIN32-Prj/event_test WIN32-Prj/event_test/event_test.dsp \
	WIN32-Prj/event_test/test.txt WIN32-Prj/libevent.dsp \
	WIN32-Prj/libevent.dsw WIN32-Prj/signal_test \
	WIN32-Prj/signal_test/signal_test.dsp WIN32-Prj/time_test \
	WIN32-Prj/time_test/time_test.dsp

lib_LTLIBRARIES = libevent.la

libevent_la_SOURCES = event.c buffer.c evbuffer.c log.c
libevent_la_LIBADD = @LTLIBOBJS@
libevent_la_LDFLAGS = -release @VERSION@ -version-info 1:2:0

include_HEADERS = event.h

INCLUDES = -Icompat

man_MANS = event.3

verify: libevent.la
	cd $(srcdir)/test && make verify	

DISTCLEANFILES = *~
