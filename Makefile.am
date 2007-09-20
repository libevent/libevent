AUTOMAKE_OPTIONS = foreign no-dependencies


bin_SCRIPTS = event_rpcgen.py

EXTRA_DIST = acconfig.h event.h event-internal.h log.h evsignal.h evdns.3 \
	evrpc.h evrpc-internal.h \
	event.3 \
	kqueue.c epoll_sub.c epoll.c select.c rtsig.c poll.c signal.c \
	evport.c devpoll.c event_rpcgen.py \
	sample/Makefile.am sample/Makefile.in sample/event-test.c \
	sample/signal-test.c sample/time-test.c \
	test/Makefile.am test/Makefile.in test/bench.c test/regress.c \
	test/test-eof.c test/test-weof.c test/test-time.c \
	test/test-init.c test/test.sh \
	compat/sys/queue.h compat/sys/tree.h compat/sys/_time.h \
	WIN32-Code/config.h WIN32-Code/misc.c \
	WIN32-Code/win32.c WIN32-Code/misc.h \
	WIN32-Prj/event_test/event_test.dsp \
	WIN32-Prj/event_test/test.txt WIN32-Prj/libevent.dsp \
	WIN32-Prj/libevent.dsw WIN32-Prj/signal_test/signal_test.dsp \
	WIN32-Prj/time_test/time_test.dsp

lib_LTLIBRARIES = libevent.la

if BUILD_WIN32

SUBDIRS = . sample
SYS_LIBS = -lws2_32
SYS_SRC = WIN32-Code/misc.c WIN32-Code/win32.c
SYS_INCLUDES = -IWIN32-Code

else

SUBDIRS = . sample test
SYS_LIBS =
SYS_SRC =
SYS_INCLUDES =

endif

libevent_la_SOURCES = event.c buffer.c evbuffer.c log.c event_tagging.c \
	http.c evhttp.h http-internal.h evdns.c evdns.h evrpc.c evutil.c \
	strlcpy.c \
	strlcpy-internal.h evrpc.h evrpc-internal.h strlcpy-internal.h \
	$(SYS_SRC)
libevent_la_LIBADD = @LTLIBOBJS@ $(SYS_LIBS)
libevent_la_LDFLAGS = -release @VERSION@ -version-info 1:3:0

include_HEADERS = event.h evhttp.h evdns.h evrpc.h evutil.h

INCLUDES = -I$(srcdir)/compat $(SYS_INCLUDES)

man_MANS = event.3 evdns.3

verify: libevent.la
	cd test && make verify

doxygen: FORCE
	doxygen $(srcdir)/Doxyfile
FORCE:

DISTCLEANFILES = *~
