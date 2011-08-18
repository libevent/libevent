AUTOMAKE_OPTIONS = foreign

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/compat -I$(top_srcdir)/include -I../include -DTINYTEST_LOCAL

EXTRA_DIST = regress.rpc regress.gen.h regress.gen.c rpcgen_wrapper.sh test.sh

noinst_PROGRAMS = test-init test-eof test-weof test-time \
	bench bench_cascade bench_http bench_httpclient test-ratelim \
	test-changelist
if BUILD_REGRESS
noinst_PROGRAMS += regress
endif
EXTRA_PROGRAMS = regress
noinst_HEADERS = tinytest.h tinytest_macros.h regress.h tinytest_local.h

TESTS = $(top_srcdir)/test/test.sh

BUILT_SOURCES =
if BUILD_REGRESS
BUILT_SOURCES += regress.gen.c regress.gen.h
endif

test_init_SOURCES = test-init.c
test_init_LDADD = ../libevent_core.la
test_eof_SOURCES = test-eof.c
test_eof_LDADD = ../libevent_core.la
test_changelist_SOURCES = test-changelist.c
test_changelist_LDADD = ../libevent_core.la
test_weof_SOURCES = test-weof.c
test_weof_LDADD = ../libevent_core.la
test_time_SOURCES = test-time.c
test_time_LDADD = ../libevent_core.la
test_ratelim_SOURCES = test-ratelim.c
test_ratelim_LDADD = ../libevent_core.la -lm

regress_SOURCES = regress.c regress_buffer.c regress_http.c regress_dns.c \
	regress_testutils.c regress_testutils.h \
	regress_rpc.c regress.gen.c regress.gen.h regress_et.c \
	regress_bufferevent.c regress_listener.c \
	regress_util.c tinytest.c regress_main.c regress_minheap.c \
	$(regress_thread_SOURCES) $(regress_zlib_SOURCES)
if PTHREADS
regress_thread_SOURCES = regress_thread.c
PTHREAD_LIBS += ../libevent_pthreads.la
endif
if BUILD_WIN32
regress_thread_SOURCES = regress_thread.c
endif
if ZLIB_REGRESS
regress_zlib_SOURCES = regress_zlib.c
endif
if BUILD_WIN32
regress_SOURCES += regress_iocp.c
endif

regress_LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent.la $(PTHREAD_LIBS) $(ZLIB_LIBS)
regress_CPPFLAGS = $(AM_CPPFLAGS) $(PTHREAD_CFLAGS) $(ZLIB_CFLAGS)
regress_LDFLAGS = $(PTHREAD_CFLAGS)

if OPENSSL
regress_SOURCES += regress_ssl.c
regress_LDADD += ../libevent_openssl.la
endif

bench_SOURCES = bench.c
bench_LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent.la
bench_cascade_SOURCES = bench_cascade.c
bench_cascade_LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent.la
bench_http_SOURCES = bench_http.c
bench_http_LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent.la
bench_httpclient_SOURCES = bench_httpclient.c
bench_httpclient_LDADD = $(LIBEVENT_GC_SECTIONS) ../libevent_core.la

regress.gen.c regress.gen.h: rpcgen-attempted

rpcgen-attempted: $(srcdir)/regress.rpc $(srcdir)/../event_rpcgen.py $(srcdir)/rpcgen_wrapper.sh
	date -u > $@
	if $(srcdir)/rpcgen_wrapper.sh $(srcdir); then \
	   echo "rpcgen okay"; \
	else \
	   echo "No Python installed; stubbing out RPC test." >&2; \
	   echo " "> regress.gen.c; \
	   echo "#define NO_PYTHON_EXISTS" > regress.gen.h; \
	fi

CLEANFILES = rpcgen-attempted

DISTCLEANFILES = *~

verify: check

bench test-init test-eof test-weof test-time test-changelist: ../libevent.la
