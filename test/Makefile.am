AUTOMAKE_OPTIONS = foreign no-dependencies

AM_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/compat -I$(top_srcdir)/include

EXTRA_DIST = regress.rpc regress.gen.h regress.gen.c

noinst_PROGRAMS = test-init test-eof test-weof test-time regress \
	bench bench_cascade bench_http bench_httpclient
noinst_HEADERS = tinytest.h tinytest_macros.h regress.h

BUILT_SOURCES = regress.gen.c regress.gen.h
test_init_SOURCES = test-init.c
test_init_LDADD = ../libevent_core.la
test_eof_SOURCES = test-eof.c
test_eof_LDADD = ../libevent_core.la
test_weof_SOURCES = test-weof.c
test_weof_LDADD = ../libevent_core.la
test_time_SOURCES = test-time.c
test_time_LDADD = ../libevent_core.la

regress_SOURCES = regress.c regress_buffer.c regress_http.c regress_dns.c \
	regress_rpc.c regress.gen.c regress.gen.h regress_et.c \
	regress_bufferevent.c regress_listener.c \
	regress_util.c tinytest.c regress_main.c regress_minheap.c \
	$(regress_pthread_SOURCES) $(regress_zlib_SOURCES)
if PTHREADS
regress_pthread_SOURCES = regress_pthread.c
PTHREAD_LIBS += ../libevent_pthreads.la
endif
if ZLIB_REGRESS
regress_zlib_SOURCES = regress_zlib.c
endif
if BUILD_WIN32
regress_SOURCES += regress_iocp.c
endif

regress_LDADD = ../libevent.la $(PTHREAD_LIBS) $(ZLIB_LIBS)
regress_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/compat \
	-I$(top_srcdir)/include  $(PTHREAD_CFLAGS) $(ZLIB_CFLAGS)
regress_LDFLAGS = $(PTHREAD_CFLAGS)

if OPENSSL
regress_SOURCES += regress_ssl.c
regress_LDADD += ../libevent_openssl.la -lcrypto -lssl
endif

bench_SOURCES = bench.c
bench_LDADD = ../libevent.la
bench_cascade_SOURCES = bench_cascade.c
bench_cascade_LDADD = ../libevent.la
bench_http_SOURCES = bench_http.c
bench_http_LDADD = ../libevent.la
bench_httpclient_SOURCES = bench_httpclient.c
bench_httpclient_LDADD = ../libevent_core.la

regress.gen.c regress.gen.h: regress.rpc $(top_srcdir)/event_rpcgen.py
	$(top_srcdir)/event_rpcgen.py $(srcdir)/regress.rpc || echo "No Python installed"

DISTCLEANFILES = *~

test: test-init test-eof test-weof test-time regress

verify: test
	@$(srcdir)/test.sh

bench test-init test-eof test-weof test-time: ../libevent.la
