AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = -L.. -levent
CPPFPLAGS = -I.. 
CFLAGS = -I../compat -Wall @CFLAGS@

noinst_PROGRAMS = test-init test-eof test-weof test-time regress bench

test_init_sources = test-init.c
test_eof_sources = test-eof.c
test_weof_sources = test-weof.c
test_time_sources = test-time.c
regress_sources = regress.c
bench_sources = bench.c

DISTCLEANFILES = *~

all:	test

test: test-init test-eof test-weof test-time regress
	@./test.sh

bench test-init test-eof test-weof test-time regress: ../libevent.a
