AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = -L.. -levent
CPPFPLAGS = -I.. 
CFLAGS = -I../compat -g -Wall

noinst_PROGRAMS = test-eof test-weof test-time regress bench

test_eof_sources = test-eof.c
test_weof_sources = test-weof.c
test_time_sources = test-time.c
regress_sources = regress.c
bench_sources = bench.c

DISTCLEANFILES = *~

all:	test

test: test-eof test-weof test-time regress
	@echo "Running tests:"
	@echo -n " test-eof: "
	@if ./test-eof >/dev/null ; \
	then \
		echo OKAY ; \
	else \
		echo FAILED ; \
	fi
	@echo -n " test-weof: "
	@if ./test-weof >/dev/null ; \
	then \
		echo OKAY ; \
	else \
		echo FAILED ; \
	fi
	@echo -n " test-time: "
	@if ./test-time >/dev/null ; \
	then \
		echo OKAY ; \
	else \
		echo FAILED ; \
	fi
	@echo -n " regress: "
	@if ./regress >/dev/null ; \
	then \
		echo OKAY ; \
	else \
		echo FAILED ; \
	fi

