AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = -L.. -levent
CPPFPLAGS = -I.. 
CFLAGS = -I../compat

noinst_PROGRAMS = test-eof test-weof test-time

test_eof_sources = test-eof.c
test_weof_sources = test-weof.c
test_time_sources = test-time.c

DISTCLEANFILES = *~

all:	test

test: $(noinst_PROGRAMS)
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

