AUTOMAKE_OPTIONS = foreign no-dependencies

LDADD = ../libevent.la
AM_CFLAGS = -I$(top_srcdir) -I$(top_srcdir)/compat -I$(top_srcdir)/include -I../include

noinst_PROGRAMS = event-test time-test signal-test dns-example hello-world http-server

event_test_sources = event-test.c
time_test_sources = time-test.c
signal_test_sources = signal-test.c
dns_example_sources = dns-example.c
hello_world_sources = hello-world.c
http_server_sources = http-server.c

if OPENSSL
noinst_PROGRAMS += le-proxy
le_proxy_sources = le-proxy.c
le_proxy_LDADD = $(LDADD) ../libevent_openssl.la -lcrypto -lssl
endif

verify:

DISTCLEANFILES = *~
