/*
 * Copyright (c) 2009 Nick Mathewson and Niels Provos
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#endif

#include "event-config.h"

#include <sys/types.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#ifdef _EVENT_HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event2/event.h"
#include "event2/util.h"
#include "../ipv6-internal.h"
#include "../util-internal.h"
#include "../log-internal.h"
#include "../strlcpy-internal.h"

#include "regress.h"

enum entry_status { NORMAL, CANONICAL, BAD };

/* This is a big table of results we expect from generating and parsing */
static struct ipv4_entry {
	const char *addr;
	ev_uint32_t res;
	enum entry_status status;
} ipv4_entries[] = {
	{ "1.2.3.4", 0x01020304u, CANONICAL },
	{ "255.255.255.255", 0xffffffffu, CANONICAL },
	{ "256.0.0.0", 0, BAD },
	{ "ABC", 0, BAD },
	{ "1.2.3.4.5", 0, BAD },
	{ "176.192.208.244", 0xb0c0d0f4, CANONICAL },
	{ NULL, 0, BAD },
};

static struct ipv6_entry {
	const char *addr;
	ev_uint32_t res[4];
	enum entry_status status;
} ipv6_entries[] = {
	{ "::", { 0, 0, 0, 0, }, CANONICAL },
	{ "0:0:0:0:0:0:0:0", { 0, 0, 0, 0, }, NORMAL },
	{ "::1", { 0, 0, 0, 1, }, CANONICAL },
	{ "::1.2.3.4", { 0, 0, 0, 0x01020304, }, CANONICAL },
	{ "ffff:1::", { 0xffff0001u, 0, 0, 0, }, CANONICAL },
	{ "ffff:0000::", { 0xffff0000u, 0, 0, 0, }, NORMAL },
	{ "ffff::1234", { 0xffff0000u, 0, 0, 0x1234, }, CANONICAL },
	{ "0102::1.2.3.4", {0x01020000u, 0, 0, 0x01020304u }, NORMAL },
	{ "::9:c0a8:1:1", { 0, 0, 0x0009c0a8u, 0x00010001u }, CANONICAL },
	{ "::ffff:1.2.3.4", { 0, 0, 0x000ffffu, 0x01020304u }, CANONICAL },
	{ "FFFF::", { 0xffff0000u, 0, 0, 0 }, NORMAL },
	{ "foobar.", { 0, 0, 0, 0 }, BAD },
	{ "foobar", { 0, 0, 0, 0 }, BAD },
	{ "fo:obar", { 0, 0, 0, 0 }, BAD },
	{ "ffff", { 0, 0, 0, 0 }, BAD },
	{ "fffff::", { 0, 0, 0, 0 }, BAD },
	{ "fffff::", { 0, 0, 0, 0 }, BAD },
        { "::1.0.1.1000", { 0, 0, 0, 0 }, BAD },
	{ "1:2:33333:4::", { 0, 0, 0, 0 }, BAD },
	{ "1:2:3:4:5:6:7:8:9", { 0, 0, 0, 0 }, BAD },
	{ "1::2::3", { 0, 0, 0, 0 }, BAD },
	{ ":::1", { 0, 0, 0, 0 }, BAD },
	{ NULL, { 0, 0, 0, 0,  }, BAD },
};

static void
regress_ipv4_parse(void *ptr)
{
	int i;
	for (i = 0; ipv4_entries[i].addr; ++i) {
		char written[128];
		struct ipv4_entry *ent = &ipv4_entries[i];
		struct in_addr in;
		int r;
		r = evutil_inet_pton(AF_INET, ent->addr, &in);
		if (r == 0) {
			if (ent->status != BAD) {
				TT_FAIL(("%s did not parse, but it's a good address!",
					ent->addr));
			}
			continue;
		}
		if (ent->status == BAD) {
			TT_FAIL(("%s parsed, but we expected an error", ent->addr));
			continue;
		}
		if (ntohl(in.s_addr) != ent->res) {
			TT_FAIL(("%s parsed to %lx, but we expected %lx", ent->addr,
				(unsigned long)ntohl(in.s_addr),
				(unsigned long)ent->res));
			continue;
		}
		if (ent->status == CANONICAL) {
			const char *w = evutil_inet_ntop(AF_INET, &in, written,
											 sizeof(written));
			if (!w) {
				TT_FAIL(("Tried to write out %s; got NULL.", ent->addr));
				continue;
			}
			if (strcmp(written, ent->addr)) {
				TT_FAIL(("Tried to write out %s; got %s",
					ent->addr, written));
				continue;
			}
		}

	}

}

static void
regress_ipv6_parse(void *ptr)
{
#ifdef AF_INET6
	int i, j;

	for (i = 0; ipv6_entries[i].addr; ++i) {
		char written[128];
		struct ipv6_entry *ent = &ipv6_entries[i];
		struct in6_addr in6;
		int r;
		r = evutil_inet_pton(AF_INET6, ent->addr, &in6);
		if (r == 0) {
			if (ent->status != BAD)
				TT_FAIL(("%s did not parse, but it's a good address!",
					ent->addr));
			continue;
		}
		if (ent->status == BAD) {
			TT_FAIL(("%s parsed, but we expected an error", ent->addr));
			continue;
		}
		for (j = 0; j < 4; ++j) {
			/* Can't use s6_addr32 here; some don't have it. */
			ev_uint32_t u =
				(in6.s6_addr[j*4  ] << 24) |
				(in6.s6_addr[j*4+1] << 16) |
				(in6.s6_addr[j*4+2] << 8) |
				(in6.s6_addr[j*4+3]);
			if (u != ent->res[j]) {
				TT_FAIL(("%s did not parse as expected.", ent->addr));
				continue;
			}
		}
		if (ent->status == CANONICAL) {
			const char *w = evutil_inet_ntop(AF_INET6, &in6, written,
											 sizeof(written));
			if (!w) {
				TT_FAIL(("Tried to write out %s; got NULL.", ent->addr));
				continue;
			}
			if (strcmp(written, ent->addr)) {
				TT_FAIL(("Tried to write out %s; got %s", ent->addr, written));
				continue;
			}
		}

	}
#else
	TT_BLATHER(("Skipping IPv6 address parsing."));
#endif
}

static struct sa_port_ent {
	const char *parse;
	int sa_family;
	const char *addr;
	int port;
} sa_port_ents[] = {
	{ "[ffff::1]:1000", AF_INET6, "ffff::1", 1000 },
	{ "[ffff::1]", AF_INET6, "ffff::1", 0 },
	{ "[ffff::1", 0, NULL, 0 },
	{ "[ffff::1]:65599", 0, NULL, 0 },
	{ "[ffff::1]:0", 0, NULL, 0 },
	{ "[ffff::1]:-1", 0, NULL, 0 },
	{ "::1", AF_INET6, "::1", 0 },
	{ "1:2::1", AF_INET6, "1:2::1", 0 },
	{ "192.168.0.1:50", AF_INET, "192.168.0.1", 50 },
	{ "1.2.3.4", AF_INET, "1.2.3.4", 0 },
	{ NULL, 0, NULL, 0 },
};

static void
regress_sockaddr_port_parse(void *ptr)
{
	struct sockaddr_storage ss;
	int i, r;

	for (i = 0; sa_port_ents[i].parse; ++i) {
		struct sa_port_ent *ent = &sa_port_ents[i];
                int len = sizeof(ss);
		memset(&ss, 0, sizeof(ss));
		r = evutil_parse_sockaddr_port(ent->parse, (struct sockaddr*)&ss, &len);
		if (r < 0) {
			if (ent->sa_family)
				TT_FAIL(("Couldn't parse %s!", ent->parse));
			continue;
		} else if (! ent->sa_family) {
			TT_FAIL(("Shouldn't have been able to parse %s!", ent->parse));
			continue;
		}
		if (ent->sa_family == AF_INET) {
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
#ifdef _EVENT_HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sin.sin_len = sizeof(sin);
#endif
			sin.sin_family = AF_INET;
			sin.sin_port = htons(ent->port);
			r = evutil_inet_pton(AF_INET, ent->addr, &sin.sin_addr);
                        if (1 != r) {
				TT_FAIL(("Couldn't parse ipv4 target %s.", ent->addr));
			} else if (memcmp(&sin, &ss, sizeof(sin))) {
				TT_FAIL(("Parse for %s was not as expected.", ent->parse));
			} else if (len != sizeof(sin)) {
                                TT_FAIL(("Length for %s not as expected.",ent->parse));
                        }
		} else {
			struct sockaddr_in6 sin6;
			memset(&sin6, 0, sizeof(sin6));
#ifdef _EVENT_HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
			sin6.sin6_len = sizeof(sin6);
#endif
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = htons(ent->port);
			r = evutil_inet_pton(AF_INET6, ent->addr, &sin6.sin6_addr);
			if (1 != r) {
				TT_FAIL(("Couldn't parse ipv6 target %s.", ent->addr));
			} else if (memcmp(&sin6, &ss, sizeof(sin6))) {
				TT_FAIL(("Parse for %s was not as expected.", ent->parse));
			} else if (len != sizeof(sin6)) {
                                TT_FAIL(("Length for %s not as expected.",ent->parse));
			}
		}
	}
}

static void
test_evutil_strtoll(void *ptr)
{
        const char *s;
        char *endptr;

        tt_want(evutil_strtoll("5000000000", NULL, 10) ==
		((ev_int64_t)5000000)*1000);
        tt_want(evutil_strtoll("-5000000000", NULL, 10) ==
		((ev_int64_t)5000000)*-1000);
	s = " 99999stuff";
	tt_want(evutil_strtoll(s, &endptr, 10) == (ev_int64_t)99999);
	tt_want(endptr == s+6);
	tt_want(evutil_strtoll("foo", NULL, 10) == 0);
 }

static void
test_evutil_snprintf(void *ptr)
{
	char buf[16];
	int r;
	r = evutil_snprintf(buf, sizeof(buf), "%d %d", 50, 100);
        tt_str_op(buf, ==, "50 100");
        tt_int_op(r, ==, 6);

	r = evutil_snprintf(buf, sizeof(buf), "longish %d", 1234567890);
        tt_str_op(buf, ==, "longish 1234567");
        tt_int_op(r, ==, 18);

      end:
	;
}

static void
test_evutil_casecmp(void *ptr)
{
	tt_int_op(evutil_ascii_strcasecmp("ABC", "ABC"), ==, 0);
	tt_int_op(evutil_ascii_strcasecmp("ABC", "abc"), ==, 0);
	tt_int_op(evutil_ascii_strcasecmp("ABC", "abcd"), <, 0);
	tt_int_op(evutil_ascii_strcasecmp("ABC", "abb"), >, 0);
	tt_int_op(evutil_ascii_strcasecmp("ABCd", "abc"), >, 0);

	tt_int_op(evutil_ascii_strncasecmp("Libevent", "LibEvEnT", 100), ==, 0);
	tt_int_op(evutil_ascii_strncasecmp("Libevent", "LibEvEnT", 4), ==, 0);
	tt_int_op(evutil_ascii_strncasecmp("Libevent", "LibEXXXX", 4), ==, 0);
	tt_int_op(evutil_ascii_strncasecmp("Libevent", "LibE", 4), ==, 0);
	tt_int_op(evutil_ascii_strncasecmp("Libe", "LibEvEnT", 4), ==, 0);
	tt_int_op(evutil_ascii_strncasecmp("Lib", "LibEvEnT", 4), <, 0);
	tt_int_op(evutil_ascii_strncasecmp("abc", "def", 99), <, 0);
	tt_int_op(evutil_ascii_strncasecmp("Z", "qrst", 1), >, 0);
end:
	;
}

static int logsev = 0;
static char *logmsg = NULL;

static void
logfn(int severity, const char *msg)
{
	logsev = severity;
	tt_want(msg);
	if (msg)
		logmsg = strdup(msg);
}

static int exited = 0;
static int exitcode = 0;
static void
fatalfn(int c)
{
	exited = 1;
	exitcode = c;
}

static void
test_evutil_log(void *ptr)
{
	evutil_socket_t fd = -1;
	char buf[128];

	event_set_log_callback(logfn);
	event_set_fatal_callback(fatalfn);
#define RESET() do {				\
		logsev = exited = exitcode = 0;	\
		if (logmsg) free(logmsg);	\
		logmsg = NULL;			\
	} while (0)
#define LOGEQ(sev,msg) do {			\
		tt_int_op(logsev,==,sev);	\
		tt_assert(logmsg != NULL);	\
		tt_str_op(logmsg,==,msg);	\
	} while (0)

	event_errx(2, "Fatal error; too many kumquats (%d)", 5);
	LOGEQ(_EVENT_LOG_ERR, "Fatal error; too many kumquats (5)");
	tt_int_op(exitcode,==,2);
	RESET();

	event_warnx("Far too many %s (%d)", "wombats", 99);
	LOGEQ(_EVENT_LOG_WARN, "Far too many wombats (99)");
	tt_int_op(exited,==,0);
	RESET();

	event_msgx("Connecting lime to coconut");
	LOGEQ(_EVENT_LOG_MSG, "Connecting lime to coconut");
	tt_int_op(exited,==,0);
	RESET();

	event_debug(("A millisecond passed!  We should log that!"));
#ifdef USE_DEBUG
	LOGEQ(_EVENT_LOG_DEBUG, "A millisecond passed!  We should log that!");
#else
	tt_int_op(logsev,==,0);
	tt_ptr_op(logmsg,==,NULL);
#endif
	RESET();

	/* Try with an errno. */
	errno = ENOENT;
	event_warn("Couldn't open %s", "/bad/file");
	evutil_snprintf(buf, sizeof(buf),
	    "Couldn't open /bad/file: %s",strerror(ENOENT));
	LOGEQ(_EVENT_LOG_WARN,buf);
	tt_int_op(exited, ==, 0);
	RESET();

	errno = ENOENT;
	event_err(5,"Couldn't open %s", "/very/bad/file");
	evutil_snprintf(buf, sizeof(buf),
	    "Couldn't open /very/bad/file: %s",strerror(ENOENT));
	LOGEQ(_EVENT_LOG_ERR,buf);
	tt_int_op(exitcode, ==, 5);
	RESET();

	/* Try with a socket errno. */
	fd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef WIN32
	evutil_snprintf(buf, sizeof(buf),
	    "Unhappy socket: %s",
	    evutil_socket_error_to_string(WSAEWOULDBLOCK));
	EVUTIL_SET_SOCKET_ERROR(WSAEWOULDBLOCK);
#else
	evutil_snprintf(buf, sizeof(buf),
	    "Unhappy socket: %s", strerror(EAGAIN));
	errno = EAGAIN;
#endif
	event_sock_warn(fd, "Unhappy socket");
	LOGEQ(_EVENT_LOG_WARN, buf);
	tt_int_op(exited,==,0);
	RESET();

#ifdef WIN32
	EVUTIL_SET_SOCKET_ERROR(WSAEWOULDBLOCK);
#else
	errno = EAGAIN;
#endif
	event_sock_err(200, fd, "Unhappy socket");
	LOGEQ(_EVENT_LOG_ERR, buf);
	tt_int_op(exitcode,==,200);
	RESET();

#undef RESET
#undef LOGEQ
end:
	if (logmsg)
		free(logmsg);
	if (fd >= 0)
		EVUTIL_CLOSESOCKET(fd);
}

static void
test_evutil_strlcpy(void *arg)
{
	char buf[8];

	/* Successful case. */
	tt_int_op(5, ==, strlcpy(buf, "Hello", sizeof(buf)));
	tt_str_op(buf, ==, "Hello");

	/* Overflow by a lot. */
	tt_int_op(13, ==, strlcpy(buf, "pentasyllabic", sizeof(buf)));
	tt_str_op(buf, ==, "pentasy");

	/* Overflow by exactly one. */
	tt_int_op(8, ==, strlcpy(buf, "overlong", sizeof(buf)));
	tt_str_op(buf, ==, "overlon");
end:
	;
}

struct example_struct {
	long a;
	const char *b;
	long c;
};

static void
test_evutil_upcast(void *arg)
{
	struct example_struct es1;
	const char **cp;
	es1.a = 5;
	es1.b = "Hello";
	es1.c = -99;

	tt_int_op(evutil_offsetof(struct example_struct, b), ==, sizeof(long));

	cp = &es1.b;
	tt_ptr_op(EVUTIL_UPCAST(cp, struct example_struct, b), ==, &es1);

end:
	;

}

struct evutil_addrinfo *
ai_find_by_family(struct evutil_addrinfo *ai, int family)
{
	while (ai) {
		if (ai->ai_family == family)
			return ai;
		ai = ai->ai_next;
	}
	return NULL;
}

struct evutil_addrinfo *
ai_find_by_protocol(struct evutil_addrinfo *ai, int protocol)
{
	while (ai) {
		if (ai->ai_protocol == protocol)
			return ai;
		ai = ai->ai_next;
	}
	return NULL;
}


int
_test_ai_eq(const struct evutil_addrinfo *ai, const char *sockaddr_port,
    int socktype, int protocol, int line)
{
	struct sockaddr_storage ss;
        int slen = sizeof(ss);
	int gotport;
	char buf[128];
	memset(&ss, 0, sizeof(ss));
	if (socktype > 0)
		tt_int_op(ai->ai_socktype, ==, socktype);
	if (protocol > 0)
		tt_int_op(ai->ai_protocol, ==, protocol);

	if (evutil_parse_sockaddr_port(
		    sockaddr_port, (struct sockaddr*)&ss, &slen)<0) {
		TT_FAIL(("Couldn't parse expected address %s on line %d",
			sockaddr_port, line));
		return -1;
	}
	if (ai->ai_family != ss.ss_family) {
		TT_FAIL(("Address family %d did not match %d on line %d",
			ai->ai_family, ss.ss_family, line));
		return -1;
	}
	if (ai->ai_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in*)ai->ai_addr;
		evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
		gotport = ntohs(sin->sin_port);
		if (ai->ai_addrlen != sizeof(struct sockaddr_in)) {
			TT_FAIL(("Addr size mismatch on line %d", line));
			return -1;
		}
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)ai->ai_addr;
		evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
		gotport = ntohs(sin6->sin6_port);
		if (ai->ai_addrlen != sizeof(struct sockaddr_in6)) {
			TT_FAIL(("Addr size mismatch on line %d", line));
			return -1;
		}
	}
	if (evutil_sockaddr_cmp(ai->ai_addr, (struct sockaddr*)&ss, 1)) {
		TT_FAIL(("Wanted %s, got %s:%d on line %d", sockaddr_port,
			buf, gotport, line));
		return -1;
	} else {
		TT_BLATHER(("Wanted %s, got %s:%d on line %d", sockaddr_port,
			buf, gotport, line));
	}
	return 0;
end:
	TT_FAIL(("Test failed on line %d", line));
	return -1;
}

static void
test_evutil_getaddrinfo(void *arg)
{
	struct evutil_addrinfo *ai = NULL, *a;
	struct evutil_addrinfo hints;

	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	char buf[128];
	const char *cp;
	int r;

	/* Try using it as a pton. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	r = evutil_getaddrinfo("1.2.3.4", "8080", &hints, &ai);
	tt_int_op(r, ==, 0);
	tt_assert(ai);
	tt_ptr_op(ai->ai_next, ==, NULL); /* no ambiguity */
	test_ai_eq(ai, "1.2.3.4:8080", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_protocol = IPPROTO_UDP;
	r = evutil_getaddrinfo("1001:b0b::f00f", "4321", &hints, &ai);
	tt_int_op(r, ==, 0);
	tt_assert(ai);
	tt_ptr_op(ai->ai_next, ==, NULL); /* no ambiguity */
	test_ai_eq(ai, "[1001:b0b::f00f]:4321", SOCK_DGRAM, IPPROTO_UDP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	/* Try out the behavior of nodename=NULL */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = EVUTIL_AI_PASSIVE; /* as if for bind */
	r = evutil_getaddrinfo(NULL, "9999", &hints, &ai);
	tt_int_op(r,==,0);
	tt_assert(ai);
	tt_ptr_op(ai->ai_next, ==, NULL);
	test_ai_eq(ai, "0.0.0.0:9999", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(ai);
	ai = NULL;
	hints.ai_flags = 0; /* as if for connect */
	r = evutil_getaddrinfo(NULL, "9998", &hints, &ai);
	tt_assert(ai);
	tt_int_op(r,==,0);
	test_ai_eq(ai, "127.0.0.1:9998", SOCK_STREAM, IPPROTO_TCP);
	tt_ptr_op(ai->ai_next, ==, NULL);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	hints.ai_flags = 0; /* as if for connect */
	hints.ai_family = PF_INET6;
	r = evutil_getaddrinfo(NULL, "9997", &hints, &ai);
	tt_assert(ai);
	tt_int_op(r,==,0);
	tt_ptr_op(ai->ai_next, ==, NULL);
	test_ai_eq(ai, "[::1]:9997", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	hints.ai_flags = EVUTIL_AI_PASSIVE; /* as if for bind. */
	hints.ai_family = PF_INET6;
	r = evutil_getaddrinfo(NULL, "9996", &hints, &ai);
	tt_assert(ai);
	tt_int_op(r,==,0);
	tt_ptr_op(ai->ai_next, ==, NULL);
	test_ai_eq(ai, "[::]:9996", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	/* Now try an unspec one. We should get a v6 and a v4. */
	hints.ai_family = PF_UNSPEC;
	r = evutil_getaddrinfo(NULL, "9996", &hints, &ai);
	tt_assert(ai);
	tt_int_op(r,==,0);
	a = ai_find_by_family(ai, PF_INET6);
	tt_assert(a);
	test_ai_eq(a, "[::]:9996", SOCK_STREAM, IPPROTO_TCP);
	a = ai_find_by_family(ai, PF_INET);
	tt_assert(a);
	test_ai_eq(a, "0.0.0.0:9996", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	/* Try out AI_NUMERICHOST: successful case.  Also try
	 * multiprotocol. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = EVUTIL_AI_NUMERICHOST;
	r = evutil_getaddrinfo("1.2.3.4", NULL, &hints, &ai);
	tt_int_op(r, ==, 0);
	a = ai_find_by_protocol(ai, IPPROTO_TCP);
	tt_assert(a);
	test_ai_eq(a, "1.2.3.4", SOCK_STREAM, IPPROTO_TCP);
	a = ai_find_by_protocol(ai, IPPROTO_UDP);
	tt_assert(a);
	test_ai_eq(a, "1.2.3.4", SOCK_DGRAM, IPPROTO_UDP);
	evutil_freeaddrinfo(ai);
	ai = NULL;

	/* Try the failing case of AI_NUMERICHOST */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = EVUTIL_AI_NUMERICHOST;
	r = evutil_getaddrinfo("www.google.com", "80", &hints, &ai);
	tt_int_op(r, ==, EVUTIL_EAI_NONAME);
	tt_int_op(ai, ==, NULL);

	/* Try symbolic service names wit AI_NUMERICSERV */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = EVUTIL_AI_NUMERICSERV;
	r = evutil_getaddrinfo("1.2.3.4", "http", &hints, &ai);
	tt_int_op(r,==,EVUTIL_EAI_NONAME);

	/* Try symbolic service names */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	r = evutil_getaddrinfo("1.2.3.4", "http", &hints, &ai);
	if (r!=0) {
		TT_GRIPE(("Symbolic service names seem broken."));
	} else {
		tt_assert(ai);
		test_ai_eq(ai, "1.2.3.4:80", SOCK_STREAM, IPPROTO_TCP);
		evutil_freeaddrinfo(ai);
		ai = NULL;
	}

	/* Now do some actual lookups. */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	r = evutil_getaddrinfo("www.google.com", "80", &hints, &ai);
	if (r != 0) {
		TT_GRIPE(("Couldn't resolve www.google.com"));
	} else {
		tt_assert(ai);
		tt_int_op(ai->ai_family, ==, PF_INET);
		tt_int_op(ai->ai_protocol, ==, IPPROTO_TCP);
		tt_int_op(ai->ai_socktype, ==, SOCK_STREAM);
		tt_int_op(ai->ai_addrlen, ==, sizeof(struct sockaddr_in));
		sin = (struct sockaddr_in*)ai->ai_addr;
		tt_int_op(sin->sin_family, ==, AF_INET);
		tt_int_op(sin->sin_port, ==, htons(80));
		tt_int_op(sin->sin_addr.s_addr, !=, 0xffffffff);

		cp = evutil_inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
		TT_BLATHER(("www.google.com resolved to %s",
			cp?cp:"<unwriteable>"));
		evutil_freeaddrinfo(ai);
		ai = NULL;
	}

	hints.ai_family = PF_INET6;
	r = evutil_getaddrinfo("ipv6.google.com", "80", &hints, &ai);
	if (r != 0) {
		TT_BLATHER(("Couldn't do an ipv6 lookup for ipv6.google.com"));
	} else {
		tt_assert(ai);
		tt_int_op(ai->ai_family, ==, PF_INET6);
		tt_int_op(ai->ai_addrlen, ==, sizeof(struct sockaddr_in6));
		sin6 = (struct sockaddr_in6*)ai->ai_addr;
		tt_int_op(sin6->sin6_port, ==, htons(80));

		cp = evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, buf,
		    sizeof(buf));
		TT_BLATHER(("ipv6.google.com resolved to %s",
			cp?cp:"<unwriteable>"));
	}

end:
	if (ai)
		evutil_freeaddrinfo(ai);
}

struct testcase_t util_testcases[] = {
	{ "ipv4_parse", regress_ipv4_parse, 0, NULL, NULL },
	{ "ipv6_parse", regress_ipv6_parse, 0, NULL, NULL },
	{ "sockaddr_port_parse", regress_sockaddr_port_parse, 0, NULL, NULL },
	{ "evutil_snprintf", test_evutil_snprintf, 0, NULL, NULL },
	{ "evutil_strtoll", test_evutil_strtoll, 0, NULL, NULL },
	{ "evutil_casecmp", test_evutil_casecmp, 0, NULL, NULL },
	{ "strlcpy", test_evutil_strlcpy, 0, NULL, NULL },
	{ "log", test_evutil_log, TT_FORK, NULL, NULL },
	{ "upcast", test_evutil_upcast, 0, NULL, NULL },
	{ "getaddrinfo", test_evutil_getaddrinfo, TT_FORK, NULL, NULL },
	END_OF_TESTCASES,
};

