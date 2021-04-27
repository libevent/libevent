/*
 * Copyright (c) 2003-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
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
#include "../util-internal.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#endif

#include "event2/event-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#ifdef EVENT__HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifdef EVENT__HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "event2/dns.h"
#include "event2/dns_compat.h"
#include "event2/dns_struct.h"
#include "event2/event.h"
#include "event2/event_compat.h"
#include "event2/event_struct.h"
#include "event2/util.h"
#include "event2/listener.h"
#include "event2/bufferevent.h"
#include <event2/thread.h>
#include "log-internal.h"
#include "evthread-internal.h"
#include "regress.h"
#include "regress_testutils.h"
#include "regress_thread.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

#define REPEAT_2(address) \
	address "," address
#define REPEAT_4(address) \
	REPEAT_2(address) "," REPEAT_2(address)
#define REPEAT_8(address) \
	REPEAT_4(address) "," REPEAT_4(address)
#define REPEAT_16(address) \
	REPEAT_8(address) "," REPEAT_8(address)
#define REPEAT_32(address) \
	REPEAT_16(address) "," REPEAT_16(address)
#define REPEAT_64(address) \
	REPEAT_32(address) "," REPEAT_32(address)
#define REPEAT_128(address) \
	REPEAT_64(address) "," REPEAT_64(address)
#define REPEAT_256(address) \
	REPEAT_128(address) "," REPEAT_128(address)

static int dns_ok = 0;
static int dns_got_cancel = 0;
static int dns_err = 0;


static void
dns_gethostbyname_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	dns_ok = dns_err = 0;

	if (result == DNS_ERR_TIMEOUT) {
		printf("[Timed out] ");
		dns_err = result;
		goto out;
	}

	if (result != DNS_ERR_NONE) {
		printf("[Error code %d] ", result);
		goto out;
	}

	TT_BLATHER(("type: %d, count: %d, ttl: %d: ", type, count, ttl));

	switch (type) {
	case DNS_IPv6_AAAA: {
#if defined(EVENT__HAVE_STRUCT_IN6_ADDR) && defined(EVENT__HAVE_INET_NTOP) && defined(INET6_ADDRSTRLEN)
		struct in6_addr *in6_addrs = addresses;
		char buf[INET6_ADDRSTRLEN+1];
		int i;
		/* a resolution that's not valid does not help */
		if (ttl < 0)
			goto out;
		for (i = 0; i < count; ++i) {
			const char *b = evutil_inet_ntop(AF_INET6, &in6_addrs[i], buf,sizeof(buf));
			if (b)
				TT_BLATHER(("%s ", b));
			else
				TT_BLATHER(("%s ", strerror(errno)));
		}
#endif
		break;
	}
	case DNS_IPv4_A: {
		struct in_addr *in_addrs = addresses;
		int i;
		/* a resolution that's not valid does not help */
		if (ttl < 0)
			goto out;
		for (i = 0; i < count; ++i)
			TT_BLATHER(("%s ", inet_ntoa(in_addrs[i])));
		break;
	}
	case DNS_PTR:
		/* may get at most one PTR */
		if (count != 1)
			goto out;

		TT_BLATHER(("%s ", *(char **)addresses));
		break;
	default:
		goto out;
	}

	dns_ok = type;

out:
	if (arg == NULL)
		event_loopexit(NULL);
	else
		event_base_loopexit((struct event_base *)arg, NULL);
}

static void
dns_gethostbyname(void)
{
	dns_ok = 0;
	evdns_resolve_ipv4("www.monkey.org", 0, dns_gethostbyname_cb, NULL);
	event_dispatch();

	tt_int_op(dns_ok, ==, DNS_IPv4_A);
	test_ok = dns_ok;
end:
	;
}

static void
dns_gethostbyname6(void)
{
	dns_ok = 0;
	evdns_resolve_ipv6("www.ietf.org", 0, dns_gethostbyname_cb, NULL);
	event_dispatch();

	if (!dns_ok && dns_err == DNS_ERR_TIMEOUT) {
		tt_skip();
	}

	tt_int_op(dns_ok, ==, DNS_IPv6_AAAA);
	test_ok = 1;
end:
	;
}

static void
dns_gethostbyaddr(void)
{
	struct in_addr in;
	in.s_addr = htonl(0x7f000001ul); /* 127.0.0.1 */
	dns_ok = 0;
	evdns_resolve_reverse(&in, 0, dns_gethostbyname_cb, NULL);
	event_dispatch();

	tt_int_op(dns_ok, ==, DNS_PTR);
	test_ok = dns_ok;
end:
	;
}

static void
dns_resolve_reverse(void *ptr)
{
	struct in_addr in;
	struct event_base *base = event_base_new();
	struct evdns_base *dns = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	struct evdns_request *req = NULL;

	tt_assert(base);
	tt_assert(dns);
	in.s_addr = htonl(0x7f000001ul); /* 127.0.0.1 */
	dns_ok = 0;

	req = evdns_base_resolve_reverse(
		dns, &in, 0, dns_gethostbyname_cb, base);
	tt_assert(req);

	event_base_dispatch(base);

	tt_int_op(dns_ok, ==, DNS_PTR);

end:
	if (dns)
		evdns_base_free(dns, 0);
	if (base)
		event_base_free(base);
}

static int n_server_responses = 0;

static void
dns_server_request_cb(struct evdns_server_request *req, void *data)
{
	int i, r;
	const char TEST_ARPA[] = "11.11.168.192.in-addr.arpa";
	const char TEST_IN6[] =
	    "f.e.f.e." "0.0.0.0." "0.0.0.0." "1.1.1.1."
	    "a.a.a.a." "0.0.0.0." "0.0.0.0." "0.f.f.f.ip6.arpa";

	for (i = 0; i < req->nquestions; ++i) {
		const int qtype = req->questions[i]->type;
		const int qclass = req->questions[i]->dns_question_class;
		const char *qname = req->questions[i]->name;

		struct in_addr ans;
		ans.s_addr = htonl(0xc0a80b0bUL); /* 192.168.11.11 */
		if (qtype == EVDNS_TYPE_A &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, "zz.example.com")) {
			r = evdns_server_request_add_a_reply(req, qname,
			    1, &ans.s_addr, 12345);
			if (r<0)
				dns_ok = 0;
		} else if (qtype == EVDNS_TYPE_AAAA &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, "zz.example.com")) {
			char addr6[17] = "abcdefghijklmnop";
			r = evdns_server_request_add_aaaa_reply(req,
			    qname, 1, addr6, 123);
			if (r<0)
				dns_ok = 0;
		} else if (qtype == EVDNS_TYPE_PTR &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, TEST_ARPA)) {
			r = evdns_server_request_add_ptr_reply(req, NULL,
			    qname, "ZZ.EXAMPLE.COM", 54321);
			if (r<0)
				dns_ok = 0;
		} else if (qtype == EVDNS_TYPE_PTR &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, TEST_IN6)){
			r = evdns_server_request_add_ptr_reply(req, NULL,
			    qname,
			    "ZZ-INET6.EXAMPLE.COM", 54322);
			if (r<0)
				dns_ok = 0;
		} else if (qtype == EVDNS_TYPE_A &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, "drop.example.com")) {
			if (evdns_server_request_drop(req)<0)
				dns_ok = 0;
			return;
		} else {
			printf("Unexpected question %d %d \"%s\" ",
			    qtype, qclass, qname);
			dns_ok = 0;
		}
	}
	r = evdns_server_request_respond(req, 0);
	if (r<0) {
		printf("Couldn't send reply. ");
		dns_ok = 0;
	}
}

static void
dns_server_gethostbyname_cb(int result, char type, int count, int ttl,
    void *addresses, void *arg)
{
	if (result == DNS_ERR_CANCEL) {
		if (arg != (void*)(char*)90909) {
			printf("Unexpected cancelation");
			dns_ok = 0;
		}
		dns_got_cancel = 1;
		goto out;
	}
	if (result != DNS_ERR_NONE) {
		printf("Unexpected result %d. ", result);
		dns_ok = 0;
		goto out;
	}
	if (count != 1) {
		printf("Unexpected answer count %d. ", count);
		dns_ok = 0;
		goto out;
	}
	switch (type) {
	case DNS_IPv4_A: {
		struct in_addr *in_addrs = addresses;
		if (in_addrs[0].s_addr != htonl(0xc0a80b0bUL) || ttl != 12345) {
			printf("Bad IPv4 response \"%s\" %d. ",
					inet_ntoa(in_addrs[0]), ttl);
			dns_ok = 0;
			goto out;
		}
		break;
	}
	case DNS_IPv6_AAAA: {
#if defined (EVENT__HAVE_STRUCT_IN6_ADDR) && defined(EVENT__HAVE_INET_NTOP) && defined(INET6_ADDRSTRLEN)
		struct in6_addr *in6_addrs = addresses;
		char buf[INET6_ADDRSTRLEN+1];
		if (memcmp(&in6_addrs[0].s6_addr, "abcdefghijklmnop", 16)
		    || ttl != 123) {
			const char *b = evutil_inet_ntop(AF_INET6, &in6_addrs[0],buf,sizeof(buf));
			printf("Bad IPv6 response \"%s\" %d. ", b, ttl);
			dns_ok = 0;
			goto out;
		}
#endif
		break;
	}
	case DNS_PTR: {
		char **addrs = addresses;
		if (arg != (void*)6) {
			if (strcmp(addrs[0], "ZZ.EXAMPLE.COM") ||
			    ttl != 54321) {
				printf("Bad PTR response \"%s\" %d. ",
				    addrs[0], ttl);
				dns_ok = 0;
				goto out;
			}
		} else {
			if (strcmp(addrs[0], "ZZ-INET6.EXAMPLE.COM") ||
			    ttl != 54322) {
				printf("Bad ipv6 PTR response \"%s\" %d. ",
				    addrs[0], ttl);
				dns_ok = 0;
				goto out;
			}
		}
		break;
	}
	default:
		printf("Bad response type %d. ", type);
		dns_ok = 0;
	}
 out:
	if (++n_server_responses == 3) {
		event_loopexit(NULL);
	}
}

static void
dns_server(void)
{
	evutil_socket_t sock=-1;
	struct sockaddr_in my_addr;
	struct sockaddr_storage ss;
	ev_socklen_t slen;
	struct evdns_server_port *port=NULL;
	struct in_addr resolve_addr;
	struct in6_addr resolve_addr6;
	struct evdns_base *base=NULL;
	struct evdns_request *req=NULL;

	dns_ok = 1;

	base = evdns_base_new(NULL, 0);

	/* Now configure a nameserver port. */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock<0) {
		tt_abort_perror("socket");
	}

	evutil_make_socket_nonblocking(sock);

	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = 0; /* kernel picks */
	my_addr.sin_addr.s_addr = htonl(0x7f000001UL);
	if (bind(sock, (struct sockaddr*)&my_addr, sizeof(my_addr)) < 0) {
		tt_abort_perror("bind");
	}
	slen = sizeof(ss);
	if (getsockname(sock, (struct sockaddr*)&ss, &slen) < 0) {
		tt_abort_perror("getsockname");
	}

	port = evdns_add_server_port(sock, 0, dns_server_request_cb, NULL);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evdns_base_nameserver_sockaddr_add(base, (struct sockaddr*)&ss, slen, 0);
	tt_int_op(evdns_base_count_nameservers(base), ==, 1);
	{
		struct sockaddr_storage ss2;
		int slen2;

		memset(&ss2, 0, sizeof(ss2));

		slen2 = evdns_base_get_nameserver_addr(base, 0, (struct sockaddr *)&ss2, 3);
		tt_int_op(slen2, ==, slen);
		tt_int_op(ss2.ss_family, ==, 0);
		slen2 = evdns_base_get_nameserver_addr(base, 0, (struct sockaddr *)&ss2, sizeof(ss2));
		tt_int_op(slen2, ==, slen);
		tt_mem_op(&ss2, ==, &ss, slen);

		slen2 = evdns_base_get_nameserver_addr(base, 1, (struct sockaddr *)&ss2, sizeof(ss2));
		tt_int_op(-1, ==, slen2);
	}

	/* Send some queries. */
	evdns_base_resolve_ipv4(base, "zz.example.com", DNS_QUERY_NO_SEARCH,
					   dns_server_gethostbyname_cb, NULL);
	evdns_base_resolve_ipv6(base, "zz.example.com", DNS_QUERY_NO_SEARCH,
					   dns_server_gethostbyname_cb, NULL);
	resolve_addr.s_addr = htonl(0xc0a80b0bUL); /* 192.168.11.11 */
	evdns_base_resolve_reverse(base, &resolve_addr, 0,
	    dns_server_gethostbyname_cb, NULL);
	memcpy(resolve_addr6.s6_addr,
	    "\xff\xf0\x00\x00\x00\x00\xaa\xaa"
	    "\x11\x11\x00\x00\x00\x00\xef\xef", 16);
	evdns_base_resolve_reverse_ipv6(base, &resolve_addr6, 0,
	    dns_server_gethostbyname_cb, (void*)6);

	req = evdns_base_resolve_ipv4(base,
	    "drop.example.com", DNS_QUERY_NO_SEARCH,
	    dns_server_gethostbyname_cb, (void*)(char*)90909);

	evdns_cancel_request(base, req);

	event_dispatch();

	tt_assert(dns_got_cancel);
	test_ok = dns_ok;

end:
	if (port)
		evdns_close_server_port(port);
	if (sock >= 0)
		evutil_closesocket(sock);
	if (base)
		evdns_base_free(base, 0);
}

static int n_replies_left;
static struct event_base *exit_base;
static struct evdns_server_port *exit_port;

struct generic_dns_callback_result {
	int result;
	char type;
	int count;
	int ttl;
	size_t addrs_len;
	void *addrs;
	char addrs_buf[4096];
};

static void
generic_dns_callback(int result, char type, int count, int ttl, void *addresses,
    void *arg)
{
	size_t len;
	struct generic_dns_callback_result *res = arg;
	res->result = result;
	res->type = type;
	res->count = count;
	res->ttl = ttl;

	if (type == DNS_IPv4_A)
		len = count * 4;
	else if (type == DNS_IPv6_AAAA)
		len = count * 16;
	else if (type == DNS_PTR)
		len = strlen(addresses)+1;
	else {
		res->addrs_len = len = 0;
		res->addrs = NULL;
	}
	if (len) {
		res->addrs_len = len;
		if (len > ARRAY_SIZE(res->addrs_buf))
			len = ARRAY_SIZE(res->addrs_buf);
		memcpy(res->addrs_buf, addresses, len);
		res->addrs = res->addrs_buf;
	}

	--n_replies_left;
	if (n_replies_left == 0) {
		if (exit_port) {
			evdns_close_server_port(exit_port);
			exit_port = NULL;
		} else
			event_base_loopexit(exit_base, NULL);
	}
}

static struct regress_dns_server_table search_table[] = {
	{ "small.a.example.com", "A", REPEAT_64("11.22.33.45"), 0, 0},
	{ "medium.b.example.com", "A", REPEAT_64("11.22.33.45") "," REPEAT_64("12.22.33.45"), 0, 0},
	{ "large.c.example.com", "A",
		REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"), 0, 0},
	{ "lost.request.com", "err", "67", 0, 0},
	{ "host.a.example.com", "err", "3", 0, 0 },
	{ "host.b.example.com", "err", "3", 0, 0 },
	{ "host.c.example.com", "A", "11.22.33.44", 0, 0 },
	{ "host2.a.example.com", "err", "3", 0, 0 },
	{ "host2.b.example.com", "A", "200.100.0.100", 0, 0 },
	{ "host2.c.example.com", "err", "3", 0, 0 },
	{ "hostn.a.example.com", "errsoa", "0", 0, 0 },
	{ "hostn.b.example.com", "errsoa", "3", 0, 0 },
	{ "hostn.c.example.com", "err", "0", 0, 0 },
	{ "host", "err", "3", 0, 0 },
	{ "host2", "err", "3", 0, 0 },
	{ "*", "err", "3", 0, 0 },
	{ NULL, NULL, NULL, 0, 0 }
};

static struct regress_dns_server_table tcp_search_table[] = {
	{ "small.a.example.com", "A", REPEAT_64("11.22.33.45"), 0, 0},
	{ "medium.b.example.com", "A", REPEAT_64("11.22.33.45") "," REPEAT_64("12.22.33.45"), 0, 0},
	{ "large.c.example.com", "A",
		REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"), 0, 0},
	{ "lost.request.com", "err", "67", 0, 0},
	{ NULL, NULL, NULL, 0, 0 }
};

#define assert_request_results(r, exp_result, exp_addresses) \
	do { \
		k_ = parse_csv_address_list(exp_addresses, AF_INET, addrs, ARRAY_SIZE(addrs)); \
		tt_int_op(r.result, ==, exp_result); \
		tt_int_op(r.type, ==, DNS_IPv4_A); \
		tt_int_op(r.count, ==, k_); \
		for (k_ = 0; k_ < r.count; ++k_) \
			tt_int_op(((ev_uint32_t *)r.addrs)[k_], ==, addrs[k_].s_addr); \
	} while (0)

static void
dns_search_test_impl(void *arg, int lower)
{
	struct regress_dns_server_table table[ARRAY_SIZE(search_table)];
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];

	struct generic_dns_callback_result r[8];
	size_t i;

	for (i = 0; i < ARRAY_SIZE(table); ++i) {
		table[i] = search_table[i];
		table[i].lower = lower;
	}

	tt_assert(regress_dnsserver(base, &portnum, table, NULL));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, 0);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	evdns_base_search_add(dns, "a.example.com");
	evdns_base_search_add(dns, "b.example.com");
	evdns_base_search_add(dns, "c.example.com");

	n_replies_left = ARRAY_SIZE(r);
	exit_base = base;

	evdns_base_resolve_ipv4(dns, "host", 0, generic_dns_callback, &r[0]);
	evdns_base_resolve_ipv4(dns, "host2", 0, generic_dns_callback, &r[1]);
	evdns_base_resolve_ipv4(dns, "host", DNS_NO_SEARCH, generic_dns_callback, &r[2]);
	evdns_base_resolve_ipv4(dns, "host2", DNS_NO_SEARCH, generic_dns_callback, &r[3]);
	evdns_base_resolve_ipv4(dns, "host3", 0, generic_dns_callback, &r[4]);
	evdns_base_resolve_ipv4(dns, "hostn.a.example.com", DNS_NO_SEARCH, generic_dns_callback, &r[5]);
	evdns_base_resolve_ipv4(dns, "hostn.b.example.com", DNS_NO_SEARCH, generic_dns_callback, &r[6]);
	evdns_base_resolve_ipv4(dns, "hostn.c.example.com", DNS_NO_SEARCH, generic_dns_callback, &r[7]);

	event_base_dispatch(base);

	tt_int_op(r[0].type, ==, DNS_IPv4_A);
	tt_int_op(r[0].count, ==, 1);
	tt_int_op(((ev_uint32_t*)r[0].addrs)[0], ==, htonl(0x0b16212c));
	tt_int_op(r[1].type, ==, DNS_IPv4_A);
	tt_int_op(r[1].count, ==, 1);
	tt_int_op(((ev_uint32_t*)r[1].addrs)[0], ==, htonl(0xc8640064));
	tt_int_op(r[2].result, ==, DNS_ERR_NOTEXIST);
	tt_int_op(r[3].result, ==, DNS_ERR_NOTEXIST);
	tt_int_op(r[4].result, ==, DNS_ERR_NOTEXIST);
	tt_int_op(r[5].result, ==, DNS_ERR_NODATA);
	tt_int_op(r[5].ttl, ==, 42);
	tt_int_op(r[6].result, ==, DNS_ERR_NOTEXIST);
	tt_int_op(r[6].ttl, ==, 42);
	tt_int_op(r[7].result, ==, DNS_ERR_NODATA);
	tt_int_op(r[7].ttl, ==, 0);

end:
	if (dns)
		evdns_base_free(dns, 0);

	regress_clean_dnsserver();
}
static void
dns_search_empty_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;

	dns = evdns_base_new(base, 0);

	evdns_base_search_add(dns, "whatever.example.com");

	n_replies_left = 1;
	exit_base = base;

	tt_ptr_op(evdns_base_resolve_ipv4(dns, "", 0, generic_dns_callback, NULL), ==, NULL);

end:
	if (dns)
		evdns_base_free(dns, 0);
}
static void dns_search_test(void *arg) { dns_search_test_impl(arg, 0); }
static void dns_search_lower_test(void *arg) { dns_search_test_impl(arg, 1); }

static int request_count = 0;
static struct evdns_request *current_req = NULL;

static void
search_cancel_server_cb(struct evdns_server_request *req, void *data)
{
	const char *question;

	if (req->nquestions != 1)
		TT_DIE(("Only handling one question at a time; got %d",
			req->nquestions));

	question = req->questions[0]->name;

	TT_BLATHER(("got question, %s", question));

	tt_assert(request_count > 0);
	tt_assert(!evdns_server_request_respond(req, 3));

	if (!--request_count)
		evdns_cancel_request(NULL, current_req);

end:
	;
}

static void
dns_search_cancel_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	struct evdns_server_port *port = NULL;
	ev_uint16_t portnum = 0;
	struct generic_dns_callback_result r1;
	char buf[64];

	port = regress_get_udp_dnsserver(base, &portnum, NULL,
	    search_cancel_server_cb, NULL);
	tt_assert(port);
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, 0);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	evdns_base_search_add(dns, "a.example.com");
	evdns_base_search_add(dns, "b.example.com");
	evdns_base_search_add(dns, "c.example.com");
	evdns_base_search_add(dns, "d.example.com");

	exit_base = base;
	request_count = 3;
	n_replies_left = 1;

	current_req = evdns_base_resolve_ipv4(dns, "host", 0,
					generic_dns_callback, &r1);
	event_base_dispatch(base);

	tt_int_op(r1.result, ==, DNS_ERR_CANCEL);

end:
	if (port)
		evdns_close_server_port(port);
	if (dns)
		evdns_base_free(dns, 0);
}

static void
fail_server_cb(struct evdns_server_request *req, void *data)
{
	const char *question;
	int *count = data;
	struct in_addr in;

	/* Drop the first N requests that we get. */
	if (*count > 0) {
		--*count;
		tt_want(! evdns_server_request_drop(req));
		return;
	}

	if (req->nquestions != 1)
		TT_DIE(("Only handling one question at a time; got %d",
			req->nquestions));

	question = req->questions[0]->name;

	if (!evutil_ascii_strcasecmp(question, "google.com")) {
		/* Detect a probe, and get out of the loop. */
		event_base_loopexit(exit_base, NULL);
	}

	tt_assert(evutil_inet_pton(AF_INET, "16.32.64.128", &in));
	evdns_server_request_add_a_reply(req, question, 1, &in.s_addr,
	    100);
	tt_assert(! evdns_server_request_respond(req, 0))
	return;
end:
	tt_want(! evdns_server_request_drop(req));
}

static void
dns_retry_test_impl(void *arg, int flags)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_server_port *port = NULL;
	struct evdns_base *dns = NULL;
	int drop_count = 2;
	ev_uint16_t portnum = 0;
	char buf[64];

	struct generic_dns_callback_result r1;

	port = regress_get_udp_dnsserver(base, &portnum, NULL,
	    fail_server_cb, &drop_count);
	tt_assert(port);
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, flags);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));
	tt_assert(! evdns_base_set_option(dns, "timeout", "0.2"));
	tt_assert(! evdns_base_set_option(dns, "max-timeouts:", "10"));
	tt_assert(! evdns_base_set_option(dns, "initial-probe-timeout", "0.1"));

	evdns_base_resolve_ipv4(dns, "host.example.com", 0,
	    generic_dns_callback, &r1);

	n_replies_left = 1;
	exit_base = base;

	event_base_dispatch(base);

	tt_int_op(drop_count, ==, 0);

	tt_int_op(r1.type, ==, DNS_IPv4_A);
	tt_int_op(r1.count, ==, 1);
	tt_int_op(((ev_uint32_t*)r1.addrs)[0], ==, htonl(0x10204080));

	/* Now try again, but this time have the server get treated as
	 * failed, so we can send it a test probe. */
	drop_count = 4;
	tt_assert(! evdns_base_set_option(dns, "max-timeouts:", "2"));
	tt_assert(! evdns_base_set_option(dns, "attempts:", "3"));
	memset(&r1, 0, sizeof(r1));

	evdns_base_resolve_ipv4(dns, "host.example.com", 0,
	    generic_dns_callback, &r1);

	n_replies_left = 2;

	/* This will run until it answers the "google.com" probe request. */
	event_base_dispatch(base);

	/* We'll treat the server as failed here. */
	tt_int_op(r1.result, ==, DNS_ERR_TIMEOUT);

	/* It should work this time. */
	tt_int_op(drop_count, ==, 0);
	evdns_base_resolve_ipv4(dns, "host.example.com", 0,
	    generic_dns_callback, &r1);

	event_base_dispatch(base);
	tt_int_op(r1.result, ==, DNS_ERR_NONE);
	tt_int_op(r1.type, ==, DNS_IPv4_A);
	tt_int_op(r1.count, ==, 1);
	tt_int_op(((ev_uint32_t*)r1.addrs)[0], ==, htonl(0x10204080));

end:
	if (dns)
		evdns_base_free(dns, 0);
	if (port)
		evdns_close_server_port(port);
}
static void
dns_retry_test(void *arg)
{
	dns_retry_test_impl(arg, 0);
}
static void
dns_retry_disable_when_inactive_test(void *arg)
{
	dns_retry_test_impl(arg, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
}

static void
dns_probe_settings_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_server_port *port = NULL;
	struct evdns_base *dns = NULL;
	int drop_count = 1;
	ev_uint16_t portnum = 0;
	char buf[64];

	struct generic_dns_callback_result r1, r2;
	struct timeval tval_before, tval_after;

	port = regress_get_udp_dnsserver(base, &portnum, NULL,
	    fail_server_cb, &drop_count);
	tt_assert(port);
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, 0);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));
	tt_assert(!evdns_base_set_option(dns, "timeout", "0.2"));
	tt_assert(!evdns_base_set_option(dns, "max-timeouts", "1"));
	tt_assert(!evdns_base_set_option(dns, "attempts", "1"));
	tt_assert(!evdns_base_set_option(dns, "initial-probe-timeout", "10"));
	// it will also set initial-probe-timeout to 1s (10s > 1s)
	tt_assert(!evdns_base_set_option(dns, "max-probe-timeout", "1"));

	evdns_base_resolve_ipv4(dns, "host.example.com", 0,
	    generic_dns_callback, &r1);
	n_replies_left = 2;
	exit_base = base;
	gettimeofday(&tval_before, NULL);
	// this will wait until the probe request done
	// should be around 1s instead of 10s
	event_base_dispatch(base);
	gettimeofday(&tval_after, NULL);
	tt_int_op(r1.result, ==, DNS_ERR_TIMEOUT);
	test_timeval_diff_leq(&tval_before, &tval_after, 1000, 500);

	// should be ok now
	evdns_base_resolve_ipv4(dns, "host.example.com", 0,
	    generic_dns_callback, &r1);
	n_replies_left = 1;
	event_base_dispatch(base);

	tt_int_op(r1.result, ==, DNS_ERR_NONE);
	tt_int_op(r1.type, ==, DNS_IPv4_A);
	tt_int_op(r1.count, ==, 1);
	tt_int_op(((ev_uint32_t*)r1.addrs)[0], ==, htonl(0x10204080));

	// dns server down again
	drop_count = 3;
	tt_assert(!evdns_base_set_option(dns, "max-probe-timeout", "3600"));
	tt_assert(!evdns_base_set_option(dns, "initial-probe-timeout", "0.2"));
	tt_assert(!evdns_base_set_option(dns, "probe-backoff-factor", "10"));
	evdns_base_resolve_ipv4(dns, "host.example.com", 0, generic_dns_callback, &r1);
	evdns_base_resolve_ipv4(dns, "host.example.com", 0, generic_dns_callback, &r2);
	// probe timeout should be around 2s now
	n_replies_left = 3;

	gettimeofday(&tval_before, NULL);
	// wait dns server up
	event_base_dispatch(base);
	tt_int_op(r1.result, ==, DNS_ERR_TIMEOUT);
	tt_int_op(r2.result, ==, DNS_ERR_TIMEOUT);
	gettimeofday(&tval_after, NULL);
	test_timeval_diff_leq(&tval_before, &tval_after, 2000, 1000);

	// should be ok now
	evdns_base_resolve_ipv4(dns, "host.example.com", 0, generic_dns_callback, &r1);
	n_replies_left = 1;
	event_base_dispatch(base);

	tt_int_op(r1.result, ==, DNS_ERR_NONE);
	tt_int_op(r1.type, ==, DNS_IPv4_A);
	tt_int_op(r1.count, ==, 1);
	tt_int_op(((ev_uint32_t*)r1.addrs)[0], ==, htonl(0x10204080));

	end:
	if (dns)
		evdns_base_free(dns, 0);
	if (port)
		evdns_close_server_port(port);
}

static struct regress_dns_server_table internal_error_table[] = {
	/* Error 4 (NOTIMPL) makes us reissue the request to another server
	   if we can.

	   XXXX we should reissue under a much wider set of circumstances!
	 */
	{ "foof.example.com", "err", "4", 0, 0 },
	{ NULL, NULL, NULL, 0, 0 }
};

static struct regress_dns_server_table reissue_table[] = {
	{ "foof.example.com", "A", "240.15.240.15", 0, 0 },
	{ NULL, NULL, NULL, 0, 0 }
};

static void
dns_reissue_test_impl(void *arg, int flags)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_server_port *port1 = NULL, *port2 = NULL;
	struct evdns_base *dns = NULL;
	struct generic_dns_callback_result r1;
	ev_uint16_t portnum1 = 0, portnum2=0;
	char buf1[64], buf2[64];

	port1 = regress_get_udp_dnsserver(base, &portnum1, NULL,
	    regress_dns_server_cb, internal_error_table);
	tt_assert(port1);
	port2 = regress_get_udp_dnsserver(base, &portnum2, NULL,
	    regress_dns_server_cb, reissue_table);
	tt_assert(port2);
	evutil_snprintf(buf1, sizeof(buf1), "127.0.0.1:%d", (int)portnum1);
	evutil_snprintf(buf2, sizeof(buf2), "127.0.0.1:%d", (int)portnum2);

	dns = evdns_base_new(base, flags);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf1));
	tt_assert(! evdns_base_set_option(dns, "timeout:", "0.3"));
	tt_assert(! evdns_base_set_option(dns, "max-timeouts:", "2"));
	tt_assert(! evdns_base_set_option(dns, "attempts:", "5"));

	memset(&r1, 0, sizeof(r1));
	evdns_base_resolve_ipv4(dns, "foof.example.com", 0,
	    generic_dns_callback, &r1);

	/* Add this after, so that we are sure to get a reissue. */
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf2));

	n_replies_left = 1;
	exit_base = base;

	event_base_dispatch(base);
	tt_int_op(r1.result, ==, DNS_ERR_NONE);
	tt_int_op(r1.type, ==, DNS_IPv4_A);
	tt_int_op(r1.count, ==, 1);
	tt_int_op(((ev_uint32_t*)r1.addrs)[0], ==, htonl(0xf00ff00f));

	/* Make sure we dropped at least once. */
	tt_int_op(internal_error_table[0].seen, >, 0);

end:
	if (dns)
		evdns_base_free(dns, 0);
	if (port1)
		evdns_close_server_port(port1);
	if (port2)
		evdns_close_server_port(port2);
}
static void
dns_reissue_test(void *arg)
{
	dns_reissue_test_impl(arg, 0);
}
static void
dns_reissue_disable_when_inactive_test(void *arg)
{
	dns_reissue_test_impl(arg, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
}

#if 0
static void
dumb_bytes_fn(char *p, size_t n)
{
	unsigned i;
	/* This gets us 6 bits of entropy per transaction ID, which means we
	 * will have probably have collisions and need to pick again. */
	for (i=0;i<n;++i)
		p[i] = (char)(rand() & 7);
}
#endif

static void
dns_inflight_test_impl(void *arg, int flags)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	struct evdns_server_port *dns_port = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];
	int disable_when_inactive = flags & EVDNS_BASE_DISABLE_WHEN_INACTIVE;

	struct generic_dns_callback_result r[20];
	int i;

	dns_port = regress_get_udp_dnsserver(base, &portnum, NULL,
		regress_dns_server_cb, reissue_table);
	tt_assert(dns_port);
	if (disable_when_inactive) {
		exit_port = dns_port;
	}

	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, flags);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));
	tt_assert(! evdns_base_set_option(dns, "max-inflight:", "3"));
	tt_assert(! evdns_base_set_option(dns, "randomize-case:", "0"));

	for (i=0;i<20;++i)
		evdns_base_resolve_ipv4(dns, "foof.example.com", 0, generic_dns_callback, &r[i]);

	n_replies_left = 20;
	exit_base = base;

	event_base_dispatch(base);

	for (i=0;i<20;++i) {
		tt_int_op(r[i].type, ==, DNS_IPv4_A);
		tt_int_op(r[i].count, ==, 1);
		tt_int_op(((ev_uint32_t*)r[i].addrs)[0], ==, htonl(0xf00ff00f));
	}

end:
	if (dns)
		evdns_base_free(dns, 0);
	if (exit_port) {
		evdns_close_server_port(exit_port);
		exit_port = NULL;
	} else if (! disable_when_inactive) {
		evdns_close_server_port(dns_port);
	}
}

static void
dns_inflight_test(void *arg)
{
	dns_inflight_test_impl(arg, 0);
}

static void
dns_disable_when_inactive_test(void *arg)
{
	dns_inflight_test_impl(arg, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
}

static void
dns_disable_when_inactive_no_ns_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base, *inactive_base;
	struct evdns_base *dns = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];
	struct generic_dns_callback_result r;

	inactive_base = event_base_new();
	tt_assert(inactive_base);

	/** Create dns server with inactive base, to avoid replying to clients */
	tt_assert(regress_dnsserver(inactive_base, &portnum, search_table, NULL));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));
	tt_assert(! evdns_base_set_option(dns, "timeout:", "0.1"));

	evdns_base_resolve_ipv4(dns, "foof.example.com", 0, generic_dns_callback, &r);
	n_replies_left = 1;
	exit_base = base;

	event_base_dispatch(base);

	tt_int_op(n_replies_left, ==, 0);

	tt_int_op(r.result, ==, DNS_ERR_TIMEOUT);
	tt_int_op(r.count, ==, 0);
	tt_ptr_op(r.addrs, ==, NULL);

end:
	if (dns)
		evdns_base_free(dns, 0);
	regress_clean_dnsserver();
	if (inactive_base)
		event_base_free(inactive_base);
}

static void
dns_initialize_nameservers_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	struct sockaddr_storage ss;
	int size;

	dns = evdns_base_new(base, 0);
	tt_assert(dns);
	tt_int_op(evdns_base_get_nameserver_addr(dns, 0, NULL, 0), ==, -1);
	evdns_base_free(dns, 0);

	dns = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
	tt_assert(dns);

	size = evdns_base_get_nameserver_addr(dns, 0, (struct sockaddr *)&ss, sizeof(ss));
	tt_int_op(size, >, 0);
	if (ss.ss_family == AF_INET)
		tt_int_op(size, ==, sizeof(struct sockaddr_in));
	else
		tt_int_op(size, ==, sizeof(struct sockaddr_in6));


end:
	if (dns)
		evdns_base_free(dns, 0);
}
#ifndef _WIN32
#define RESOLV_FILE "empty-resolv.conf"
static void
dns_nameservers_no_default_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	int ok = access(RESOLV_FILE, R_OK);

	tt_assert(ok);

	dns = evdns_base_new(base, 0);
	tt_assert(dns);
	tt_int_op(evdns_base_get_nameserver_addr(dns, 0, NULL, 0), ==, -1);

	/* We cannot test
	 * EVDNS_BASE_INITIALIZE_NAMESERVERS|EVDNS_BASE_NAMESERVERS_NO_DEFAULT
	 * because we cannot mock "/etc/resolv.conf" (yet). */

	evdns_base_resolv_conf_parse(dns,
		DNS_OPTIONS_ALL|DNS_OPTION_NAMESERVERS_NO_DEFAULT, RESOLV_FILE);
	tt_int_op(evdns_base_get_nameserver_addr(dns, 0, NULL, 0), ==, -1);

	evdns_base_resolv_conf_parse(dns, DNS_OPTIONS_ALL, RESOLV_FILE);
	tt_int_op(evdns_base_get_nameserver_addr(dns, 0, NULL, 0), ==, sizeof(struct sockaddr));

end:
	if (dns)
		evdns_base_free(dns, 0);
}
#endif

/* === Test for bufferevent_socket_connect_hostname */

static int total_connected_or_failed = 0;
static int total_n_accepted = 0;
static struct event_base *be_connect_hostname_base = NULL;

/* Implements a DNS server for the connect_hostname test and the
 * getaddrinfo_async test */
static void
be_getaddrinfo_server_cb(struct evdns_server_request *req, void *data)
{
	int i;
	int *n_got_p=data;
	int added_any=0;
	++*n_got_p;

	for (i = 0; i < req->nquestions; ++i) {
		const int qtype = req->questions[i]->type;
		const int qclass = req->questions[i]->dns_question_class;
		const char *qname = req->questions[i]->name;
		struct in_addr ans;
		struct in6_addr ans6;
		memset(&ans6, 0, sizeof(ans6));

		TT_BLATHER(("Got question about %s, type=%d", qname, qtype));

		if (qtype == EVDNS_TYPE_A &&
		    qclass == EVDNS_CLASS_INET &&
		    !evutil_ascii_strcasecmp(qname, "nobodaddy.example.com")) {
			ans.s_addr = htonl(0x7f000001);
			evdns_server_request_add_a_reply(req, qname,
			    1, &ans.s_addr, 2000);
			added_any = 1;
		} else if (!evutil_ascii_strcasecmp(qname,
			"nosuchplace.example.com")) {
			/* ok, just say notfound. */
		} else if (!evutil_ascii_strcasecmp(qname,
			"both.example.com")) {
			if (qtype == EVDNS_TYPE_A) {
				ans.s_addr = htonl(0x50502020);
				evdns_server_request_add_a_reply(req, qname,
				    1, &ans.s_addr, 2000);
				added_any = 1;
			} else if (qtype == EVDNS_TYPE_AAAA) {
				ans6.s6_addr[0] = 0x80;
				ans6.s6_addr[1] = 0xff;
				ans6.s6_addr[14] = 0xbb;
				ans6.s6_addr[15] = 0xbb;
				evdns_server_request_add_aaaa_reply(req, qname,
				    1, &ans6.s6_addr, 2000);
				added_any = 1;
			}
			evdns_server_request_add_cname_reply(req, qname,
			    "both-canonical.example.com", 1000);
		} else if (!evutil_ascii_strcasecmp(qname,
			"v4only.example.com") ||
		    !evutil_ascii_strcasecmp(qname, "v4assert.example.com")) {
			if (qtype == EVDNS_TYPE_A) {
				ans.s_addr = htonl(0x12345678);
				evdns_server_request_add_a_reply(req, qname,
				    1, &ans.s_addr, 2000);
				added_any = 1;
			} else if (!evutil_ascii_strcasecmp(qname,
				"v4assert.example.com")) {
				TT_FAIL(("Got an AAAA request for v4assert"));
			}
		} else if (!evutil_ascii_strcasecmp(qname,
			"v6only.example.com") ||
		    !evutil_ascii_strcasecmp(qname, "v6assert.example.com")) {
			if (qtype == EVDNS_TYPE_AAAA) {
				ans6.s6_addr[0] = 0x0b;
				ans6.s6_addr[1] = 0x0b;
				ans6.s6_addr[14] = 0xf0;
				ans6.s6_addr[15] = 0x0d;
				evdns_server_request_add_aaaa_reply(req, qname,
				    1, &ans6.s6_addr, 2000);
				added_any = 1;
			}  else if (!evutil_ascii_strcasecmp(qname,
				"v6assert.example.com")) {
				TT_FAIL(("Got a A request for v6assert"));
			}
		} else if (!evutil_ascii_strcasecmp(qname,
			"v6timeout.example.com")) {
			if (qtype == EVDNS_TYPE_A) {
				ans.s_addr = htonl(0xabcdef01);
				evdns_server_request_add_a_reply(req, qname,
				    1, &ans.s_addr, 2000);
				added_any = 1;
			} else if (qtype == EVDNS_TYPE_AAAA) {
				/* Let the v6 request time out.*/
				evdns_server_request_drop(req);
				return;
			}
		} else if (!evutil_ascii_strcasecmp(qname,
			"v4timeout.example.com")) {
			if (qtype == EVDNS_TYPE_AAAA) {
				ans6.s6_addr[0] = 0x0a;
				ans6.s6_addr[1] = 0x0a;
				ans6.s6_addr[14] = 0xff;
				ans6.s6_addr[15] = 0x01;
				evdns_server_request_add_aaaa_reply(req, qname,
				    1, &ans6.s6_addr, 2000);
				added_any = 1;
			} else if (qtype == EVDNS_TYPE_A) {
				/* Let the v4 request time out.*/
				evdns_server_request_drop(req);
				return;
			}
		} else if (!evutil_ascii_strcasecmp(qname,
			"v6timeout-nonexist.example.com")) {
			if (qtype == EVDNS_TYPE_A) {
				/* Fall through, give an nexist. */
			} else if (qtype == EVDNS_TYPE_AAAA) {
				/* Let the v6 request time out.*/
				evdns_server_request_drop(req);
				return;
			}
		} else if (!evutil_ascii_strcasecmp(qname,
			"all-timeout.example.com")) {
			/* drop all requests */
			evdns_server_request_drop(req);
			return;
		} else {
			TT_GRIPE(("Got weird request for %s",qname));
		}
	}
	if (added_any) {
		TT_BLATHER(("answering"));
		evdns_server_request_respond(req, 0);
	} else {
		TT_BLATHER(("saying nexist."));
		evdns_server_request_respond(req, 3);
	}
}

/* Implements a listener for connect_hostname test. */
static void
nil_accept_cb(struct evconnlistener *l, evutil_socket_t fd, struct sockaddr *s,
    int socklen, void *arg)
{
	int *p = arg;
	(*p)++;
	++total_n_accepted;
	/* don't do anything with the socket; let it close when we exit() */
	if (total_n_accepted >= 3 && total_connected_or_failed >= 5)
		event_base_loopexit(be_connect_hostname_base,
		    NULL);
}

struct be_conn_hostname_result {
	int dnserr;
	int what;
};

/* Bufferevent event callback for the connect_hostname test: remembers what
 * event we got. */
static void
be_connect_hostname_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	struct be_conn_hostname_result *got = ctx;

	if (got->what) {
		TT_FAIL(("Two events on one bufferevent. %d,%d",
			got->what, (int)what));
	}

	TT_BLATHER(("Got a bufferevent event %d", what));
	got->what = what;

	if ((what & BEV_EVENT_CONNECTED) || (what & BEV_EVENT_ERROR)) {
		int expected = 3;
		int r = bufferevent_socket_get_dns_error(bev);

		if (r) {
			got->dnserr = r;
			TT_BLATHER(("DNS error %d: %s", r,
				   evutil_gai_strerror(r)));
		}
		++total_connected_or_failed;
		TT_BLATHER(("Got %d connections or errors.", total_connected_or_failed));

		/** emfile test */
		if (errno == EMFILE) {
			expected = 0;
		}

		if (total_n_accepted >= expected && total_connected_or_failed >= 5)
			event_base_loopexit(be_connect_hostname_base,
			    NULL);
	}
}

static int bev_connect_hostname(struct bufferevent *bev, struct evdns_base *dns,
    struct evutil_addrinfo *hints, const char *host, int port)
{
	if (hints->ai_flags)
		return bufferevent_socket_connect_hostname_hints(bev, dns, hints, host, port);
	else
		return bufferevent_socket_connect_hostname(bev, dns, AF_INET, host, port);
}
static void
test_bufferevent_connect_hostname(void *arg)
{
	struct basic_test_data *data = arg;
	int emfile = data->setup_data && !strcmp(data->setup_data, "emfile");
	int hints  = data->setup_data && !strcmp(data->setup_data, "hints");
	struct evconnlistener *listener = NULL;
	struct bufferevent *be[5] = { NULL, NULL, NULL, NULL, NULL };
	struct be_conn_hostname_result be_outcome[ARRAY_SIZE(be)];
	int expect_err;
	struct evdns_base *dns=NULL;
	struct evdns_server_port *port=NULL;
	struct sockaddr_in sin;
	int listener_port=-1;
	ev_uint16_t dns_port=0;
	int n_accept=0, n_dns=0;
	char buf[128];
	unsigned i;
	int ret;
	struct evutil_addrinfo in_hints;

	memset(&in_hints, 0, sizeof(in_hints));
	if (hints) {
		in_hints.ai_family = AF_INET;
		in_hints.ai_protocol = IPPROTO_TCP;
		in_hints.ai_socktype = SOCK_STREAM;
		in_hints.ai_flags = EVUTIL_AI_ADDRCONFIG;
	}

	be_connect_hostname_base = data->base;

	/* Bind an address and figure out what port it's on. */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	sin.sin_port = 0;
	listener = evconnlistener_new_bind(data->base, nil_accept_cb,
	    &n_accept,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC,
	    -1, (struct sockaddr *)&sin, sizeof(sin));
	tt_assert(listener);
	listener_port = regress_get_socket_port(
		evconnlistener_get_fd(listener));

	port = regress_get_udp_dnsserver(data->base, &dns_port, NULL,
	    be_getaddrinfo_server_cb, &n_dns);
	tt_assert(port);
	tt_int_op(dns_port, >=, 0);

	/* Start an evdns_base that uses the server as its resolver. */
	dns = evdns_base_new(data->base, 0);
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)dns_port);
	evdns_base_nameserver_ip_add(dns, buf);

#ifdef EVENT__HAVE_SETRLIMIT
	if (emfile) {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		struct rlimit file = { fd, fd };

		tt_int_op(fd, >=, 0);
		tt_assert(!close(fd));

		tt_assert(!setrlimit(RLIMIT_NOFILE, &file));
	}
#endif

	/* Now, finally, at long last, launch the bufferevents.	 One should do
	 * a failing lookup IP, one should do a successful lookup by IP,
	 * and one should do a successful lookup by hostname. */
	for (i = 0; i < ARRAY_SIZE(be); ++i) {
		memset(&be_outcome[i], 0, sizeof(be_outcome[i]));
		be[i] = bufferevent_socket_new(data->base, -1, BEV_OPT_CLOSE_ON_FREE);
		bufferevent_setcb(be[i], NULL, NULL, be_connect_hostname_event_cb,
			&be_outcome[i]);
	}

	/* Use the blocking resolver.  This one will fail if your resolver
	 * can't resolve localhost to 127.0.0.1 */
	tt_assert(!bev_connect_hostname(be[3], NULL, &in_hints,
		"localhost", listener_port));
	/* Use the blocking resolver with a nonexistent hostname. */
	tt_assert(!bev_connect_hostname(be[4], NULL, &in_hints,
		"nonesuch.nowhere.example.com", 80));
	{
		/* The blocking resolver will use the system nameserver, which
		 * might tell us anything.  (Yes, some twits even pretend that
		 * example.com is real.) Let's see what answer to expect. */
		struct evutil_addrinfo hints, *ai = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		expect_err = evutil_getaddrinfo(
			"nonesuch.nowhere.example.com", "80", &hints, &ai);
	}
	/* Launch an async resolve that will fail. */
	tt_assert(!bev_connect_hostname(be[0], dns, &in_hints,
		"nosuchplace.example.com", listener_port));
	/* Connect to the IP without resolving. */
	tt_assert(!bev_connect_hostname(be[1], dns, &in_hints,
		"127.0.0.1", listener_port));
	/* Launch an async resolve that will succeed. */
	tt_assert(!bev_connect_hostname(be[2], dns, &in_hints,
		"nobodaddy.example.com", listener_port));

	ret = event_base_dispatch(data->base);
#ifdef __sun__
	if (emfile && !strcmp(event_base_get_method(data->base), "devpoll")) {
		tt_int_op(ret, ==, -1);
		/** DP_POLL failed */
		tt_skip();
	} else
#endif
	{
		tt_int_op(ret, ==, 0);
	}

	tt_int_op(be_outcome[0].what, ==, BEV_EVENT_ERROR);
	tt_int_op(be_outcome[0].dnserr, ==, EVUTIL_EAI_NONAME);
	tt_int_op(be_outcome[1].what, ==, !emfile ? BEV_EVENT_CONNECTED : BEV_EVENT_ERROR);
	tt_int_op(be_outcome[1].dnserr, ==, 0);
	tt_int_op(be_outcome[2].what, ==, !emfile ? BEV_EVENT_CONNECTED : BEV_EVENT_ERROR);
	tt_int_op(be_outcome[2].dnserr, ==, 0);
	tt_int_op(be_outcome[3].what, ==, !emfile ? BEV_EVENT_CONNECTED : BEV_EVENT_ERROR);
	if (!emfile) {
		tt_int_op(be_outcome[3].dnserr, ==, 0);
	} else {
		tt_int_op(be_outcome[3].dnserr, !=, 0);
	}
	if (expect_err) {
		tt_int_op(be_outcome[4].what, ==, BEV_EVENT_ERROR);
		tt_int_op(be_outcome[4].dnserr, ==, expect_err);
	}

	if (emfile) {
		tt_int_op(n_accept, ==, 0);
	} else {
		tt_int_op(n_accept, ==, 3);
	}
	tt_int_op(n_dns, ==, 2);

end:
	if (listener)
		evconnlistener_free(listener);
	if (port)
		evdns_close_server_port(port);
	if (dns)
		evdns_base_free(dns, 0);
	for (i = 0; i < ARRAY_SIZE(be); ++i) {
		if (be[i])
			bufferevent_free(be[i]);
	}
}

struct gai_outcome {
	int err;
	struct evutil_addrinfo *ai;
};

static int n_gai_results_pending = 0;
static struct event_base *exit_base_on_no_pending_results = NULL;

static void
gai_cb(int err, struct evutil_addrinfo *res, void *ptr)
{
	struct gai_outcome *go = ptr;
	go->err = err;
	go->ai = res;
	if (--n_gai_results_pending <= 0 && exit_base_on_no_pending_results)
		event_base_loopexit(exit_base_on_no_pending_results, NULL);
	if (n_gai_results_pending < 900)
		TT_BLATHER(("Got an answer; expecting %d more.",
			n_gai_results_pending));
}

static void
cancel_gai_cb(evutil_socket_t fd, short what, void *ptr)
{
	struct evdns_getaddrinfo_request *r = ptr;
	evdns_getaddrinfo_cancel(r);
}

static void
test_getaddrinfo_async(void *arg)
{
	struct basic_test_data *data = arg;
	struct evutil_addrinfo hints, *a;
	struct gai_outcome local_outcome;
	struct gai_outcome a_out[12];
	unsigned i;
	struct evdns_getaddrinfo_request *r;
	char buf[128];
	struct evdns_server_port *port = NULL;
	ev_uint16_t dns_port = 0;
	int n_dns_questions = 0;
	struct evdns_base *dns_base;

	memset(a_out, 0, sizeof(a_out));
	memset(&local_outcome, 0, sizeof(local_outcome));

	dns_base = evdns_base_new(data->base, 0);
	tt_assert(dns_base);

	/* for localhost */
	evdns_base_load_hosts(dns_base, NULL);

	tt_assert(! evdns_base_set_option(dns_base, "timeout", "0.3"));
	tt_assert(! evdns_base_set_option(dns_base, "getaddrinfo-allow-skew", "0.2"));

	n_gai_results_pending = 10000; /* don't think about exiting yet. */

	/* 1. Try some cases that will never hit the asynchronous resolver. */
	/* 1a. Simple case with a symbolic service name */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	memset(&local_outcome, 0, sizeof(local_outcome));
	r = evdns_getaddrinfo(dns_base, "1.2.3.4", "http",
	    &hints, gai_cb, &local_outcome);
	tt_assert(! r);
	if (!local_outcome.err) {
		tt_ptr_op(local_outcome.ai,!=,NULL);
		test_ai_eq(local_outcome.ai, "1.2.3.4:80", SOCK_STREAM, IPPROTO_TCP);
		evutil_freeaddrinfo(local_outcome.ai);
		local_outcome.ai = NULL;
	} else {
		TT_BLATHER(("Apparently we have no getservbyname."));
	}

	/* 1b. EVUTIL_AI_NUMERICHOST is set */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = EVUTIL_AI_NUMERICHOST;
	memset(&local_outcome, 0, sizeof(local_outcome));
	r = evdns_getaddrinfo(dns_base, "www.google.com", "80",
	    &hints, gai_cb, &local_outcome);
	tt_ptr_op(r,==,NULL);
	tt_int_op(local_outcome.err,==,EVUTIL_EAI_NONAME);
	tt_ptr_op(local_outcome.ai,==,NULL);

	/* 1c. We give a numeric address (ipv6) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_UNSPEC;
	hints.ai_protocol = IPPROTO_TCP;
	r = evdns_getaddrinfo(dns_base, "f::f", "8008",
	    &hints, gai_cb, &local_outcome);
	tt_assert(!r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	tt_ptr_op(local_outcome.ai->ai_next,==,NULL);
	test_ai_eq(local_outcome.ai, "[f::f]:8008", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 1d. We give a numeric address (ipv4) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_UNSPEC;
	r = evdns_getaddrinfo(dns_base, "5.6.7.8", NULL,
	    &hints, gai_cb, &local_outcome);
	tt_assert(!r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	a = ai_find_by_protocol(local_outcome.ai, IPPROTO_TCP);
	tt_assert(a);
	test_ai_eq(a, "5.6.7.8", SOCK_STREAM, IPPROTO_TCP);
	a = ai_find_by_protocol(local_outcome.ai, IPPROTO_UDP);
	tt_assert(a);
	test_ai_eq(a, "5.6.7.8", SOCK_DGRAM, IPPROTO_UDP);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 1e. nodename is NULL (bind) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = EVUTIL_AI_PASSIVE;
	r = evdns_getaddrinfo(dns_base, NULL, "9090",
	    &hints, gai_cb, &local_outcome);
	tt_assert(!r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	/* we should get a v4 address of 0.0.0.0... */
	a = ai_find_by_family(local_outcome.ai, PF_INET);
	tt_assert(a);
	test_ai_eq(a, "0.0.0.0:9090", SOCK_DGRAM, IPPROTO_UDP);
	/* ... and a v6 address of ::0 */
	a = ai_find_by_family(local_outcome.ai, PF_INET6);
	tt_assert(a);
	test_ai_eq(a, "[::]:9090", SOCK_DGRAM, IPPROTO_UDP);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 1f. nodename is NULL (connect) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	r = evdns_getaddrinfo(dns_base, NULL, "2",
	    &hints, gai_cb, &local_outcome);
	tt_assert(!r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	/* we should get a v4 address of 127.0.0.1 .... */
	a = ai_find_by_family(local_outcome.ai, PF_INET);
	tt_assert(a);
	test_ai_eq(a, "127.0.0.1:2", SOCK_STREAM, IPPROTO_TCP);
	/* ... and a v6 address of ::1 */
	a = ai_find_by_family(local_outcome.ai, PF_INET6);
	tt_assert(a);
	test_ai_eq(a, "[::1]:2", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 1g. We find localhost immediately. (pf_unspec) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	r = evdns_getaddrinfo(dns_base, "LOCALHOST", "80",
	    &hints, gai_cb, &local_outcome);
	tt_assert(!r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	/* we should get a v4 address of 127.0.0.1 .... */
	a = ai_find_by_family(local_outcome.ai, PF_INET);
	tt_assert(a);
	test_ai_eq(a, "127.0.0.1:80", SOCK_STREAM, IPPROTO_TCP);
	/* ... and a v6 address of ::1 */
	a = ai_find_by_family(local_outcome.ai, PF_INET6);
	tt_assert(a);
	test_ai_eq(a, "[::1]:80", SOCK_STREAM, IPPROTO_TCP);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 1g. We find localhost immediately. (pf_inet6) */
	memset(&hints, 0, sizeof(hints));
	memset(&local_outcome, 0, sizeof(local_outcome));
	hints.ai_family = PF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	r = evdns_getaddrinfo(dns_base, "LOCALHOST", "9999",
	    &hints, gai_cb, &local_outcome);
	tt_assert(! r);
	tt_int_op(local_outcome.err,==,0);
	tt_assert(local_outcome.ai);
	a = local_outcome.ai;
	test_ai_eq(a, "[::1]:9999", SOCK_STREAM, IPPROTO_TCP);
	tt_ptr_op(a->ai_next, ==, NULL);
	evutil_freeaddrinfo(local_outcome.ai);
	local_outcome.ai = NULL;

	/* 2. Okay, now we can actually test the asynchronous resolver. */
	/* Start a dummy local dns server... */
	port = regress_get_udp_dnsserver(data->base, &dns_port, NULL,
	    be_getaddrinfo_server_cb, &n_dns_questions);
	tt_assert(port);
	tt_int_op(dns_port, >=, 0);
	/* ... and tell the evdns_base about it. */
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", dns_port);
	evdns_base_nameserver_ip_add(dns_base, buf);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = EVUTIL_AI_CANONNAME;
	/* 0: Request for both.example.com should return both addresses. */
	r = evdns_getaddrinfo(dns_base, "both.example.com", "8000",
	    &hints, gai_cb, &a_out[0]);
	tt_assert(r);

	/* 1: Request for v4only.example.com should return one address. */
	r = evdns_getaddrinfo(dns_base, "v4only.example.com", "8001",
	    &hints, gai_cb, &a_out[1]);
	tt_assert(r);

	/* 2: Request for v6only.example.com should return one address. */
	hints.ai_flags = 0;
	r = evdns_getaddrinfo(dns_base, "v6only.example.com", "8002",
	    &hints, gai_cb, &a_out[2]);
	tt_assert(r);

	/* 3: PF_INET request for v4assert.example.com should not generate a
	 * v6 request.	The server will fail the test if it does. */
	hints.ai_family = PF_INET;
	r = evdns_getaddrinfo(dns_base, "v4assert.example.com", "8003",
	    &hints, gai_cb, &a_out[3]);
	tt_assert(r);

	/* 4: PF_INET6 request for v6assert.example.com should not generate a
	 * v4 request.	The server will fail the test if it does. */
	hints.ai_family = PF_INET6;
	r = evdns_getaddrinfo(dns_base, "v6assert.example.com", "8004",
	    &hints, gai_cb, &a_out[4]);
	tt_assert(r);

	/* 5: PF_INET request for nosuchplace.example.com should give NEXIST. */
	hints.ai_family = PF_INET;
	r = evdns_getaddrinfo(dns_base, "nosuchplace.example.com", "8005",
	    &hints, gai_cb, &a_out[5]);
	tt_assert(r);

	/* 6: PF_UNSPEC request for nosuchplace.example.com should give NEXIST.
	 */
	hints.ai_family = PF_UNSPEC;
	r = evdns_getaddrinfo(dns_base, "nosuchplace.example.com", "8006",
	    &hints, gai_cb, &a_out[6]);
	tt_assert(r);

	/* 7: PF_UNSPEC request for v6timeout.example.com should give an ipv4
	 * address only. */
	hints.ai_family = PF_UNSPEC;
	r = evdns_getaddrinfo(dns_base, "v6timeout.example.com", "8007",
	    &hints, gai_cb, &a_out[7]);
	tt_assert(r);

	/* 8: PF_UNSPEC request for v6timeout-nonexist.example.com should give
	 * a NEXIST */
	hints.ai_family = PF_UNSPEC;
	r = evdns_getaddrinfo(dns_base, "v6timeout-nonexist.example.com",
	    "8008", &hints, gai_cb, &a_out[8]);
	tt_assert(r);

	/* 9: AI_ADDRCONFIG should at least not crash.	Can't test it more
	 * without knowing what kind of internet we have. */
	hints.ai_flags |= EVUTIL_AI_ADDRCONFIG;
	r = evdns_getaddrinfo(dns_base, "both.example.com",
	    "8009", &hints, gai_cb, &a_out[9]);
	tt_assert(r);

	/* 10: PF_UNSPEC for v4timeout.example.com should give an ipv6 address
	 * only. */
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = 0;
	r = evdns_getaddrinfo(dns_base, "v4timeout.example.com", "8010",
	    &hints, gai_cb, &a_out[10]);
	tt_assert(r);

	/* 11: timeout.example.com: cancel it after 100 msec. */
	r = evdns_getaddrinfo(dns_base, "all-timeout.example.com", "8011",
	    &hints, gai_cb, &a_out[11]);
	tt_assert(r);
	{
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 100*1000; /* 100 msec */
		event_base_once(data->base, -1, EV_TIMEOUT, cancel_gai_cb,
		    r, &tv);
	}

	/* XXXXX There are more tests we could do, including:

	   - A test to elicit NODATA.

	 */

	n_gai_results_pending = 12;
	exit_base_on_no_pending_results = data->base;

	event_base_dispatch(data->base);

	/* 0: both.example.com */
	tt_int_op(a_out[0].err, ==, 0);
	tt_assert(a_out[0].ai);
	tt_assert(a_out[0].ai->ai_next);
	tt_assert(!a_out[0].ai->ai_next->ai_next);
	a = ai_find_by_family(a_out[0].ai, PF_INET);
	tt_assert(a);
	test_ai_eq(a, "80.80.32.32:8000", SOCK_STREAM, IPPROTO_TCP);
	a = ai_find_by_family(a_out[0].ai, PF_INET6);
	tt_assert(a);
	test_ai_eq(a, "[80ff::bbbb]:8000", SOCK_STREAM, IPPROTO_TCP);
	tt_assert(a_out[0].ai->ai_canonname);
	tt_str_op(a_out[0].ai->ai_canonname, ==, "both-canonical.example.com");

	/* 1: v4only.example.com */
	tt_int_op(a_out[1].err, ==, 0);
	tt_assert(a_out[1].ai);
	tt_assert(! a_out[1].ai->ai_next);
	test_ai_eq(a_out[1].ai, "18.52.86.120:8001", SOCK_STREAM, IPPROTO_TCP);
	tt_assert(a_out[1].ai->ai_canonname == NULL);


	/* 2: v6only.example.com */
	tt_int_op(a_out[2].err, ==, 0);
	tt_assert(a_out[2].ai);
	tt_assert(! a_out[2].ai->ai_next);
	test_ai_eq(a_out[2].ai, "[b0b::f00d]:8002", SOCK_STREAM, IPPROTO_TCP);

	/* 3: v4assert.example.com */
	tt_int_op(a_out[3].err, ==, 0);
	tt_assert(a_out[3].ai);
	tt_assert(! a_out[3].ai->ai_next);
	test_ai_eq(a_out[3].ai, "18.52.86.120:8003", SOCK_STREAM, IPPROTO_TCP);

	/* 4: v6assert.example.com */
	tt_int_op(a_out[4].err, ==, 0);
	tt_assert(a_out[4].ai);
	tt_assert(! a_out[4].ai->ai_next);
	test_ai_eq(a_out[4].ai, "[b0b::f00d]:8004", SOCK_STREAM, IPPROTO_TCP);

	/* 5: nosuchplace.example.com (inet) */
	tt_int_op(a_out[5].err, ==, EVUTIL_EAI_NONAME);
	tt_assert(! a_out[5].ai);

	/* 6: nosuchplace.example.com (unspec) */
	tt_int_op(a_out[6].err, ==, EVUTIL_EAI_NONAME);
	tt_assert(! a_out[6].ai);

	/* 7: v6timeout.example.com */
	tt_int_op(a_out[7].err, ==, 0);
	tt_assert(a_out[7].ai);
	tt_assert(! a_out[7].ai->ai_next);
	test_ai_eq(a_out[7].ai, "171.205.239.1:8007", SOCK_STREAM, IPPROTO_TCP);

	/* 8: v6timeout-nonexist.example.com */
	tt_int_op(a_out[8].err, ==, EVUTIL_EAI_NONAME);
	tt_assert(! a_out[8].ai);

	/* 9: both (ADDRCONFIG) */
	tt_int_op(a_out[9].err, ==, 0);
	tt_assert(a_out[9].ai);
	a = ai_find_by_family(a_out[9].ai, PF_INET);
	if (a)
		test_ai_eq(a, "80.80.32.32:8009", SOCK_STREAM, IPPROTO_TCP);
	else
		tt_assert(ai_find_by_family(a_out[9].ai, PF_INET6));
	a = ai_find_by_family(a_out[9].ai, PF_INET6);
	if (a)
		test_ai_eq(a, "[80ff::bbbb]:8009", SOCK_STREAM, IPPROTO_TCP);
	else
		tt_assert(ai_find_by_family(a_out[9].ai, PF_INET));

	/* 10: v4timeout.example.com */
	tt_int_op(a_out[10].err, ==, 0);
	tt_assert(a_out[10].ai);
	tt_assert(! a_out[10].ai->ai_next);
	test_ai_eq(a_out[10].ai, "[a0a::ff01]:8010", SOCK_STREAM, IPPROTO_TCP);

	/* 11: cancelled request. */
	tt_int_op(a_out[11].err, ==, EVUTIL_EAI_CANCEL);
	tt_assert(a_out[11].ai == NULL);

end:
	if (local_outcome.ai)
		evutil_freeaddrinfo(local_outcome.ai);
	for (i = 0; i < ARRAY_SIZE(a_out); ++i) {
		if (a_out[i].ai)
			evutil_freeaddrinfo(a_out[i].ai);
	}
	if (port)
		evdns_close_server_port(port);
	if (dns_base)
		evdns_base_free(dns_base, 0);
}

struct gaic_request_status {
	int magic;
	struct event_base *base;
	struct evdns_base *dns_base;
	struct evdns_getaddrinfo_request *request;
	struct event cancel_event;
	int canceled;
};

#define GAIC_MAGIC 0x1234abcd

static int gaic_pending = 0;
static int gaic_freed = 0;

static void
gaic_cancel_request_cb(evutil_socket_t fd, short what, void *arg)
{
	struct gaic_request_status *status = arg;

	tt_assert(status->magic == GAIC_MAGIC);
	status->canceled = 1;
	evdns_getaddrinfo_cancel(status->request);
	return;
end:
	event_base_loopexit(status->base, NULL);
}

static void
gaic_server_cb(struct evdns_server_request *req, void *arg)
{
	ev_uint32_t answer = 0x7f000001;
	tt_assert(req->nquestions);
	evdns_server_request_add_a_reply(req, req->questions[0]->name, 1,
	    &answer, 100);
	evdns_server_request_respond(req, 0);
	return;
end:
	evdns_server_request_respond(req, DNS_ERR_REFUSED);
}


static void
gaic_getaddrinfo_cb(int result, struct evutil_addrinfo *res, void *arg)
{
	struct gaic_request_status *status = arg;
	struct event_base *base = status->base;
	tt_assert(status->magic == GAIC_MAGIC);

	if (result == EVUTIL_EAI_CANCEL) {
		tt_assert(status->canceled);
	}
	event_del(&status->cancel_event);

	memset(status, 0xf0, sizeof(*status));
	free(status);

end:
	if (res)
	{
		TT_BLATHER(("evutil_freeaddrinfo(%p)", res));
		evutil_freeaddrinfo(res);
		++gaic_freed;
	}
	if (--gaic_pending <= 0)
		event_base_loopexit(base, NULL);
}

static void
gaic_launch(struct event_base *base, struct evdns_base *dns_base)
{
	struct gaic_request_status *status = calloc(1,sizeof(*status));
	struct timeval tv = { 0, 10000 };
	status->magic = GAIC_MAGIC;
	status->base = base;
	status->dns_base = dns_base;
	event_assign(&status->cancel_event, base, -1, 0, gaic_cancel_request_cb,
	    status);
	status->request = evdns_getaddrinfo(dns_base,
	    "foobar.bazquux.example.com", "80", NULL, gaic_getaddrinfo_cb,
	    status);
	event_add(&status->cancel_event, &tv);
	++gaic_pending;
}

#ifdef EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
/* FIXME: We should move this to regress_main.c if anything else needs it.*/

/* Trivial replacements for malloc/free/realloc to check for memory leaks.
 * Not threadsafe. */
static int allocated_chunks = 0;

static void *
cnt_malloc(size_t sz)
{
	allocated_chunks += 1;
	return malloc(sz);
}

static void *
cnt_realloc(void *old, size_t sz)
{
	if (!old)
		allocated_chunks += 1;
	if (!sz)
		allocated_chunks -= 1;
	return realloc(old, sz);
}

static void
cnt_free(void *ptr)
{
	allocated_chunks -= 1;
	free(ptr);
}

struct testleak_env_t {
	struct event_base *base;
	struct evdns_base *dns_base;
	struct evdns_request *req;
	struct generic_dns_callback_result r;
};

static void *
testleak_setup(const struct testcase_t *testcase)
{
	struct testleak_env_t *env;

	allocated_chunks = 0;

	/* Reset allocation counter, to start allocations from the very beginning.
	 * (this will avoid false-positive negative numbers for allocated_chunks)
	 */
	libevent_global_shutdown();

	event_set_mem_functions(cnt_malloc, cnt_realloc, cnt_free);

	event_enable_debug_mode();

	/* not mm_calloc: we don't want to mess with the count. */
	env = calloc(1, sizeof(struct testleak_env_t));
	env->base = event_base_new();
	env->dns_base = evdns_base_new(env->base, 0);
	env->req = evdns_base_resolve_ipv4(
		env->dns_base, "example.com", DNS_QUERY_NO_SEARCH,
		generic_dns_callback, &env->r);
	return env;
}

static int
testleak_cleanup(const struct testcase_t *testcase, void *env_)
{
	int ok = 0;
	struct testleak_env_t *env = env_;
	tt_assert(env);
#ifdef EVENT__DISABLE_DEBUG_MODE
	tt_int_op(allocated_chunks, ==, 0);
#else
	libevent_global_shutdown();
	tt_int_op(allocated_chunks, ==, 0);
#endif
	ok = 1;
end:
	if (env) {
		if (env->dns_base)
			evdns_base_free(env->dns_base, 0);
		if (env->base)
			event_base_free(env->base);
		free(env);
	}
	return ok;
}

static struct testcase_setup_t testleak_funcs = {
	testleak_setup, testleak_cleanup
};

static void
test_dbg_leak_cancel(void *env_)
{
	/* cancel, loop, free/dns, free/base */
	struct testleak_env_t *env = env_;
	int send_err_shutdown = 1;
	evdns_cancel_request(env->dns_base, env->req);
	env->req = 0;

	/* `req` is freed in callback, that's why one loop is required. */
	event_base_loop(env->base, EVLOOP_NONBLOCK);

	/* send_err_shutdown means nothing as soon as our request is
	 * already canceled */
	evdns_base_free(env->dns_base, send_err_shutdown);
	env->dns_base = 0;
	event_base_free(env->base);
	env->base = 0;
}

static void
dbg_leak_resume(void *env_, int cancel, int send_err_shutdown)
{
	/* cancel, loop, free/dns, free/base */
	struct testleak_env_t *env = env_;
	if (cancel) {
		evdns_cancel_request(env->dns_base, env->req);
		tt_assert(!evdns_base_resume(env->dns_base));
	} else {
		/* TODO: No nameservers, request can't be processed, must be errored */
		tt_assert(!evdns_base_resume(env->dns_base));
	}

	event_base_loop(env->base, EVLOOP_NONBLOCK);
	/**
	 * Because we don't cancel request, and want our callback to recieve
	 * DNS_ERR_SHUTDOWN, we use deferred callback, and there was:
	 * - one extra malloc(),
	 *   @see reply_schedule_callback()
	 * - and one missing free
	 *   @see request_finished() (req->handle->pending_cb = 1)
	 * than we don't need to count in testleak_cleanup(), but we can clean them
	 * if we will run loop once again, but *after* evdns base freed.
	 */
	evdns_base_free(env->dns_base, send_err_shutdown);
	env->dns_base = 0;
	event_base_loop(env->base, EVLOOP_NONBLOCK);

end:
	event_base_free(env->base);
	env->base = 0;
}

#define IMPL_DBG_LEAK_RESUME(name, cancel, send_err_shutdown)      \
	static void                                                    \
	test_dbg_leak_##name##_(void *env_)                            \
	{                                                              \
		dbg_leak_resume(env_, cancel, send_err_shutdown);          \
	}
IMPL_DBG_LEAK_RESUME(resume, 0, 0)
IMPL_DBG_LEAK_RESUME(cancel_and_resume, 1, 0)
IMPL_DBG_LEAK_RESUME(resume_send_err, 0, 1)
IMPL_DBG_LEAK_RESUME(cancel_and_resume_send_err, 1, 1)

static void
test_dbg_leak_shutdown(void *env_)
{
	/* free/dns, loop, free/base */
	struct testleak_env_t *env = env_;
	int send_err_shutdown = 1;

	/* `req` is freed both with `send_err_shutdown` and without it,
	 * the only difference is `evdns_callback` call */
	env->req = 0;

	evdns_base_free(env->dns_base, send_err_shutdown);
	env->dns_base = 0;

	/* `req` is freed in callback, that's why one loop is required */
	event_base_loop(env->base, EVLOOP_NONBLOCK);
	event_base_free(env->base);
	env->base = 0;
}
#endif

static void
test_getaddrinfo_async_cancel_stress(void *ptr)
{
	struct event_base *base;
	struct evdns_base *dns_base = NULL;
	struct evdns_server_port *server = NULL;
	evutil_socket_t fd = -1;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen;
	unsigned i;

	base = event_base_new();
	dns_base = evdns_base_new(base, 0);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = 0;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		tt_abort_perror("socket");
	}
	evutil_make_socket_nonblocking(fd);
	if (bind(fd, (struct sockaddr*)&sin, sizeof(sin))<0) {
		tt_abort_perror("bind");
	}
	server = evdns_add_server_port_with_base(base, fd, 0, gaic_server_cb,
	    base);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);
	if (getsockname(fd, (struct sockaddr*)&ss, &slen)<0) {
		tt_abort_perror("getsockname");
	}
	evdns_base_nameserver_sockaddr_add(dns_base,
	    (struct sockaddr*)&ss, slen, 0);

	for (i = 0; i < 1000; ++i) {
		gaic_launch(base, dns_base);
	}

	event_base_dispatch(base);

	// at least some was canceled via external event
	tt_int_op(gaic_freed, !=, 1000);

end:
	if (dns_base)
		evdns_base_free(dns_base, 1);
	if (server)
		evdns_close_server_port(server);
	if (base)
		event_base_free(base);
	if (fd >= 0)
		evutil_closesocket(fd);
}

static void
dns_client_fail_requests_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	int limit_inflight = data->setup_data && !strcmp(data->setup_data, "limit-inflight");
	struct evdns_base *dns = NULL;
	struct evdns_server_port *dns_port = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];

	struct generic_dns_callback_result r[20];
	unsigned i;

	dns_port = regress_get_udp_dnsserver(base, &portnum, NULL,
		regress_dns_server_cb, reissue_table);
	tt_assert(dns_port);

	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	if (limit_inflight)
		tt_assert(!evdns_base_set_option(dns, "max-inflight:", "11"));

	for (i = 0; i < 20; ++i)
		evdns_base_resolve_ipv4(dns, "foof.example.com", 0, generic_dns_callback, &r[i]);

	n_replies_left = 20;
	exit_base = base;

	evdns_base_free(dns, 1 /** fail requests */);
	/** run defered callbacks, to trigger UAF */
	event_base_dispatch(base);

	tt_int_op(n_replies_left, ==, 0);
	for (i = 0; i < 20; ++i)
		tt_int_op(r[i].result, ==, DNS_ERR_SHUTDOWN);

end:
	evdns_close_server_port(dns_port);
}

static void
getaddrinfo_cb(int err, struct evutil_addrinfo *res, void *ptr)
{
	generic_dns_callback(err, 0, 0, 0, NULL, ptr);
}
static void
dns_client_fail_requests_getaddrinfo_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	struct evdns_server_port *dns_port = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];

	struct generic_dns_callback_result r[20];
	int i;

	dns_port = regress_get_udp_dnsserver(base, &portnum, NULL,
		regress_dns_server_cb, reissue_table);
	tt_assert(dns_port);

	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	dns = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	for (i = 0; i < 20; ++i)
		tt_assert(evdns_getaddrinfo(dns, "foof.example.com", "80", NULL, getaddrinfo_cb, &r[i]));

	n_replies_left = 20;
	exit_base = base;

	evdns_base_free(dns, 1 /** fail requests */);
	/** run defered callbacks, to trigger UAF */
	event_base_dispatch(base);

	tt_int_op(n_replies_left, ==, 0);
	for (i = 0; i < 20; ++i)
		tt_int_op(r[i].result, ==, EVUTIL_EAI_FAIL);

end:
	evdns_close_server_port(dns_port);
}

#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
struct race_param
{
	void *lock;
	void *reqs_cmpl_cond;
	int bw_threads;
	void *bw_threads_exited_cond;
	volatile int stopping;
	void *base;
	void *dns;

	int locked;
};
static void *
race_base_run(void *arg)
{
	struct race_param *rp = (struct race_param *)arg;
	event_base_loop(rp->base, EVLOOP_NO_EXIT_ON_EMPTY);
	THREAD_RETURN();
}
static void *
race_busywait_run(void *arg)
{
	struct race_param *rp = (struct race_param *)arg;
	struct sockaddr_storage ss;
	while (!rp->stopping)
		evdns_base_get_nameserver_addr(rp->dns, 0, (struct sockaddr *)&ss, sizeof(ss));
	EVLOCK_LOCK(rp->lock, 0);
	if (--rp->bw_threads == 0)
		EVTHREAD_COND_SIGNAL(rp->bw_threads_exited_cond);
	EVLOCK_UNLOCK(rp->lock, 0);
	THREAD_RETURN();
}
static void
race_gai_cb(int result, struct evutil_addrinfo *res, void *arg)
{
	struct race_param *rp = arg;
	(void)result;
	(void)res;

	--n_replies_left;
	if (n_replies_left == 0) {
		EVLOCK_LOCK(rp->lock, 0);
		EVTHREAD_COND_SIGNAL(rp->reqs_cmpl_cond);
		EVLOCK_UNLOCK(rp->lock, 0);
	}
}
static void
getaddrinfo_race_gotresolve_test(void *arg)
{
	struct race_param rp;
	struct evdns_server_port *dns_port = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];
	int i;

	// Some stress is needed to yield inside getaddrinfo between resolve_ipv4 and resolve_ipv6
	int n_reqs = 16384;
#ifdef _SC_NPROCESSORS_ONLN
	int n_threads = sysconf(_SC_NPROCESSORS_ONLN) + 1;
#else
	int n_threads = 17;
#endif
	THREAD_T thread[n_threads];
	struct timeval tv;

	(void)arg;

	evthread_use_pthreads();

	rp.base = event_base_new();
	tt_assert(rp.base);
	if (evthread_make_base_notifiable(rp.base) < 0)
		tt_abort_msg("Couldn't make base notifiable!");

	dns_port = regress_get_udp_dnsserver(rp.base, &portnum, NULL,
									 regress_dns_server_cb, reissue_table);
	tt_assert(dns_port);

	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	rp.dns = evdns_base_new(rp.base, 0);
	tt_assert(!evdns_base_nameserver_ip_add(rp.dns, buf));

	n_replies_left = n_reqs;

	EVTHREAD_ALLOC_LOCK(rp.lock, 0);
	EVTHREAD_ALLOC_COND(rp.reqs_cmpl_cond);
	EVTHREAD_ALLOC_COND(rp.bw_threads_exited_cond);
	tt_assert(rp.lock);
	tt_assert(rp.reqs_cmpl_cond);
	tt_assert(rp.bw_threads_exited_cond);
	rp.bw_threads = 0;
	rp.stopping = 0;

	// Run resolver thread
	THREAD_START(thread[0], race_base_run, &rp);
	// Run busy-wait threads used to force yield this thread
	for (i = 1; i < n_threads; i++) {
		rp.bw_threads++;
		THREAD_START(thread[i], race_busywait_run, &rp);
	}

	EVLOCK_LOCK(rp.lock, 0);
	rp.locked = 1;

	for (i = 0; i < n_reqs; ++i) {
		tt_assert(evdns_getaddrinfo(rp.dns, "foof.example.com", "80", NULL, race_gai_cb, &rp));
		// This magic along with busy-wait threads make this thread yield frequently
		if (i % 100 == 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 10000;
			evutil_usleep_(&tv);
		}
	}

	exit_base = rp.base;

	// Wait for some time
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	EVTHREAD_COND_WAIT_TIMED(rp.reqs_cmpl_cond, rp.lock, &tv);

	// Stop busy-wait threads
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	rp.stopping = 1;
	tt_assert(EVTHREAD_COND_WAIT_TIMED(rp.bw_threads_exited_cond, rp.lock, &tv) == 0);

	EVLOCK_UNLOCK(rp.lock, 0);
	rp.locked = 0;

	evdns_base_free(rp.dns, 1 /** fail requests */);

	tt_int_op(n_replies_left, ==, 0);

end:
	if (rp.locked)
		EVLOCK_UNLOCK(rp.lock, 0);
	EVTHREAD_FREE_LOCK(rp.lock, 0);
	EVTHREAD_FREE_COND(rp.reqs_cmpl_cond);
	EVTHREAD_FREE_COND(rp.bw_threads_exited_cond);
	evdns_close_server_port(dns_port);
	event_base_loopbreak(rp.base);
	event_base_free(rp.base);
}
#endif

static void
test_tcp_resolve(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = evdns_base_new(base, 0);
	ev_uint16_t portnum = 0;
	struct evdns_request *req = NULL;
	struct generic_dns_callback_result r;
	struct in_addr addrs[2048];
	char buf[64];
	int k_;
	exit_base = base;

	tt_assert(base);

	tt_assert(regress_dnsserver(base, &portnum, search_table, tcp_search_table));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	// small table
	req = evdns_base_resolve_ipv4(
			dns, "small.a.example.com", 0, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE, REPEAT_64("11.22.33.45"));
	tt_assert(search_table[0].seen == 1);
	tt_assert(tcp_search_table[0].seen == 0);

	// medium table
	req = evdns_base_resolve_ipv4(
		dns, "medium.b.example.com", DNS_QUERY_IGNTC, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	tt_assert(r.type != DNS_IPv4_A);
	tt_assert(r.result == DNS_ERR_TRUNCATED);
	tt_assert(search_table[1].seen == 1);
	tt_assert(tcp_search_table[1].seen == 0);

	req = evdns_base_resolve_ipv4(
		dns, "medium.b.example.com", DNS_QUERY_USEVC, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE, REPEAT_64("11.22.33.45") "," REPEAT_64("12.22.33.45"));
	tt_assert(search_table[1].seen == 1);
	tt_assert(tcp_search_table[1].seen == 1);

	// big table
	req = evdns_base_resolve_ipv4(
		dns, "large.c.example.com", DNS_QUERY_IGNTC, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	tt_assert(r.type != DNS_IPv4_A);
	tt_assert(r.result == DNS_ERR_TRUNCATED);
	tt_assert(search_table[2].seen == 1);
	tt_assert(tcp_search_table[2].seen == 0);

	req = evdns_base_resolve_ipv4(
		dns, "large.c.example.com", 0, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE,
		REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"));
	tt_assert(search_table[2].seen == 2);
	tt_assert(tcp_search_table[2].seen == 1);

	req = evdns_base_resolve_ipv4(
		dns, "large.c.example.com", DNS_QUERY_USEVC, generic_dns_callback, &r);
	tt_assert(req);
	n_replies_left = 1;
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE,
		REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"));
	tt_assert(search_table[2].seen == 2);
	tt_assert(tcp_search_table[2].seen == 2);

end:
	if (dns)
		evdns_base_free(dns, 0);

	regress_clean_dnsserver();
}

static void
test_tcp_resolve_pipeline(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = evdns_base_new(base, 0);
	ev_uint16_t portnum = 0;
	struct evdns_request *reqs[3] = {NULL, NULL, NULL};
	struct generic_dns_callback_result results[3];
	char buf[64];
	struct in_addr addrs[2048];
	int i, k_;
	exit_base = base;

	tt_assert(base);
	tt_assert(regress_dnsserver(base, &portnum, search_table, tcp_search_table));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));
	tt_assert(!evdns_base_set_option(dns, "use-vc", NULL));

	for (i = 0; i < 3; ++i) {
		reqs[i] = evdns_base_resolve_ipv4(
			dns, "large.c.example.com", 0, generic_dns_callback, &results[i]);
		tt_assert(reqs[i]);
	}

	n_replies_left = 3;
	event_base_dispatch(base);
	for (i = 0; i < 3; ++i) {
		assert_request_results(results[i], DNS_ERR_NONE,
			REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"));
	}
	tt_assert(search_table[2].seen == 0);
	tt_assert(tcp_search_table[2].seen == 3);

end:
	if (dns)
		evdns_base_free(dns, 0);
	regress_clean_dnsserver();
}

static void
test_tcp_resolve_many_clients(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns[3] = {evdns_base_new(base, 0), evdns_base_new(base, 0), evdns_base_new(base, 0)};
	struct evdns_request *req[3] = {NULL, NULL, NULL};
	struct generic_dns_callback_result r[3];
	int k_, i;
	ev_uint16_t portnum = 0;
	char buf[64];
	struct in_addr addrs[2048];
	exit_base = base;
	tt_assert(base);

	tt_assert(regress_dnsserver(base, &portnum, search_table, tcp_search_table));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);
	for (i = 0; i < 3; ++i) {
		tt_assert(!evdns_base_nameserver_ip_add(dns[i], buf));
		req[i] = evdns_base_resolve_ipv4(
				dns[i], "small.a.example.com", DNS_QUERY_USEVC, generic_dns_callback, &r[i]);
		tt_assert(req[i]);
	}

	n_replies_left = 3;
	event_base_dispatch(base);
	for (i = 0; i < 3; ++i) {
		assert_request_results(r[i], DNS_ERR_NONE, REPEAT_64("11.22.33.45"));
	}
	tt_assert(search_table[0].seen == 0);
	tt_assert(tcp_search_table[0].seen == 3);

end:
	for (i = 0; i < 3; ++i) {
		if (dns[i])
			evdns_base_free(dns[i], 0);
	}
	regress_clean_dnsserver();
}

static void
test_tcp_timeout(void *arg)
{
	struct generic_dns_callback_result r;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = evdns_base_new(base, 0);
	ev_uint16_t portnum = 0;
	struct evdns_request *req = NULL;
	char buf[64];

	exit_base = base;

	tt_assert(base);

	tt_assert(!evdns_base_set_option(dns, "timeout:", "1"));
	tt_assert(regress_dnsserver(base, &portnum, search_table, tcp_search_table));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);

	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	req = evdns_base_resolve_ipv4(
		dns, "lost.request.com", DNS_QUERY_USEVC, generic_dns_callback, &r);
	tt_assert(req);

	n_replies_left = 1;
	event_base_dispatch(base);

	tt_assert(DNS_ERR_TIMEOUT == r.result);

end:
	if (dns)
		evdns_base_free(dns, 0);

	regress_clean_dnsserver();
}

static void
test_edns(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evdns_base *dns = NULL;
	ev_uint16_t portnum = 0;
	char buf[64];
	struct generic_dns_callback_result r;
	struct in_addr addrs[2048]; /* used by macros `assert_request_results` */
	int k_; /* used by macros `assert_request_results` */

	exit_base = base;
	tt_assert(regress_dnsserver(base, &portnum, search_table, NULL));
	evutil_snprintf(buf, sizeof(buf), "127.0.0.1:%d", (int)portnum);
	dns = evdns_base_new(base, 0);
	tt_assert(!evdns_base_nameserver_ip_add(dns, buf));

	n_replies_left = 1;
	evdns_base_resolve_ipv4(dns, "medium.b.example.com",
		DNS_QUERY_IGNTC, generic_dns_callback, &r);
	event_base_dispatch(base);
	tt_int_op(r.result, ==, DNS_ERR_TRUNCATED);
	tt_int_op(r.count, ==, 0);

	tt_assert(!evdns_base_set_option(dns, "edns-udp-size", "4096"));
	n_replies_left = 1;
	evdns_base_resolve_ipv4(dns, "medium.b.example.com",
		DNS_QUERY_IGNTC, generic_dns_callback, &r);
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE, REPEAT_64("11.22.33.45") "," REPEAT_64("12.22.33.45"));

	n_replies_left = 1;
	evdns_base_resolve_ipv4(dns, "large.c.example.com",
		DNS_QUERY_IGNTC, generic_dns_callback, &r);
	event_base_dispatch(base);
	tt_int_op(r.result, ==, DNS_ERR_TRUNCATED);
	tt_int_op(r.count, ==, 0);

	tt_assert(!evdns_base_set_option(dns, "edns-udp-size", "65535"));
	n_replies_left = 1;
	evdns_base_resolve_ipv4(dns, "large.c.example.com",
		DNS_QUERY_IGNTC, generic_dns_callback, &r);
	event_base_dispatch(base);
	assert_request_results(r, DNS_ERR_NONE,
		REPEAT_256("11.22.33.45") "," REPEAT_256("12.22.33.45") "," REPEAT_256("13.22.33.45") "," REPEAT_256("14.22.33.45"));

end:
	if (dns)
		evdns_base_free(dns, 0);

	regress_clean_dnsserver();
}

static void
test_set_so_rcvbuf_so_sndbuf(void *arg)
{
	struct basic_test_data *data = arg;
	struct evdns_base *dns_base;

	dns_base = evdns_base_new(data->base, 0);
	tt_assert(dns_base);

	tt_assert(!evdns_base_set_option(dns_base, "so-rcvbuf", "10240"));
	tt_assert(!evdns_base_set_option(dns_base, "so-sndbuf", "10240"));

	/* actually check SO_RCVBUF/SO_SNDBUF not fails */
	tt_assert(!evdns_base_nameserver_ip_add(dns_base, "127.0.0.1"));

end:
	if (dns_base)
		evdns_base_free(dns_base, 0);
}

static void
test_set_option(void *arg)
{
#define SUCCESS 0
#define FAIL -1
	struct basic_test_data *data = arg;
	struct evdns_base *dns_base;
	size_t i;
	/* Option names are allowed to have ':' at the end.
	 * So all test option names come in pairs.
	 */
	const char *int_options[] = {
		"ndots", "ndots:",
		"max-timeouts", "max-timeouts:",
		"max-inflight", "max-inflight:",
		"attempts", "attempts:",
		"randomize-case", "randomize-case:",
		"so-rcvbuf", "so-rcvbuf:",
		"so-sndbuf", "so-sndbuf:",
	};
	const char *timeval_options[] = {
		"timeout", "timeout:",
		"getaddrinfo-allow-skew", "getaddrinfo-allow-skew:",
		"initial-probe-timeout", "initial-probe-timeout:",
	};
	const char *addr_port_options[] = {
		"bind-to", "bind-to:",
	};
	const char *options_without_values[] = {
		"use-vc", "use-vc:",
		"ignore-tc", "ignore-tc:",
	};

	dns_base = evdns_base_new(data->base, 0);
	tt_assert(dns_base);

	for (i = 0; i < ARRAY_SIZE(int_options); ++i) {
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, int_options[i], "0"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, int_options[i], "1"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, int_options[i], "10000"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, int_options[i], "foo"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, int_options[i], "3.14"));
	}

	for (i = 0; i < ARRAY_SIZE(timeval_options); ++i) {
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, timeval_options[i], "1"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, timeval_options[i], "0.001"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, timeval_options[i], "3.14"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, timeval_options[i], "10000"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, timeval_options[i], "0"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, timeval_options[i], "foo"));
	}

	for (i = 0; i < ARRAY_SIZE(addr_port_options); ++i) {
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, addr_port_options[i], "8.8.8.8:80"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, addr_port_options[i], "1.2.3.4"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, addr_port_options[i], "::1:82"));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, addr_port_options[i], "3::4"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, addr_port_options[i], "3.14"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, addr_port_options[i], "foo"));
	}

	for (i = 0; i < ARRAY_SIZE(options_without_values); ++i) {
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, options_without_values[i], NULL));
		tt_assert(SUCCESS == evdns_base_set_option(dns_base, options_without_values[i], ""));
		tt_assert(FAIL == evdns_base_set_option(dns_base, options_without_values[i], "1"));
		tt_assert(FAIL == evdns_base_set_option(dns_base, options_without_values[i], "foo"));
	}

#undef SUCCESS
#undef FAIL
end:
	if (dns_base)
		evdns_base_free(dns_base, 0);
}

static void
test_set_server_option(void *arg)
{
#define SUCCESS 0
#define FAIL -1
	struct basic_test_data *data = arg;
	struct evdns_server_port *tcp_port = NULL;
	struct evdns_server_port *udp_port = NULL;
	evutil_socket_t udp_sock = -1;
	evutil_socket_t tcp_sock = -1;
	ev_uint16_t portnum;
	size_t i;
	enum evdns_server_option tcp_options[] = {EVDNS_SOPT_TCP_MAX_CLIENTS, EVDNS_SOPT_TCP_IDLE_TIMEOUT};

	portnum = 0;
	tcp_port = regress_get_tcp_dnsserver(data->base, &portnum, &tcp_sock, NULL, NULL);
	tt_assert(tcp_port);
	portnum = 0;
	udp_port = regress_get_udp_dnsserver(data->base, &portnum, &udp_sock, NULL, NULL);
	tt_assert(udp_port);

	for (i = 0; i < ARRAY_SIZE(tcp_options); ++i) {
		tt_assert(SUCCESS == evdns_server_port_set_option(tcp_port, tcp_options[i], 0));
		tt_assert(SUCCESS == evdns_server_port_set_option(tcp_port, tcp_options[i], 1));
		tt_assert(SUCCESS == evdns_server_port_set_option(tcp_port, tcp_options[i], 100));
		tt_assert(FAIL == evdns_server_port_set_option(udp_port, tcp_options[i], 0));
		tt_assert(FAIL == evdns_server_port_set_option(udp_port, tcp_options[i], 100));
	}

#undef SUCCESS
#undef FAIL
end:
	if (tcp_port)
		evdns_close_server_port(tcp_port);
	if (tcp_sock >= 0)
		evutil_closesocket(tcp_sock);
	if (udp_port)
		evdns_close_server_port(udp_port);
	if (udp_sock >= 0)
		evutil_closesocket(udp_sock);
}

#define DNS_LEGACY(name, flags)					       \
	{ #name, run_legacy_test_fn, flags|TT_LEGACY, &legacy_setup,   \
		    dns_##name }

struct testcase_t dns_testcases[] = {
	DNS_LEGACY(server, TT_FORK|TT_NEED_BASE),
	DNS_LEGACY(gethostbyname, TT_FORK|TT_NEED_BASE|TT_NEED_DNS|TT_OFF_BY_DEFAULT),
	DNS_LEGACY(gethostbyname6, TT_FORK|TT_NEED_BASE|TT_NEED_DNS|TT_OFF_BY_DEFAULT),
	DNS_LEGACY(gethostbyaddr, TT_FORK|TT_NEED_BASE|TT_NEED_DNS|TT_OFF_BY_DEFAULT),
	{ "resolve_reverse", dns_resolve_reverse, TT_FORK|TT_OFF_BY_DEFAULT, NULL, NULL },
	{ "search_empty", dns_search_empty_test, TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "search", dns_search_test, TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "search_lower", dns_search_lower_test, TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "search_cancel", dns_search_cancel_test,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "retry", dns_retry_test, TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "retry_disable_when_inactive", dns_retry_disable_when_inactive_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "probe_settings", dns_probe_settings_test, TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "reissue", dns_reissue_test, TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "reissue_disable_when_inactive", dns_reissue_disable_when_inactive_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "inflight", dns_inflight_test, TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "bufferevent_connect_hostname", test_bufferevent_connect_hostname,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
#ifdef EVENT__HAVE_SETRLIMIT
	{ "bufferevent_connect_hostname_emfile", test_bufferevent_connect_hostname,
	  TT_FORK|TT_NEED_BASE, &basic_setup, (char*)"emfile" },
#endif
	{ "bufferevent_connect_hostname_hints", test_bufferevent_connect_hostname,
	  TT_FORK|TT_NEED_BASE, &basic_setup, (char*)"hints" },
	{ "disable_when_inactive", dns_disable_when_inactive_test,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "disable_when_inactive_no_ns", dns_disable_when_inactive_no_ns_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },

	{ "initialize_nameservers", dns_initialize_nameservers_test,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
#ifndef _WIN32
	{ "nameservers_no_default", dns_nameservers_no_default_test,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
#endif

	{ "getaddrinfo_async", test_getaddrinfo_async,
	  TT_FORK|TT_NEED_BASE, &basic_setup, (char*)"" },
	{ "getaddrinfo_cancel_stress", test_getaddrinfo_async_cancel_stress,
	  TT_FORK, NULL, NULL },

#ifdef EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
	{ "leak_shutdown", test_dbg_leak_shutdown, TT_FORK, &testleak_funcs, NULL },
	{ "leak_cancel", test_dbg_leak_cancel, TT_FORK, &testleak_funcs, NULL },

	{ "leak_resume", test_dbg_leak_resume_, TT_FORK, &testleak_funcs, NULL },
	{ "leak_cancel_and_resume", test_dbg_leak_cancel_and_resume_,
	  TT_FORK, &testleak_funcs, NULL },
	{ "leak_resume_send_err", test_dbg_leak_resume_send_err_,
	  TT_FORK, &testleak_funcs, NULL },
	{ "leak_cancel_and_resume_send_err", test_dbg_leak_cancel_and_resume_send_err_,
	  TT_FORK, &testleak_funcs, NULL },
#endif

	{ "client_fail_requests", dns_client_fail_requests_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
	{ "client_fail_waiting_requests", dns_client_fail_requests_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, (char*)"limit-inflight" },
	{ "client_fail_requests_getaddrinfo",
	  dns_client_fail_requests_getaddrinfo_test,
	  TT_FORK|TT_NEED_BASE|TT_NO_LOGS, &basic_setup, NULL },
#ifdef EVTHREAD_USE_PTHREADS_IMPLEMENTED
	{ "getaddrinfo_race_gotresolve",
	  getaddrinfo_race_gotresolve_test,
	  TT_FORK|TT_OFF_BY_DEFAULT, NULL, NULL },
#endif
	{ "tcp_resolve", test_tcp_resolve,
	  TT_FORK | TT_NEED_BASE, &basic_setup, NULL },
	{ "tcp_resolve_pipeline", test_tcp_resolve_pipeline,
	  TT_FORK | TT_NEED_BASE, &basic_setup, NULL },
	{ "tcp_resolve_many_clients", test_tcp_resolve_many_clients,
	  TT_FORK | TT_NEED_BASE, &basic_setup, NULL },
	{ "tcp_timeout", test_tcp_timeout,
	  TT_FORK | TT_NEED_BASE, &basic_setup, NULL },

	{ "set_SO_RCVBUF_SO_SNDBUF", test_set_so_rcvbuf_so_sndbuf,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "set_options", test_set_option,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "set_server_options", test_set_server_option,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "edns", test_edns,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },

	END_OF_TESTCASES
};

