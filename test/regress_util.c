/*
 * Copyright (c) 2009 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifndef WIN32
#include <sys/socket.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event2/util.h"

void util_suite(void);

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
	{ "1:2:33333:4::", { 0, 0, 0, 0 }, BAD },
	{ "1:2:3:4:5:6:7:8:9", { 0, 0, 0, 0 }, BAD },
	{ "1::2::3", { 0, 0, 0, 0 }, BAD },
	{ ":::1", { 0, 0, 0, 0 }, BAD },
	{ NULL, { 0, 0, 0, 0,  }, BAD },
};

static void
regress_ipv4_parse(void)
{
	int i;
	int ok = 1;
	printf("Testing IPv4 parsing...");

	for (i = 0; ipv4_entries[i].addr; ++i) {
		char written[128];
		struct ipv4_entry *ent = &ipv4_entries[i];
		struct in_addr in;
		int r;
		r = evutil_inet_pton(AF_INET, ent->addr, &in);
		if (r == 0) {
			if (ent->status != BAD) {
				printf("%s did not parse, but it's a good address!\n",
					   ent->addr);
				ok = 0;
			}
			continue;
		}
		if (ent->status == BAD) {
			printf("%s parsed, but we expected an error\n", ent->addr);
			ok = 0;
			continue;
		}
		if (ntohl(in.s_addr) != ent->res) {
			printf("%s parsed to %lx, but we expected %lx\n", ent->addr,
				   (unsigned long)ntohl(in.s_addr),
				   (unsigned long)ent->res);
			ok = 0;
			continue;
		}
		if (ent->status == CANONICAL) {
			const char *w = evutil_inet_ntop(AF_INET, &in, written,
											 sizeof(written));
			if (!w) {
				printf("Tried to write out %s; got NULL.\n", ent->addr);
				ok = 0;
				continue;
			}
			if (strcmp(written, ent->addr)) {
				printf("Tried to write out %s; got %s\n", ent->addr, written);
				ok = 0;
				continue;
			}
		}

	}
	if (!ok) {
		printf("FAILED\n");
		exit(1);
	}
	printf("OK\n");
}

static void
regress_ipv6_parse(void)
{
#ifdef AF_INET6
	int i, j;
	int ok = 1;
	printf("Testing IPv6 parsing...");

	for (i = 0; ipv6_entries[i].addr; ++i) {
		char written[128];
		struct ipv6_entry *ent = &ipv6_entries[i];
		struct in6_addr in6;
		int r;
		r = evutil_inet_pton(AF_INET6, ent->addr, &in6);
		if (r == 0) {
			if (ent->status != BAD) {
				printf("%s did not parse, but it's a good address!\n",
					   ent->addr);
				ok = 0;
			}
			continue;
		}
		if (ent->status == BAD) {
			printf("%s parsed, but we expected an error\n", ent->addr);
			ok = 0;
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
				printf("%s did not parse as expected.\n", ent->addr);
				ok = 0;
				continue;
			}
		}
		if (ent->status == CANONICAL) {
			const char *w = evutil_inet_ntop(AF_INET6, &in6, written,
											 sizeof(written));
			if (!w) {
				printf("Tried to write out %s; got NULL.\n", ent->addr);
				ok = 0;
				continue;
			}
			if (strcmp(written, ent->addr)) {
				printf("Tried to write out %s; got %s\n", ent->addr, written);
				ok = 0;
				continue;
			}
		}

	}
	if (!ok) {
		printf("FAILED\n");
		exit(1);
	}
	printf("OK\n");
#else
	print("Skipping IPv6 address parsing.\n");
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
	{ "::1", AF_INET6, "::1", 0 },
	{ "1:2::1", AF_INET6, "1:2::1", 0 },
	{ "192.168.0.1:50", AF_INET, "192.168.0.1", 50 },
	{ "1.2.3.4", AF_INET, "1.2.3.4", 0 },
	{ NULL, 0, NULL, 0 },
};

static void
regress_sockaddr_port_parse(void)
{
	struct sockaddr_storage ss;
	int ok = 1;
	int i, r;

	for (i = 0; sa_port_ents[i].parse; ++i) {
		struct sa_port_ent *ent = &sa_port_ents[i];
		memset(&ss, 0, sizeof(ss));
		r = evutil_parse_sockaddr_port(ent->parse, (struct sockaddr*)&ss, sizeof(ss));
		if (r < 0) {
			if (ent->sa_family) {
				printf("Couldn't parse %s!\n", ent->parse);
				ok = 0;
			}
			continue;
		} else if (! ent->sa_family) {
			printf("Shouldn't have been able to parse %s!\n",
				   ent->parse);
			ok = 0;
			continue;
		}
		if (ent->sa_family == AF_INET) {
			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(sin));
			sin.sin_len = sizeof(sin);
			sin.sin_family = AF_INET;
			sin.sin_port = htons(ent->port);
			r = evutil_inet_pton(AF_INET, ent->addr, &sin.sin_addr);
			if (1 != r) {
				printf("Couldn't parse ipv4 target %s.\n", ent->addr);
				ok = 0;
			} else if (memcmp(&sin, &ss, sizeof(sin))) {
				printf("Parse for %s was not as expected.\n", ent->parse);
				ok = 0;
			}
		} else {
			struct sockaddr_in6 sin6;
			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_len = sizeof(sin6);
			sin6.sin6_family = AF_INET6;
			sin6.sin6_port = htons(ent->port);
			r = evutil_inet_pton(AF_INET6, ent->addr, &sin6.sin6_addr);
			if (1 != r) {
				printf("Couldn't parse ipv6 target %s.\n", ent->addr);
				ok = 0;
			} else if (memcmp(&sin6, &ss, sizeof(sin6))) {
				printf("Parse for %s was not as expected.\n", ent->parse);
				ok = 0;
			}
		}
	}

	if (!ok) {
		printf("FAILED\n");
		exit(1);
	}
	printf("OK\n");
}

void
util_suite(void)
{
	regress_ipv4_parse();
	regress_ipv6_parse();
	regress_sockaddr_port_parse();
}
