/*
 * Copyright (c) 2009 Niels Provos, Nick Mathewson
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

/** @file bufferevent_evdns.c
 *
 * This module contains code to implement the asynchronous
 * resolve-then-connect behavior of bufferevent_socket_connect_hostname.
 *
 * It isn't part of bufferevent_socket because evdns is in libevent_extras,
 * and bufferevent is in libevent_core.
 */

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "event-config.h"

#include <sys/types.h>
#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef _EVENT_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _EVENT_HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#include <stdlib.h>
#include <string.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/dns.h>
#include "bufferevent-internal.h"
#include "mm-internal.h"

/* Holds info passed to the dns callback  */
struct resolveinfo {
	ev_uint8_t family; /* address family that we tried to resolve. */
	ev_uint16_t port; /* port to connect to, in network order. */
	struct bufferevent *bev; /* bufferevent to inform of the resolve. */
};

/* Callback: Invoked when we are done resolving (or failing to resolve) the
 * hostname */
static void
dns_reply_callback(int result, char type, int count, int ttl, void *addresses,
    void *arg)
{
	struct resolveinfo *info = arg;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr *sa = NULL;
	int socklen;

	EVUTIL_ASSERT(info->bev);
	BEV_LOCK(info->bev);

	if (result != DNS_ERR_NONE || count == 0) {
		_bufferevent_run_eventcb(info->bev, BEV_EVENT_ERROR);
		_bufferevent_decref_and_unlock(info->bev);
		memset(info, 0, sizeof(*info));
		mm_free(info);
		return;
	}

	if (type == DNS_IPv4_A) {
		EVUTIL_ASSERT(info->family == AF_INET);
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = info->port;
		/* XXX handle multiple addresses better */
		sin.sin_addr.s_addr = *(ev_uint32_t*)addresses;
		sa = (struct sockaddr*)&sin;
		socklen = sizeof(sin);
	} else if (type == DNS_IPv6_AAAA) {
		EVUTIL_ASSERT(info->family == AF_INET6);
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET;
		sin6.sin6_port = info->port;
		/* XXX handle multiple addresses better */
		memcpy(sin6.sin6_addr.s6_addr, addresses, 16);
		sa = (struct sockaddr*)&sin6;
		socklen = sizeof(sin6);
	} else {
		EVUTIL_ASSERT(info->family == AF_INET ||
		    info->family == AF_INET6);
		return; /* unreachable */
	}

	bufferevent_socket_connect(info->bev, sa, socklen);
	_bufferevent_decref_and_unlock(info->bev);
	memset(info, 0, sizeof(*info));
	mm_free(info);
}

/* Implements the asynchronous-resolve side of
 * bufferevent_socket_connect_hostname(). */
int
_bufferevent_socket_connect_hostname_evdns(
	struct bufferevent *bufev,
	struct evdns_base *evdns_base,
	int family,
	const char *hostname,
	int port)
{
	struct evdns_request *r;
	struct resolveinfo *resolveinfo;

	if (family == AF_UNSPEC)
		family = AF_INET; /* XXXX handle "unspec" correctly */
	if (family != AF_INET && family != AF_INET6)
		return -1;
	if (!bufev || !evdns_base || !hostname)
		return -1;
	if (port < 1 || port > 65535)
		return -1;

	resolveinfo = mm_calloc(1, sizeof(resolveinfo));
	if (!resolveinfo)
		return -1;
	resolveinfo->family = family;
	resolveinfo->port = htons(port);
	resolveinfo->bev = bufev;

	if (family == AF_INET) {
		r = evdns_base_resolve_ipv4(evdns_base, hostname, 0,
		    dns_reply_callback, resolveinfo);
	} else {
		r = evdns_base_resolve_ipv6(evdns_base, hostname, 0,
		    dns_reply_callback, resolveinfo);
	}

	if (!r) {
		mm_free(resolveinfo);
		return -1;
	}

	/* We either need to incref the bufferevent here, or have some code to
	 * cancel the resolve if the bufferevent gets freed.  Let's take the
	 * first approach. */
	bufferevent_incref(bufev);
	return 0;
}

