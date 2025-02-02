/*
 * Copyright (c) 2010-2012 Niels Provos and Nick Mathewson
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

#ifndef REGRESS_TESTUTILS_H_INCLUDED_
#define REGRESS_TESTUTILS_H_INCLUDED_

#include "event2/dns.h"
#include "event2/dns_struct.h"

struct regress_dns_server_table {
	const char *q;
	const char *anstype;
	const char *ans; /* Comma-separated list of IP numbers (e.g. "1.2.3.4", "1.2.3.4,5.6.7.8") */
	int seen;
	int lower;
};

struct evdns_server_port *
regress_get_udp_dnsserver(struct event_base *base,
    ev_uint16_t *portnum,
    evutil_socket_t *psock,
    evdns_request_callback_fn_type cb,
    void *arg);

struct evdns_server_port *
regress_get_tcp_dnsserver(struct event_base *base,
    ev_uint16_t *portnum,
    evutil_socket_t *psock,
    evdns_request_callback_fn_type cb,
    void *arg);

/* Helper: return the port that a socket is bound on, in host order. */
int regress_get_socket_port(evutil_socket_t fd);

/* used to look up pre-canned responses in a search table */
void regress_dns_server_cb(
	struct evdns_server_request *req, void *data);

/* Globally allocates a dns server that serves from a search table.
   TCP and UDP listeners are created on the same port number. If one of the
   input search tables is NULL appropriate listener is not created. */
int regress_dnsserver(struct event_base *base, ev_uint16_t *port,
    struct regress_dns_server_table *udp_seach_table,
    struct regress_dns_server_table *tcp_seach_table);

/* clean up the global dns server resources */
void regress_clean_dnsserver(void);

struct evconnlistener;
struct sockaddr;
int regress_get_listener_addr(struct evconnlistener *lev,
    struct sockaddr *sa, ev_socklen_t *socklen);

/* Parse comma-separated list of IP addresses. */
int parse_csv_address_list(const char *s, int family,
    void *addrs, size_t addrs_size);

/* Parse comma-separated list of NS records
 * in format "<ttl> <name>", ex. "600 ns1.abcd.com,300 ns2.safeweb.com". */
int parse_csv_ns_list(const char *s, struct evdns_reply_ns *ns,
    size_t ns_size);

#endif /* REGRESS_TESTUTILS_H_INCLUDED_ */

