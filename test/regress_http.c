/*
 * Copyright (c) 2003-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
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

#include "event2/event-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "event2/dns.h"

#include "event.h"
#include "evhttp.h"
#include "log-internal.h"
#include "util-internal.h"
#include "http-internal.h"
#include "regress.h"
#include "regress_testutils.h"

static struct evhttp *http;
/* set if a test needs to call loopexit on a base */
static struct event_base *base;

static char const BASIC_REQUEST_BODY[] = "This is funny";

static void http_basic_cb(struct evhttp_request *req, void *arg);
static void http_chunked_cb(struct evhttp_request *req, void *arg);
static void http_post_cb(struct evhttp_request *req, void *arg);
static void http_put_cb(struct evhttp_request *req, void *arg);
static void http_delete_cb(struct evhttp_request *req, void *arg);
static void http_delay_cb(struct evhttp_request *req, void *arg);
static void http_large_delay_cb(struct evhttp_request *req, void *arg);
static void http_badreq_cb(struct evhttp_request *req, void *arg);
static void http_dispatcher_cb(struct evhttp_request *req, void *arg);
static int
http_bind(struct evhttp *myhttp, ev_uint16_t *pport)
{
	int port;
	struct evhttp_bound_socket *sock;

	sock = evhttp_bind_socket_with_handle(myhttp, "127.0.0.1", *pport);
	if (sock == NULL)
		event_errx(1, "Could not start web server");

	port = regress_get_socket_port(evhttp_bound_socket_get_fd(sock));
	if (port < 0)
		return -1;
	*pport = (ev_uint16_t) port;

	return 0;
}

static struct evhttp *
http_setup(ev_uint16_t *pport, struct event_base *base)
{
	struct evhttp *myhttp;

	/* Try a few different ports */
	myhttp = evhttp_new(base);

	if (http_bind(myhttp, pport) < 0)
		return NULL;

	/* Register a callback for certain types of requests */
	evhttp_set_cb(myhttp, "/test", http_basic_cb, NULL);
	evhttp_set_cb(myhttp, "/chunked", http_chunked_cb, NULL);
	evhttp_set_cb(myhttp, "/streamed", http_chunked_cb, NULL);
	evhttp_set_cb(myhttp, "/postit", http_post_cb, NULL);
	evhttp_set_cb(myhttp, "/putit", http_put_cb, NULL);
	evhttp_set_cb(myhttp, "/deleteit", http_delete_cb, NULL);
	evhttp_set_cb(myhttp, "/delay", http_delay_cb, NULL);
	evhttp_set_cb(myhttp, "/largedelay", http_large_delay_cb, NULL);
	evhttp_set_cb(myhttp, "/badrequest", http_badreq_cb, NULL);
	evhttp_set_cb(myhttp, "/", http_dispatcher_cb, NULL);
	return (myhttp);
}

#ifndef NI_MAXSERV
#define NI_MAXSERV 1024
#endif

static int
http_connect(const char *address, u_short port)
{
	/* Stupid code for connecting */
#ifdef WIN32
	struct hostent *he;
	struct sockaddr_in sin;
#else
	struct addrinfo ai, *aitop;
	char strport[NI_MAXSERV];
#endif
	struct sockaddr *sa;
	int slen;
	evutil_socket_t fd;

#ifdef WIN32
	if (!(he = gethostbyname(address))) {
		event_warn("gethostbyname");
	}
	memcpy(&sin.sin_addr, he->h_addr_list[0], he->h_length);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	slen = sizeof(struct sockaddr_in);
	sa = (struct sockaddr*)&sin;
#else
	memset(&ai, 0, sizeof(ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = SOCK_STREAM;
	evutil_snprintf(strport, sizeof(strport), "%d", port);
	if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
		event_warn("getaddrinfo");
		return (-1);
	}
	sa = aitop->ai_addr;
	slen = aitop->ai_addrlen;
#endif

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		event_err(1, "socket failed");

	evutil_make_socket_nonblocking(fd);
	if (connect(fd, sa, slen) == -1) {
#ifdef WIN32
		int tmp_err = WSAGetLastError();
		if (tmp_err != WSAEINPROGRESS && tmp_err != WSAEINVAL &&
		    tmp_err != WSAEWOULDBLOCK)
			event_err(1, "connect failed");
#else
		if (errno != EINPROGRESS)
			event_err(1, "connect failed");
#endif
	}

#ifndef WIN32
	freeaddrinfo(aitop);
#endif

	return (fd);
}

static void
http_readcb(struct bufferevent *bev, void *arg)
{
	const char *what = BASIC_REQUEST_BODY;

	event_debug(("%s: %s\n", __func__, EVBUFFER_DATA(bufferevent_get_input(bev))));

	if (evbuffer_find(bufferevent_get_input(bev),
		(const unsigned char*) what, strlen(what)) != NULL) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		enum message_read_status done;

		req->kind = EVHTTP_RESPONSE;
		done = evhttp_parse_firstline(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		if (done == 1 &&
		    evhttp_find_header(req->input_headers,
			"Content-Type") != NULL)
			test_ok++;

	 out:
		evhttp_request_free(req);
		bufferevent_disable(bev, EV_READ);
		if (base)
			event_base_loopexit(base, NULL);
		else
			event_loopexit(NULL);
	}
}

static void
http_writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
	event_loopexit(NULL);
}

static void
http_basic_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(req->input_headers, "Empty") != NULL;
	event_debug(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* For multi-line headers test */
	{
		const char *multi =
		    evhttp_find_header(req->input_headers,"X-multi");
		if (multi) {
			if (strcmp("END", multi + strlen(multi) - 3) == 0)
				test_ok++;
			if (evhttp_find_header(req->input_headers, "X-Last"))
				test_ok++;
		}
	}

	/* injecting a bad content-length */
	if (evhttp_find_header(req->input_headers, "X-Negative"))
		evhttp_add_header(req->output_headers,
		    "Content-Length", "-100");

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static char const* const CHUNKS[] = {
	"This is funny",
	"but not hilarious.",
	"bwv 1052"
};

struct chunk_req_state {
	struct evhttp_request *req;
	int i;
};

static void
http_chunked_trickle_cb(evutil_socket_t fd, short events, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	struct chunk_req_state *state = arg;
	struct timeval when = { 0, 0 };

	evbuffer_add_printf(evb, "%s", CHUNKS[state->i]);
	evhttp_send_reply_chunk(state->req, evb);
	evbuffer_free(evb);

	if (++state->i < sizeof(CHUNKS)/sizeof(CHUNKS[0])) {
		event_once(-1, EV_TIMEOUT,
		    http_chunked_trickle_cb, state, &when);
	} else {
		evhttp_send_reply_end(state->req);
		free(state);
	}
}

static void
http_chunked_cb(struct evhttp_request *req, void *arg)
{
	struct timeval when = { 0, 0 };
	struct chunk_req_state *state = malloc(sizeof(struct chunk_req_state));
	event_debug(("%s: called\n", __func__));

	memset(state, 0, sizeof(struct chunk_req_state));
	state->req = req;

	if (strcmp(evhttp_request_uri(req), "/streamed") == 0) {
		evhttp_add_header(req->output_headers, "Content-Length", "39");
	}

	/* generate a chunked/streamed reply */
	evhttp_send_reply_start(req, HTTP_OK, "Everything is fine");

	/* but trickle it across several iterations to ensure we're not
	 * assuming it comes all at once */
	event_once(-1, EV_TIMEOUT, http_chunked_trickle_cb, state, &when);
}

static void
http_complete_write(evutil_socket_t fd, short what, void *arg)
{
	struct bufferevent *bev = arg;
	const char *http_request = "host\r\n"
	    "Connection: close\r\n"
	    "\r\n";
	bufferevent_write(bev, http_request, strlen(http_request));
}

static void
http_basic_test(void)
{
	struct timeval tv;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0, port2 = 0;

	test_ok = 0;

	http = http_setup(&port, NULL);

	/* bind to a second socket */
	if (http_bind(http, &port2) == -1) {
		fprintf(stdout, "FAILED (bind)\n");
		exit(1);
	}

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_readcb, http_writecb,
	    http_errorcb, NULL);

	/* first half of the http request */
	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: some";

	bufferevent_write(bev, http_request, strlen(http_request));
	evutil_timerclear(&tv);
	tv.tv_usec = 10000;
	event_once(-1, EV_TIMEOUT, http_complete_write, bev, &tv);

	event_dispatch();

	tt_assert(test_ok == 3);

	/* connect to the second port */
	bufferevent_free(bev);
	evutil_closesocket(fd);

	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_readcb, http_writecb,
	    http_errorcb, NULL);

	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_dispatch();

	bufferevent_free(bev);
	evutil_closesocket(fd);

	evhttp_free(http);

	tt_assert(test_ok == 5);
 end:
	;
}

static void
http_delay_reply(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_request *req = arg;

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", NULL);

	++test_ok;
}

static void
http_delay_cb(struct evhttp_request *req, void *arg)
{
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 200 * 1000;

	event_once(-1, EV_TIMEOUT, http_delay_reply, req, &tv);
}

static void
http_badreq_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf = evbuffer_new();

	evhttp_add_header(req->output_headers, "Content-Type", "text/xml; charset=UTF-8");
	evbuffer_add_printf(buf, "Hello, %s!", "127.0.0.1");

	evhttp_send_reply(req, HTTP_OK, "OK", buf);
	evbuffer_free(buf);
}

static void
http_badreq_errorcb(struct bufferevent *bev, short what, void *arg)
{
	event_debug(("%s: called (what=%04x, arg=%p)", __func__, what, arg));
	/* ignore */
}

#ifndef SHUT_WR
#ifdef WIN32
#define SHUT_WR SD_SEND
#else
#define SHUT_WR 1
#endif
#endif

static void
http_badreq_readcb(struct bufferevent *bev, void *arg)
{
	const char *what = "Hello, 127.0.0.1";
	const char *bad_request = "400 Bad Request";

	event_debug(("%s: %s\n", __func__, EVBUFFER_DATA(bev->input)));

	if (evbuffer_find(bev->input,
		(const unsigned char *) bad_request,
		strlen(bad_request)) != NULL) {
		TT_FAIL(("%s: bad request detected", __func__));
		bufferevent_disable(bev, EV_READ);
		event_loopexit(NULL);
		return;
	}

	if (evbuffer_find(bev->input,
		(const unsigned char*) what, strlen(what)) != NULL) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		enum message_read_status done;

		req->kind = EVHTTP_RESPONSE;
		done = evhttp_parse_firstline(req, bev->input);
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers(req, bev->input);
		if (done != ALL_DATA_READ)
			goto out;

		if (done == 1 &&
		    evhttp_find_header(req->input_headers,
			"Content-Type") != NULL)
			test_ok++;

	out:
		evhttp_request_free(req);
		evbuffer_drain(bev->input, EVBUFFER_LENGTH(bev->input));
	}

	shutdown(bev->ev_read.ev_fd, SHUT_WR);
}

static void
http_badreq_successcb(evutil_socket_t fd, short what, void *arg)
{
	event_debug(("%s: called (what=%04x, arg=%p)", __func__, what, arg));
	event_loopexit(NULL);
}

static void
http_bad_request_test(void)
{
	struct timeval tv;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port=0, port2=0;

	test_ok = 0;

	/* fprintf(stdout, "Testing \"Bad Request\" on connection close: "); */

	http = http_setup(&port, NULL);

	/* bind to a second socket */
	if (http_bind(http, &port2) == -1)
		TT_DIE(("Bind socket failed"));

	/* NULL request test */
	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_badreq_readcb, http_writecb,
	    http_badreq_errorcb, NULL);
	bufferevent_enable(bev, EV_READ);

	/* real NULL request */
	http_request = "";

	shutdown(fd, SHUT_WR);
	timerclear(&tv);
	tv.tv_usec = 10000;
	event_once(-1, EV_TIMEOUT, http_badreq_successcb, bev, &tv);

	event_dispatch();

	bufferevent_free(bev);
	evutil_closesocket(fd);

	if (test_ok != 0) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Second answer (BAD REQUEST) on connection close */

	/* connect to the second port */
	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_badreq_readcb, http_writecb,
	    http_badreq_errorcb, NULL);
	bufferevent_enable(bev, EV_READ);

	/* first half of the http request */
	http_request =
		"GET /badrequest HTTP/1.0\r\n"	\
		"Connection: Keep-Alive\r\n"	\
		"\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	timerclear(&tv);
	tv.tv_usec = 10000;
	event_once(-1, EV_TIMEOUT, http_badreq_successcb, bev, &tv);

	event_dispatch();

	tt_int_op(test_ok, ==, 2);

end:
	evhttp_free(http);
	if (bev)
		bufferevent_free(bev);
}

static struct evhttp_connection *delayed_client;

static void
http_large_delay_cb(struct evhttp_request *req, void *arg)
{
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 3;

	event_once(-1, EV_TIMEOUT, http_delay_reply, req, &tv);
	evhttp_connection_fail(delayed_client, EVCON_HTTP_EOF);
}

/*
 * HTTP DELETE test,  just piggyback on the basic test
 */

static void
http_delete_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(req->input_headers, "Empty") != NULL;

	/* Expecting a DELETE request */
	if (req->type != EVHTTP_REQ_DELETE) {
		fprintf(stdout, "FAILED (delete type)\n");
		exit(1);
	}

	event_debug(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static void
http_delete_test(void)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, NULL);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_readcb, http_writecb,
	    http_errorcb, NULL);

	http_request =
	    "DELETE /deleteit HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_dispatch();

	bufferevent_free(bev);
	evutil_closesocket(fd);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	;
}

static void http_request_done(struct evhttp_request *, void *);
static void http_request_empty_done(struct evhttp_request *, void *);

static void
_http_connection_test(int persistent)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	tt_assert(test_ok);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/*
	 * if our connections are not supposed to be persistent; request
	 * a close from the server.
	 */
	if (!persistent)
		evhttp_add_header(req->output_headers, "Connection", "close");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("couldn't make request");
	}

	event_dispatch();

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
		exit(1);
	}

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_connection_test(void)
{
	_http_connection_test(0);
}
static void
http_persist_connection_test(void)
{
	_http_connection_test(1);
}

static struct regress_dns_server_table search_table[] = {
	{ "localhost", "A", "127.0.0.1", 0 },
	{ NULL, NULL, NULL, 0 }
};

static void
http_connection_async_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evdns_base *dns_base = NULL;
	ev_uint16_t portnum = 0;
	char address[64];

	tt_assert(regress_dnsserver(base, &portnum, search_table));

	dns_base = evdns_base_new(base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_base_new(base, dns_base, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	tt_assert(test_ok);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/*
	 * if our connections are not supposed to be persistent; request
	 * a close from the server.
	 */
	evhttp_add_header(req->output_headers, "Connection", "close");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("couldn't make request");
	}

	event_dispatch();

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
		exit(1);
	}

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
	if (dns_base)
		evdns_base_free(dns_base, 0);
	regress_clean_dnsserver();
}

static void
http_request_never_call(struct evhttp_request *req, void *arg)
{
	fprintf(stdout, "FAILED\n");
	exit(1);
}

static void
http_do_cancel(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_request *req = arg;
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 500 * 1000;

	evhttp_cancel_request(req);

	event_loopexit(&tv);

	++test_ok;
}

static void
http_cancel_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_never_call, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/delay"),
		  !=, -1);

	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000;

	event_once(-1, EV_TIMEOUT, http_do_cancel, req, &tv);

	event_dispatch();

	tt_int_op(test_ok, ==, 2);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_dispatch();

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Empty", "itis");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	const char *what = arg;

	if (req->response_code != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Content-Type") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(what)) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), what, strlen(what)) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_request_expect_error(struct evhttp_request *req, void *arg)
{
	if (req->response_code == HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

/* test virtual hosts */
static void
http_virtual_host_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *second = NULL, *third = NULL;

	http = http_setup(&port, NULL);

	/* virtual host */
	second = evhttp_new(NULL);
	evhttp_set_cb(second, "/funnybunny", http_basic_cb, NULL);
	third = evhttp_new(NULL);
	evhttp_set_cb(third, "/blackcoffee", http_basic_cb, NULL);

	if (evhttp_add_virtual_host(http, "foo.com", second) == -1) {
		tt_abort_msg("Couldn't add vhost");
	}

	if (evhttp_add_virtual_host(http, "bar.*.foo.com", third) == -1) {
		tt_abort_msg("Couldn't add wildcarded vhost");
	}

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/* make a request with a different host and expect an error */
	req = evhttp_request_new(http_request_expect_error, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	tt_assert(test_ok == 1);

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	tt_assert(test_ok == 1);

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "bar.magic.foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/blackcoffee") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	tt_assert(test_ok == 1)

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}


/* test date header and content length */

static void
http_request_empty_done(struct evhttp_request *req, void *arg)
{
	if (req->response_code != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Date") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}


	if (evhttp_find_header(req->input_headers, "Content-Length") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (strcmp(evhttp_find_header(req->input_headers, "Content-Length"),
		"0")) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

/*
 * HTTP DISPATCHER test
 */

void
http_dispatcher_cb(struct evhttp_request *req, void *arg)
{

	struct evbuffer *evb = evbuffer_new();
	event_debug(("%s: called\n", __func__));
	evbuffer_add_printf(evb, "DISPATCHER_TEST");

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);
}

static void
http_dispatcher_test_done(struct evhttp_request *req, void *arg)
{
	const char *what = "DISPATCHER_TEST";

	if (req->response_code != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(what)) {
		fprintf(stderr, "FAILED (length %zu vs %zu)\n",
		    EVBUFFER_LENGTH(req->input_buffer), strlen(what));
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), what, strlen(what)) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_dispatcher_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_dispatcher_test_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

/*
 * HTTP POST test.
 */

void http_postrequest_done(struct evhttp_request *, void *);

#define POST_DATA "Okay.  Not really printf"

static void
http_post_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule an HTTP POST request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_postrequest_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	evbuffer_add_printf(req->output_buffer, POST_DATA);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/postit") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	evhttp_connection_free(evcon);
	evhttp_free(http);

	tt_int_op(test_ok, ==, 1);
 end:
	;
}

void
http_post_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;
	event_debug(("%s: called\n", __func__));

	/* Yes, we are expecting a post request */
	if (req->type != EVHTTP_REQ_POST) {
		fprintf(stdout, "FAILED (post type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(POST_DATA)) {
		fprintf(stdout, "FAILED (length: %zu vs %zu)\n",
		    EVBUFFER_LENGTH(req->input_buffer), strlen(POST_DATA));
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), POST_DATA,
		strlen(POST_DATA))) {
		fprintf(stdout, "FAILED (data)\n");
		fprintf(stdout, "Got :%s\n", EVBUFFER_DATA(req->input_buffer));
		fprintf(stdout, "Want:%s\n", POST_DATA);
		exit(1);
	}

	evb = evbuffer_new();
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);
}

void
http_postrequest_done(struct evhttp_request *req, void *arg)
{
	const char *what = BASIC_REQUEST_BODY;

	if (req == NULL) {
		fprintf(stderr, "FAILED (timeout)\n");
		exit(1);
	}

	if (req->response_code != HTTP_OK) {

		fprintf(stderr, "FAILED (response code)\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(what)) {
		fprintf(stderr, "FAILED (length %zu vs %zu)\n",
		    EVBUFFER_LENGTH(req->input_buffer), strlen(what));
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), what, strlen(what)) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

/*
 * HTTP PUT test, basically just like POST, but ...
 */

void http_putrequest_done(struct evhttp_request *, void *);

#define PUT_DATA "Hi, I'm some PUT data"

static void
http_put_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * Schedule the HTTP PUT request
	 */

	req = evhttp_request_new(http_putrequest_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "someotherhost");
	evbuffer_add_printf(req->output_buffer, PUT_DATA);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_PUT, "/putit") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	evhttp_connection_free(evcon);
	evhttp_free(http);

	tt_int_op(test_ok, ==, 1);
 end:
	;
}

void
http_put_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;
	event_debug(("%s: called\n", __func__));

	/* Expecting a PUT request */
	if (req->type != EVHTTP_REQ_PUT) {
		fprintf(stdout, "FAILED (put type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(PUT_DATA)) {
		fprintf(stdout, "FAILED (length: %zu vs %zu)\n",
		    EVBUFFER_LENGTH(req->input_buffer), strlen(PUT_DATA));
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), PUT_DATA,
		strlen(PUT_DATA))) {
		fprintf(stdout, "FAILED (data)\n");
		fprintf(stdout, "Got :%s\n", EVBUFFER_DATA(req->input_buffer));
		fprintf(stdout, "Want:%s\n", PUT_DATA);
		exit(1);
	}

	evb = evbuffer_new();
	evbuffer_add_printf(evb, "That ain't funny");

	evhttp_send_reply(req, HTTP_OK, "Everything is great", evb);

	evbuffer_free(evb);
}

void
http_putrequest_done(struct evhttp_request *req, void *arg)
{
	const char *what = "That ain't funny";

	if (req == NULL) {
		fprintf(stderr, "FAILED (timeout)\n");
		exit(1);
	}

	if (req->response_code != HTTP_OK) {

		fprintf(stderr, "FAILED (response code)\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != strlen(what)) {
		fprintf(stderr, "FAILED (length %zu vs %zu)\n",
		    EVBUFFER_LENGTH(req->input_buffer), strlen(what));
		exit(1);
	}

	if (memcmp(EVBUFFER_DATA(req->input_buffer), what, strlen(what)) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_failure_readcb(struct bufferevent *bev, void *arg)
{
	const char *what = "400 Bad Request";
	if (evbuffer_find(bufferevent_get_input(bev),
		(const unsigned char*) what, strlen(what)) != NULL) {
		test_ok = 2;
		bufferevent_disable(bev, EV_READ);
		event_loopexit(NULL);
	}
}

/*
 * Testing that the HTTP server can deal with a malformed request.
 */
static void
http_failure_test(void)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, NULL);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_failure_readcb, http_writecb,
	    http_errorcb, NULL);

	http_request = "illegal request\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_dispatch();

	bufferevent_free(bev);
	evutil_closesocket(fd);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	;
}

static void
close_detect_done(struct evhttp_request *req, void *arg)
{
	struct timeval tv;
	tt_assert(req);
	tt_assert(req->response_code == HTTP_OK);

	test_ok = 1;

 end:
	evutil_timerclear(&tv);
	tv.tv_sec = 3;
	event_loopexit(&tv);
}

static void
close_detect_launch(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req;

	req = evhttp_request_new(close_detect_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_fail_msg("Couldn't make request");
	}
}

static void
close_detect_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct timeval tv;

	if (req != NULL && req->response_code != HTTP_OK) {
		tt_abort_msg("Failed");
	}

	evutil_timerclear(&tv);
	tv.tv_sec = 3;   /* longer than the http time out */

	/* launch a new request on the persistent connection in 3 seconds */
	event_once(-1, EV_TIMEOUT, close_detect_launch, evcon, &tv);
 end:
	;
}


static void
_http_close_detection(int with_delay)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	http = http_setup(&port, NULL);

	/* 2 second timeout */
	evhttp_set_timeout(http, 1);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);
	delayed_client = evcon;

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(close_detect_cb, evcon);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon,
	    req, EVHTTP_REQ_GET, with_delay ? "/largedelay" : "/test") == -1) {
		tt_abort_msg("couldn't make request");
		exit(1);
	}

	event_dispatch();

	/* at this point, the http server should have no connection */
	tt_assert(TAILQ_FIRST(&http->connections) == NULL);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}
static void
http_close_detection_test(void)
{
	_http_close_detection(0);
}
static void
http_close_detection_delay_test(void)
{
	_http_close_detection(1);
}

static void
http_highport_test(void)
{
	int i = -1;
	struct evhttp *myhttp = NULL;

	/* Try a few different ports */
	for (i = 0; i < 50; ++i) {
		myhttp = evhttp_start("127.0.0.1", 65535 - i);
		if (myhttp != NULL) {
			test_ok = 1;
			evhttp_free(myhttp);
			return;
		}
	}

	tt_fail_msg("Couldn't get a high port");
}

static void
http_bad_header_test(void *ptr)
{
	struct evkeyvalq headers;

	TAILQ_INIT(&headers);

	tt_want(evhttp_add_header(&headers, "One", "Two") == 0);
	tt_want(evhttp_add_header(&headers, "One", "Two\r\n Three") == 0);
	tt_want(evhttp_add_header(&headers, "One\r", "Two") == -1);
	tt_want(evhttp_add_header(&headers, "One\n", "Two") == -1);
	tt_want(evhttp_add_header(&headers, "One", "Two\r") == -1);
	tt_want(evhttp_add_header(&headers, "One", "Two\n") == -1);

	evhttp_clear_headers(&headers);
}

static int validate_header(
	const struct evkeyvalq* headers,
	const char *key, const char *value)
{
	const char *real_val = evhttp_find_header(headers, key);
	tt_assert(real_val != NULL);
	tt_want(strcmp(real_val, value) == 0);
end:
	return (0);
}

static void
http_parse_query_test(void *ptr)
{
	struct evkeyvalq headers;

	TAILQ_INIT(&headers);

	evhttp_parse_query("http://www.test.com/?q=test", &headers);
	tt_want(validate_header(&headers, "q", "test") == 0);
	evhttp_clear_headers(&headers);

	evhttp_parse_query("http://www.test.com/?q=test&foo=bar", &headers);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "foo", "bar") == 0);
	evhttp_clear_headers(&headers);

	evhttp_parse_query("http://www.test.com/?q=test+foo", &headers);
	tt_want(validate_header(&headers, "q", "test foo") == 0);
	evhttp_clear_headers(&headers);

	evhttp_parse_query("http://www.test.com/?q=test%0Afoo", &headers);
	tt_want(validate_header(&headers, "q", "test\nfoo") == 0);
	evhttp_clear_headers(&headers);

	evhttp_parse_query("http://www.test.com/?q=test%0Dfoo", &headers);
	tt_want(validate_header(&headers, "q", "test\rfoo") == 0);
	evhttp_clear_headers(&headers);
}

static void
http_base_test(void *ptr)
{
	struct event_base *base = NULL;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;

	test_ok = 0;
	base = event_init();
	http = http_setup(&port, base);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_readcb, http_writecb,
	    http_errorcb, NULL);
	bufferevent_base_set(base, bev);

	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(base);

	bufferevent_free(bev);
	evutil_closesocket(fd);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);

end:
	if (base)
		event_base_free(base);
}

/*
 * the server is just going to close the connection if it times out during
 * reading the headers.
 */

static void
http_incomplete_readcb(struct bufferevent *bev, void *arg)
{
	test_ok = -1;
	event_loopexit(NULL);
}

static void
http_incomplete_errorcb(struct bufferevent *bev, short what, void *arg)
{
	if (what == (EVBUFFER_READ | EVBUFFER_EOF))
		test_ok++;
	else
		test_ok = -2;
	event_loopexit(NULL);
}

static void
http_incomplete_writecb(struct bufferevent *bev, void *arg)
{
	if (arg != NULL) {
		evutil_socket_t fd = *(evutil_socket_t *)arg;
		/* terminate the write side to simulate EOF */
		shutdown(fd, SHUT_WR);
	}
	if (EVBUFFER_LENGTH(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
_http_incomplete_test(int use_timeout)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;

	test_ok = 0;

	http = http_setup(&port, NULL);
	evhttp_set_timeout(http, 1);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd,
	    http_incomplete_readcb, http_incomplete_writecb,
	    http_incomplete_errorcb, use_timeout ? NULL : &fd);

	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	evutil_gettimeofday(&tv_start, NULL);

	event_dispatch();

	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	bufferevent_free(bev);
	if (use_timeout) {
		evutil_closesocket(fd);
	}

	evhttp_free(http);

	if (use_timeout && tv_end.tv_sec >= 3) {
		tt_abort_msg("time");
	} else if (!use_timeout && tv_end.tv_sec >= 1) {
		/* we should be done immediately */
		tt_abort_msg("time");
	}

	tt_int_op(test_ok, ==, 2);
 end:
	;
}
static void
http_incomplete_test(void)
{
	_http_incomplete_test(0);
}
static void
http_incomplete_timeout_test(void)
{
	_http_incomplete_test(1);
}

/*
 * the server is going to reply with chunked data.
 */

static void
http_chunked_readcb(struct bufferevent *bev, void *arg)
{
	/* nothing here */
}

static void
http_chunked_errorcb(struct bufferevent *bev, short what, void *arg)
{
	if (!test_ok)
		goto out;

	test_ok = -1;

	if ((what & EVBUFFER_EOF) != 0) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		const char *header;
		enum message_read_status done;

		req->kind = EVHTTP_RESPONSE;
		done = evhttp_parse_firstline(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		header = evhttp_find_header(req->input_headers, "Transfer-Encoding");
		if (header == NULL || strcmp(header, "chunked"))
			goto out;

		header = evhttp_find_header(req->input_headers, "Connection");
		if (header == NULL || strcmp(header, "close"))
			goto out;

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 13 chars */
		if (strcmp(header, "d"))
			goto out;
		free((char*)header);

		if (strncmp((char *)evbuffer_pullup(bufferevent_get_input(bev), 13),
			"This is funny", 13))
			goto out;

		evbuffer_drain(bufferevent_get_input(bev), 13 + 2);

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 18 chars */
		if (strcmp(header, "12"))
			goto out;
		free((char *)header);

		if (strncmp((char *)evbuffer_pullup(bufferevent_get_input(bev), 18),
			"but not hilarious.", 18))
			goto out;

		evbuffer_drain(bufferevent_get_input(bev), 18 + 2);

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 8 chars */
		if (strcmp(header, "8"))
			goto out;
		free((char *)header);

		if (strncmp((char *)evbuffer_pullup(bufferevent_get_input(bev), 8),
			"bwv 1052.", 8))
			goto out;

		evbuffer_drain(bufferevent_get_input(bev), 8 + 2);

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 0 chars */
		if (strcmp(header, "0"))
			goto out;
		free((char *)header);

		test_ok = 2;

		evhttp_request_free(req);
	}

out:
	event_loopexit(NULL);
}

static void
http_chunked_writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_chunked_request_done(struct evhttp_request *req, void *arg)
{
	if (req->response_code != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers,
		"Transfer-Encoding") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer) != 13 + 18 + 8) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (strncmp((char *)evbuffer_pullup(req->input_buffer, 13 + 18 + 8),
		"This is funnybut not hilarious.bwv 1052",
		13 + 18 + 8)) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_chunk_out_test(void)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	int i;

	test_ok = 0;

	http = http_setup(&port, NULL);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd,
	    http_chunked_readcb, http_chunked_writecb,
	    http_chunked_errorcb, NULL);

	http_request =
	    "GET /chunked HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	evutil_gettimeofday(&tv_start, NULL);

	event_dispatch();

	bufferevent_free(bev);

	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	tt_int_op(tv_end.tv_sec, <, 1);

	tt_int_op(test_ok, ==, 2);

	/* now try again with the regular connection object */
	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/* make two requests to check the keepalive behavior */
	for (i = 0; i < 2; i++) {
		test_ok = 0;
		req = evhttp_request_new(http_chunked_request_done, NULL);

		/* Add the information that we care about */
		evhttp_add_header(req->output_headers, "Host", "somehost");

		/* We give ownership of the request to the connection */
		if (evhttp_make_request(evcon, req,
			EVHTTP_REQ_GET, "/chunked") == -1) {
			tt_abort_msg("Couldn't make request");
		}

		event_dispatch();

		tt_assert(test_ok == 1);
	}

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_stream_out_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done,
	    (void *)"This is funnybut not hilarious.bwv 1052");

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/streamed")
	    == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_stream_in_chunk(struct evhttp_request *req, void *arg)
{
	struct evbuffer *reply = arg;

	if (req->response_code != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	evbuffer_add_buffer(reply, req->input_buffer);
}

static void
http_stream_in_done(struct evhttp_request *req, void *arg)
{
	if (evbuffer_get_length(req->input_buffer) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	event_loopexit(NULL);
}

/**
 * Makes a request and reads the response in chunks.
 */
static void
_http_stream_in_test(char const *url,
    size_t expected_len, char const *expected)
{
	struct evhttp_connection *evcon;
	struct evbuffer *reply = evbuffer_new();
	struct evhttp_request *req = NULL;
	ev_uint16_t port = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	req = evhttp_request_new(http_stream_in_done, reply);
	evhttp_request_set_chunked_cb(req, http_stream_in_chunk);

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, url) == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	if (evbuffer_get_length(reply) != expected_len) {
		TT_DIE(("reply length %zu; expected %zu; FAILED (%s)\n",
				EVBUFFER_LENGTH(reply), expected_len,
				evbuffer_pullup(reply, -1)));
	}

	if (memcmp(evbuffer_pullup(reply, -1), expected, expected_len) != 0) {
		tt_abort_msg("Memory mismatch");
	}

	test_ok = 1;
 end:
	if (reply)
		evbuffer_free(reply);
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_stream_in_test(void)
{
	_http_stream_in_test("/chunked", 13 + 18 + 8,
	    "This is funnybut not hilarious.bwv 1052");

	_http_stream_in_test("/test", strlen(BASIC_REQUEST_BODY),
	    BASIC_REQUEST_BODY);
}

static void
http_stream_in_cancel_chunk(struct evhttp_request *req, void *arg)
{
	tt_int_op(req->response_code, ==, HTTP_OK);

 end:
	evhttp_cancel_request(req);
	event_loopexit(NULL);
}

static void
http_stream_in_cancel_done(struct evhttp_request *req, void *arg)
{
	/* should never be called */
	tt_fail_msg("In cancel done");
}

static void
http_stream_in_cancel_test(void)
{
	struct evhttp_connection *evcon;
	struct evhttp_request *req = NULL;
	ev_uint16_t port = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	req = evhttp_request_new(http_stream_in_cancel_done, NULL);
	evhttp_request_set_chunked_cb(req, http_stream_in_cancel_chunk);

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/chunked") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

	test_ok = 1;
 end:
	evhttp_connection_free(evcon);
	evhttp_free(http);

}

static void
http_connection_retry_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(req->response_code, !=, HTTP_OK);
	if (evhttp_find_header(req->input_headers, "Content-Type") != NULL) {
		tt_abort_msg("(content type)\n");
	}

	tt_uint_op(EVBUFFER_LENGTH(req->input_buffer), ==, 0);

	test_ok = 1;
 end:
	event_loopexit(NULL);
}

static void
http_make_web_server(evutil_socket_t fd, short what, void *arg)
{
	ev_uint16_t port = *(ev_uint16_t*)arg;
	http = http_setup(&port, NULL);
}

static void
http_connection_retry_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv, tv_start, tv_end;

	test_ok = 0;

	/* auto detect a port */
	http = http_setup(&port, NULL);
	evhttp_free(http);
	http = NULL;

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	evhttp_connection_set_timeout(evcon, 1);
	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_connection_retry_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	evutil_gettimeofday(&tv_start, NULL);
	event_dispatch();
	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	tt_int_op(tv_end.tv_sec, <, 1);

	tt_int_op(test_ok, ==, 1);

	/*
	 * now test the same but with retries
	 */
	test_ok = 0;

	evhttp_connection_set_timeout(evcon, 1);
	evhttp_connection_set_retries(evcon, 1);

	req = evhttp_request_new(http_connection_retry_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	evutil_gettimeofday(&tv_start, NULL);
	event_dispatch();
	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	tt_int_op(tv_end.tv_sec, >, 1);
	tt_int_op(tv_end.tv_sec, <, 6);

	tt_assert(test_ok == 1);

	/*
	 * now test the same but with retries and give it a web server
	 * at the end
	 */
	test_ok = 0;

	evhttp_connection_set_timeout(evcon, 1);
	evhttp_connection_set_retries(evcon, 3);

	req = evhttp_request_new(http_dispatcher_test_done, NULL);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	/* start up a web server one second after the connection tried
	 * to send a request
	 */
	evutil_timerclear(&tv);
	tv.tv_sec = 1;
	event_once(-1, EV_TIMEOUT, http_make_web_server, &port, &tv);

	evutil_gettimeofday(&tv_start, NULL);
	event_dispatch();
	evutil_gettimeofday(&tv_end, NULL);

	evutil_timersub(&tv_end, &tv_start, &tv_end);

	tt_int_op(tv_end.tv_sec, >, 1);
	tt_int_op(tv_end.tv_sec, <, 6);

	tt_int_op(test_ok, ==, 1);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_primitives(void *ptr)
{
	char *escaped = NULL;
	struct evhttp *http;

	escaped = evhttp_htmlescape("<script>");
	tt_str_op(escaped, ==, "&lt;script&gt;");
	free(escaped);

	escaped = evhttp_htmlescape("\"\'&");
	tt_str_op(escaped, ==, "&quot;&#039;&amp;");

	http = evhttp_new(NULL);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, 0);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, -1);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, 0);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, -1);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, 0);
	evhttp_free(http);

 end:
	if (escaped)
		free(escaped);
}

static void
http_multi_line_header_test(void)
{
	struct bufferevent *bev= NULL;
	evutil_socket_t fd = -1;
	const char *http_start_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, NULL);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_readcb, http_writecb,
	    http_errorcb, NULL);

	http_start_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "X-Multi:  aaaaaaaa\r\n"
	    " a\r\n"
	    "\tEND\r\n"
	    "X-Last: last\r\n"
	    "\r\n";

	bufferevent_write(bev, http_start_request, strlen(http_start_request));

	event_dispatch();

	tt_int_op(test_ok, ==, 4);
 end:
	if (bev)
		bufferevent_free(bev);
	if (fd >= 0)
		evutil_closesocket(fd);
	if (http)
		evhttp_free(http);
}

static void
http_request_bad(struct evhttp_request *req, void *arg)
{
	if (req != NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_negative_content_length_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_bad, NULL);

	/* Cause the response to have a negative content-length */
	evhttp_add_header(req->output_headers, "X-Negative", "makeitso");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_dispatch();

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}


static void
http_data_length_constraints_test_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(req->response_code, ==, HTTP_BADREQUEST);
end:
	event_loopexit(NULL);
}

static void
http_data_length_constraints_test(void)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	char long_str[8192];

	test_ok = 0;

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	tt_assert(evcon);

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_data_length_constraints_test_done, NULL);
	tt_assert(req);

	memset(long_str, 'a', 8192);
	long_str[8191] = '\0';
	/* Add the information that we care about */
	evhttp_set_max_headers_size(http, 8191);
	evhttp_add_header(req->output_headers, "Host", "somehost");
	evhttp_add_header(req->output_headers, "Longheader", long_str);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_dispatch();

	req = evhttp_request_new(http_data_length_constraints_test_done, NULL);
	tt_assert(req);
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* GET /?arg=verylongvalue HTTP/1.1 */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, long_str) == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_dispatch();

	evhttp_set_max_body_size(http, 8190);
	req = evhttp_request_new(http_data_length_constraints_test_done, NULL);
	evhttp_add_header(req->output_headers, "Host", "somehost");
	evbuffer_add_printf(req->output_buffer, "%s", long_str);
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_dispatch();

	test_ok = 1;
 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

/*
 * Testing client reset of server chunked connections
 */

struct terminate_state {
	struct evhttp_request *req;
	struct bufferevent *bev;
	evutil_socket_t fd;
	int gotclosecb: 1;
} terminate_state;

static void
terminate_chunked_trickle_cb(evutil_socket_t fd, short events, void *arg)
{
	struct terminate_state *state = arg;
	struct evbuffer *evb;
	struct timeval tv;

	if (evhttp_request_get_connection(state->req) == NULL) {
		test_ok = 1;
		evhttp_request_free(state->req);
		event_loopexit(NULL);
		return;
	}

	evb = evbuffer_new();
	evbuffer_add_printf(evb, "%p", evb);
	evhttp_send_reply_chunk(state->req, evb);
	evbuffer_free(evb);

	tv.tv_sec = 0;
	tv.tv_usec = 3000;
	event_once(-1, EV_TIMEOUT, terminate_chunked_trickle_cb, arg, &tv);
}

static void
terminate_chunked_close_cb(struct evhttp_connection *evcon, void *arg)
{
	struct terminate_state *state = arg;
	state->gotclosecb = 1;
}

static void
terminate_chunked_cb(struct evhttp_request *req, void *arg)
{
	struct terminate_state *state = arg;
	struct timeval tv;

	/* we want to know if this connection closes on us */
	evhttp_connection_set_closecb(
		evhttp_request_get_connection(req),
		terminate_chunked_close_cb, arg);

	state->req = req;

	evhttp_send_reply_start(req, HTTP_OK, "OK");

	tv.tv_sec = 0;
	tv.tv_usec = 3000;
	event_once(-1, EV_TIMEOUT, terminate_chunked_trickle_cb, arg, &tv);
}

static void
terminate_chunked_client(evutil_socket_t fd, short event, void *arg)
{
	struct terminate_state *state = arg;
	bufferevent_free(state->bev);
	evutil_closesocket(state->fd);
}

static void
terminate_readcb(struct bufferevent *bev, void *arg)
{
	/* just drop the data */
	evbuffer_drain(bufferevent_get_input(bev), -1);
}


static void
http_terminate_chunked_test(void)
{
	struct bufferevent *bev = NULL;
	struct timeval tv;
	const char *http_request;
	ev_uint16_t port = 0;
	evutil_socket_t fd = -1;

	test_ok = 0;

	http = http_setup(&port, NULL);
	evhttp_del_cb(http, "/test");
	tt_assert(evhttp_set_cb(http, "/test",
		terminate_chunked_cb, &terminate_state) == 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, terminate_readcb, http_writecb,
	    http_errorcb, NULL);

	terminate_state.fd = fd;
	terminate_state.bev = bev;
	terminate_state.gotclosecb = 0;

	/* first half of the http request */
	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: some\r\n\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));
	evutil_timerclear(&tv);
	tv.tv_usec = 10000;
	event_once(-1, EV_TIMEOUT, terminate_chunked_client, &terminate_state,
	    &tv);

	event_dispatch();

	if (terminate_state.gotclosecb == 0)
		test_ok = 0;

 end:
	if (fd >= 0)
		evutil_closesocket(fd);
	if (http)
		evhttp_free(http);
}

#define HTTP_LEGACY(name)						\
	{ #name, run_legacy_test_fn, TT_ISOLATED|TT_LEGACY, &legacy_setup, \
		    http_##name##_test }

struct testcase_t http_testcases[] = {
	{ "primitives", http_primitives, 0, NULL, NULL },
	{ "base", http_base_test, TT_FORK|TT_NEED_BASE, NULL, NULL },
	{ "bad_headers", http_bad_header_test, 0, NULL, NULL },
	{ "parse_query", http_parse_query_test, 0, NULL, NULL },
	HTTP_LEGACY(basic),
	HTTP_LEGACY(cancel),
	HTTP_LEGACY(virtual_host),
	HTTP_LEGACY(post),
	HTTP_LEGACY(put),
	HTTP_LEGACY(delete),
	HTTP_LEGACY(failure),
	HTTP_LEGACY(connection),
	HTTP_LEGACY(persist_connection),
	HTTP_LEGACY(connection_async),
	HTTP_LEGACY(close_detection),
	HTTP_LEGACY(close_detection_delay),
	HTTP_LEGACY(bad_request),
	HTTP_LEGACY(incomplete),
	HTTP_LEGACY(incomplete_timeout),
	{ "terminate_chunked", run_legacy_test_fn,
	  TT_ISOLATED|TT_LEGACY, &legacy_setup,
	  http_terminate_chunked_test },

	HTTP_LEGACY(highport),
	HTTP_LEGACY(dispatcher),
	HTTP_LEGACY(multi_line_header),
	HTTP_LEGACY(negative_content_length),
	HTTP_LEGACY(chunk_out),
	HTTP_LEGACY(stream_out),

	HTTP_LEGACY(stream_in),
	HTTP_LEGACY(stream_in_cancel),

	HTTP_LEGACY(connection_retry),
	HTTP_LEGACY(data_length_constraints),

	END_OF_TESTCASES
};

