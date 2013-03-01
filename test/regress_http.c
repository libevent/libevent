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
#include "util-internal.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
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
#include <unistd.h>
#include <netdb.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "event2/dns.h"

#include "event2/event.h"
#include "event2/http.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/util.h"
#include "log-internal.h"
#include "http-internal.h"
#include "regress.h"
#include "regress_testutils.h"

static struct evhttp *http;
/* set if a test needs to call loopexit on a base */
static struct event_base *exit_base;

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
http_bind(struct evhttp *myhttp, ev_uint16_t *pport, int ipv6)
{
	int port;
	struct evhttp_bound_socket *sock;

	if (ipv6)
		sock = evhttp_bind_socket_with_handle(myhttp, "::1", *pport);
	else
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
http_setup(ev_uint16_t *pport, struct event_base *base, int ipv6)
{
	struct evhttp *myhttp;

	/* Try a few different ports */
	myhttp = evhttp_new(base);

	if (http_bind(myhttp, pport, ipv6) < 0)
		return NULL;

	/* Register a callback for certain types of requests */
	evhttp_set_cb(myhttp, "/test", http_basic_cb, base);
	evhttp_set_cb(myhttp, "/chunked", http_chunked_cb, base);
	evhttp_set_cb(myhttp, "/streamed", http_chunked_cb, base);
	evhttp_set_cb(myhttp, "/postit", http_post_cb, base);
	evhttp_set_cb(myhttp, "/putit", http_put_cb, base);
	evhttp_set_cb(myhttp, "/deleteit", http_delete_cb, base);
	evhttp_set_cb(myhttp, "/delay", http_delay_cb, base);
	evhttp_set_cb(myhttp, "/largedelay", http_large_delay_cb, base);
	evhttp_set_cb(myhttp, "/badrequest", http_badreq_cb, base);
	evhttp_set_cb(myhttp, "/", http_dispatcher_cb, base);
	return (myhttp);
}

#ifndef NI_MAXSERV
#define NI_MAXSERV 1024
#endif

static evutil_socket_t
http_connect(const char *address, u_short port)
{
	/* Stupid code for connecting */
	struct evutil_addrinfo ai, *aitop;
	char strport[NI_MAXSERV];

	struct sockaddr *sa;
	int slen;
	evutil_socket_t fd;

	memset(&ai, 0, sizeof(ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = SOCK_STREAM;
	evutil_snprintf(strport, sizeof(strport), "%d", port);
	if (evutil_getaddrinfo(address, strport, &ai, &aitop) != 0) {
		event_warn("getaddrinfo");
		return (-1);
	}
	sa = aitop->ai_addr;
	slen = aitop->ai_addrlen;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		event_err(1, "socket failed");

	evutil_make_socket_nonblocking(fd);
	if (connect(fd, sa, slen) == -1) {
#ifdef _WIN32
		int tmp_err = WSAGetLastError();
		if (tmp_err != WSAEINPROGRESS && tmp_err != WSAEINVAL &&
		    tmp_err != WSAEWOULDBLOCK)
			event_err(1, "connect failed");
#else
		if (errno != EINPROGRESS)
			event_err(1, "connect failed");
#endif
	}

	evutil_freeaddrinfo(aitop);

	return (fd);
}

/* Helper: do a strcmp on the contents of buf and the string s. */
static int
evbuffer_datacmp(struct evbuffer *buf, const char *s)
{
	size_t b_sz = evbuffer_get_length(buf);
	size_t s_sz = strlen(s);
	unsigned char *d;
	int r;

	if (b_sz < s_sz)
		return -1;

	d = evbuffer_pullup(buf, s_sz);
	if ((r = memcmp(d, s, s_sz)))
		return r;

	if (b_sz > s_sz)
		return 1;
	else
		return 0;
}

/* Helper: Return true iff buf contains s */
static int
evbuffer_contains(struct evbuffer *buf, const char *s)
{
	struct evbuffer_ptr ptr;
	ptr = evbuffer_search(buf, s, strlen(s), NULL);
	return ptr.pos != -1;
}

static void
http_readcb(struct bufferevent *bev, void *arg)
{
	const char *what = BASIC_REQUEST_BODY;
	struct event_base *my_base = arg;

	if (evbuffer_contains(bufferevent_get_input(bev), what)) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		enum message_read_status done;

		/* req->kind = EVHTTP_RESPONSE; */
		done = evhttp_parse_firstline_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		if (done == 1 &&
		    evhttp_find_header(evhttp_request_get_input_headers(req),
			"Content-Type") != NULL)
			test_ok++;

	 out:
		evhttp_request_free(req);
		bufferevent_disable(bev, EV_READ);
		if (exit_base)
			event_base_loopexit(exit_base, NULL);
		else if (my_base)
			event_base_loopexit(my_base, NULL);
		else {
			fprintf(stderr, "No way to exit loop!\n");
			exit(1);
		}
	}
}

static void
http_writecb(struct bufferevent *bev, void *arg)
{
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
	event_base_loopexit(arg, NULL);
}

static int found_multi = 0;
static int found_multi2 = 0;

static void
http_basic_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(evhttp_request_get_input_headers(req), "Empty") != NULL;
	event_debug(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* For multi-line headers test */
	{
		const char *multi =
		    evhttp_find_header(evhttp_request_get_input_headers(req),"X-Multi");
		if (multi) {
			found_multi = !strcmp(multi,"aaaaaaaa a END");
			if (strcmp("END", multi + strlen(multi) - 3) == 0)
				test_ok++;
			if (evhttp_find_header(evhttp_request_get_input_headers(req), "X-Last"))
				test_ok++;
		}
	}
	{
		const char *multi2 =
		    evhttp_find_header(evhttp_request_get_input_headers(req),"X-Multi-Extra-WS");
		if (multi2) {
			found_multi2 = !strcmp(multi2,"libevent 2.1");
		}
	}


	/* injecting a bad content-length */
	if (evhttp_find_header(evhttp_request_get_input_headers(req), "X-Negative"))
		evhttp_add_header(evhttp_request_get_output_headers(req),
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
	struct event_base *base;
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

	if (++state->i < (int) (sizeof(CHUNKS)/sizeof(CHUNKS[0]))) {
		event_base_once(state->base, -1, EV_TIMEOUT,
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
	state->base = arg;

	if (strcmp(evhttp_request_get_uri(req), "/streamed") == 0) {
		evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", "39");
	}

	/* generate a chunked/streamed reply */
	evhttp_send_reply_start(req, HTTP_OK, "Everything is fine");

	/* but trickle it across several iterations to ensure we're not
	 * assuming it comes all at once */
	event_base_once(arg, -1, EV_TIMEOUT, http_chunked_trickle_cb, state, &when);
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
http_basic_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct timeval tv;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0, port2 = 0;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	/* bind to a second socket */
	if (http_bind(http, &port2, 0) == -1) {
		fprintf(stdout, "FAILED (bind)\n");
		exit(1);
	}

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	/* first half of the http request */
	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: some";

	bufferevent_write(bev, http_request, strlen(http_request));
	evutil_timerclear(&tv);
	tv.tv_usec = 10000;
	event_base_once(data->base,
	    -1, EV_TIMEOUT, http_complete_write, bev, &tv);

	event_base_dispatch(data->base);

	tt_assert(test_ok == 3);

	/* connect to the second port */
	bufferevent_free(bev);
	evutil_closesocket(fd);

	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	tt_assert(test_ok == 5);

	/* Connect to the second port again. This time, send an absolute uri. */
	bufferevent_free(bev);
	evutil_closesocket(fd);

	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "GET http://somehost.net/test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	tt_assert(test_ok == 7);

	evhttp_free(http);
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

	event_base_once(arg, -1, EV_TIMEOUT, http_delay_reply, req, &tv);
}

static void
http_badreq_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf = evbuffer_new();

	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/xml; charset=UTF-8");
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
#ifdef _WIN32
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

	if (evbuffer_contains(bufferevent_get_input(bev), bad_request)) {
		TT_FAIL(("%s:bad request detected", __func__));
		bufferevent_disable(bev, EV_READ);
		event_base_loopexit(arg, NULL);
		return;
	}

	if (evbuffer_contains(bufferevent_get_input(bev), what)) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		enum message_read_status done;

		/* req->kind = EVHTTP_RESPONSE; */
		done = evhttp_parse_firstline_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		if (done == 1 &&
		    evhttp_find_header(evhttp_request_get_input_headers(req),
			"Content-Type") != NULL)
			test_ok++;

	out:
		evhttp_request_free(req);
		evbuffer_drain(bufferevent_get_input(bev), evbuffer_get_length(bufferevent_get_input(bev)));
	}

	shutdown(bufferevent_getfd(bev), SHUT_WR);
}

static void
http_badreq_successcb(evutil_socket_t fd, short what, void *arg)
{
	event_debug(("%s: called (what=%04x, arg=%p)", __func__, what, arg));
	event_base_loopexit(exit_base, NULL);
}

static void
http_bad_request_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct timeval tv;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port=0, port2=0;

	test_ok = 0;
	exit_base = data->base;

	http = http_setup(&port, data->base, 0);

	/* bind to a second socket */
	if (http_bind(http, &port2, 0) == -1)
		TT_DIE(("Bind socket failed"));

	/* NULL request test */
	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_badreq_readcb, http_writecb,
	    http_badreq_errorcb, data->base);
	bufferevent_enable(bev, EV_READ);

	/* real NULL request */
	http_request = "";

	bufferevent_write(bev, http_request, strlen(http_request));

	shutdown(fd, SHUT_WR);
	timerclear(&tv);
	tv.tv_usec = 10000;
	event_base_once(data->base, -1, EV_TIMEOUT, http_badreq_successcb, bev, &tv);

	event_base_dispatch(data->base);

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
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_badreq_readcb, http_writecb,
	    http_badreq_errorcb, data->base);
	bufferevent_enable(bev, EV_READ);

	/* first half of the http request */
	http_request =
		"GET /badrequest HTTP/1.0\r\n"	\
		"Connection: Keep-Alive\r\n"	\
		"\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	timerclear(&tv);
	tv.tv_usec = 10000;
	event_base_once(data->base, -1, EV_TIMEOUT, http_badreq_successcb, bev, &tv);

	event_base_dispatch(data->base);

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
	tv.tv_usec = 500000;

	event_base_once(arg, -1, EV_TIMEOUT, http_delay_reply, req, &tv);
	evhttp_connection_fail_(delayed_client, EVCON_HTTP_EOF);
}

/*
 * HTTP DELETE test,  just piggyback on the basic test
 */

static void
http_delete_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(evhttp_request_get_input_headers(req), "Empty") != NULL;

	/* Expecting a DELETE request */
	if (evhttp_request_get_command(req) != EVHTTP_REQ_DELETE) {
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
http_delete_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "DELETE /deleteit HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev);
	evutil_closesocket(fd);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	;
}

static void
http_allowed_methods_eventcb(struct bufferevent *bev, short what, void *arg)
{
	char **output = arg;
	if ((what & (BEV_EVENT_ERROR|BEV_EVENT_EOF))) {
		char buf[4096];
		int n;
		n = evbuffer_remove(bufferevent_get_input(bev), buf,
		    sizeof(buf)-1);
		if (n >= 0) {
			buf[n]='\0';
			if (*output)
				free(*output);
			*output = strdup(buf);
		}
		event_base_loopexit(exit_base, NULL);
	}
}

static void
http_allowed_methods_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev1, *bev2, *bev3;
	evutil_socket_t fd1, fd2, fd3;
	const char *http_request;
	char *result1=NULL, *result2=NULL, *result3=NULL;
	ev_uint16_t port = 0;

	exit_base = data->base;
	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	fd1 = http_connect("127.0.0.1", port);

	/* GET is out; PATCH is in. */
	evhttp_set_allowed_methods(http, EVHTTP_REQ_PATCH);

	/* Stupid thing to send a request */
	bev1 = bufferevent_socket_new(data->base, fd1, 0);
	bufferevent_enable(bev1, EV_READ|EV_WRITE);
	bufferevent_setcb(bev1, NULL, NULL,
	    http_allowed_methods_eventcb, &result1);

	http_request =
	    "GET /index.html HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev1, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	fd2 = http_connect("127.0.0.1", port);

	bev2 = bufferevent_socket_new(data->base, fd2, 0);
	bufferevent_enable(bev2, EV_READ|EV_WRITE);
	bufferevent_setcb(bev2, NULL, NULL,
	    http_allowed_methods_eventcb, &result2);

	http_request =
	    "PATCH /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev2, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	fd3 = http_connect("127.0.0.1", port);

	bev3 = bufferevent_socket_new(data->base, fd3, 0);
	bufferevent_enable(bev3, EV_READ|EV_WRITE);
	bufferevent_setcb(bev3, NULL, NULL,
	    http_allowed_methods_eventcb, &result3);

	http_request =
	    "FLOOP /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev3, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev1);
	bufferevent_free(bev2);
	bufferevent_free(bev3);
	evutil_closesocket(fd1);
	evutil_closesocket(fd2);
	evutil_closesocket(fd3);

	evhttp_free(http);

	/* Method known but disallowed */
	tt_assert(result1);
	tt_assert(!strncmp(result1, "HTTP/1.1 501 ", strlen("HTTP/1.1 501 ")));

	/* Method known and allowed */
	tt_assert(result2);
	tt_assert(!strncmp(result2, "HTTP/1.1 200 ", strlen("HTTP/1.1 200 ")));

	/* Method unknown */
	tt_assert(result3);
	tt_assert(!strncmp(result3, "HTTP/1.1 501 ", strlen("HTTP/1.1 501 ")));

 end:
	if (result1)
		free(result1);
	if (result2)
		free(result2);
	if (result3)
		free(result3);
}

static void http_request_done(struct evhttp_request *, void *);
static void http_request_empty_done(struct evhttp_request *, void *);

static void
http_connection_test_(struct basic_test_data *data, int persistent, const char *address, struct evdns_base *dnsbase, int ipv6)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, data->base, ipv6);

	evcon = evhttp_connection_base_new(data->base, dnsbase, address, port);
	tt_assert(evcon);

	tt_assert(evhttp_connection_get_base(evcon) == data->base);

	exit_base = data->base;
	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/*
	 * if our connections are not supposed to be persistent; request
	 * a close from the server.
	 */
	if (!persistent)
		evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("couldn't make request");
	}

	event_base_dispatch(data->base);

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, data->base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_connection_test(void *arg)
{
	http_connection_test_(arg, 0, "127.0.0.1", NULL, 0);
}
static void
http_persist_connection_test(void *arg)
{
	http_connection_test_(arg, 1, "127.0.0.1", NULL, 0);
}

static struct regress_dns_server_table search_table[] = {
	{ "localhost", "A", "127.0.0.1", 0 },
	{ NULL, NULL, NULL, 0 }
};

static void
http_connection_async_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evdns_base *dns_base = NULL;
	ev_uint16_t portnum = 0;
	char address[64];

	exit_base = data->base;
	tt_assert(regress_dnsserver(data->base, &portnum, search_table));

	dns_base = evdns_base_new(data->base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, dns_base, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/*
	 * if our connections are not supposed to be persistent; request
	 * a close from the server.
	 */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("couldn't make request");
	}

	event_base_dispatch(data->base);

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, data->base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

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
	struct event_base *base;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 500 * 1000;

	base = evhttp_connection_get_base(evhttp_request_get_connection(req));
	evhttp_cancel_request(req);

	event_base_loopexit(base, &tv);

	++test_ok;
}

static void
http_cancel_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv;

	exit_base = data->base;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_never_call, NULL);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/delay"),
		  !=, -1);

	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000;

	event_base_once(data->base, -1, EV_TIMEOUT, http_do_cancel, req, &tv);

	event_base_dispatch(data->base);

	tt_int_op(test_ok, ==, 2);

	/* try to make another request over the same connection */
	test_ok = 0;

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_base_dispatch(data->base);

	/* make another request: request empty reply */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, data->base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Empty", "itis");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_base_dispatch(data->base);

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

	if (evhttp_request_get_response_code(req) != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(what)) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), what) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	EVUTIL_ASSERT(exit_base);
	event_base_loopexit(exit_base, NULL);
}

static void
http_request_expect_error(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_response_code(req) == HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	EVUTIL_ASSERT(arg);
	event_base_loopexit(arg, NULL);
}

/* test virtual hosts */
static void
http_virtual_host_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *second = NULL, *third = NULL;
	evutil_socket_t fd;
	struct bufferevent *bev;
	const char *http_request;

	exit_base = data->base;

	http = http_setup(&port, data->base, 0);

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

	/* add some aliases to the vhosts */
	tt_assert(evhttp_add_server_alias(second, "manolito.info") == 0);
	tt_assert(evhttp_add_server_alias(third, "bonkers.org") == 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/* make a request with a different host and expect an error */
	req = evhttp_request_new(http_request_expect_error, data->base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok == 1);

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok == 1);

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "bar.magic.foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/blackcoffee") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok == 1)

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "manolito.info");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok == 1)

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the Host header. This time with the optional port. */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "bonkers.org:8000");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/blackcoffee") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_assert(test_ok == 1)

	test_ok = 0;

	/* Now make a raw request with an absolute URI. */
	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, NULL);

	/* The host in the URI should override the Host: header */
	http_request =
	    "GET http://manolito.info/funnybunny HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	tt_int_op(test_ok, ==, 2);

	bufferevent_free(bev);
	evutil_closesocket(fd);

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
	if (evhttp_request_get_response_code(req) != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Date") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}


	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Length") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (strcmp(evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Length"),
		"0")) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	EVUTIL_ASSERT(arg);
	event_base_loopexit(arg, NULL);
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
	struct event_base *base = arg;
	const char *what = "DISPATCHER_TEST";

	if (evhttp_request_get_response_code(req) != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(what)) {
		fprintf(stderr, "FAILED (length %lu vs %lu)\n",
		    (unsigned long)evbuffer_get_length(evhttp_request_get_input_buffer(req)), (unsigned long)strlen(what));
		exit(1);
	}

	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), what) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_base_loopexit(base, NULL);
}

static void
http_dispatcher_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_dispatcher_test_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

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
http_post_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule an HTTP POST request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_postrequest_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), POST_DATA);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/postit") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_int_op(test_ok, ==, 1);

	test_ok = 0;

	req = evhttp_request_new(http_postrequest_done, data->base);
	tt_assert(req);

	/* Now try with 100-continue. */

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Expect", "100-continue");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), POST_DATA);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/postit") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	tt_int_op(test_ok, ==, 1);

	evhttp_connection_free(evcon);
	evhttp_free(http);

 end:
	;
}

void
http_post_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;
	event_debug(("%s: called\n", __func__));

	/* Yes, we are expecting a post request */
	if (evhttp_request_get_command(req) != EVHTTP_REQ_POST) {
		fprintf(stdout, "FAILED (post type)\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(POST_DATA)) {
		fprintf(stdout, "FAILED (length: %lu vs %lu)\n",
		    (unsigned long) evbuffer_get_length(evhttp_request_get_input_buffer(req)), (unsigned long) strlen(POST_DATA));
		exit(1);
	}

	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), POST_DATA) != 0) {
		fprintf(stdout, "FAILED (data)\n");
		fprintf(stdout, "Got :%s\n", evbuffer_pullup(evhttp_request_get_input_buffer(req),-1));
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
	struct event_base *base = arg;

	if (req == NULL) {
		fprintf(stderr, "FAILED (timeout)\n");
		exit(1);
	}

	if (evhttp_request_get_response_code(req) != HTTP_OK) {

		fprintf(stderr, "FAILED (response code)\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(what)) {
		fprintf(stderr, "FAILED (length %lu vs %lu)\n",
		    (unsigned long)evbuffer_get_length(evhttp_request_get_input_buffer(req)), (unsigned long)strlen(what));
		exit(1);
	}

	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), what) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_base_loopexit(base, NULL);
}

/*
 * HTTP PUT test, basically just like POST, but ...
 */

void http_putrequest_done(struct evhttp_request *, void *);

#define PUT_DATA "Hi, I'm some PUT data"

static void
http_put_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * Schedule the HTTP PUT request
	 */

	req = evhttp_request_new(http_putrequest_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "someotherhost");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), PUT_DATA);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_PUT, "/putit") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

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
	if (evhttp_request_get_command(req) != EVHTTP_REQ_PUT) {
		fprintf(stdout, "FAILED (put type)\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(PUT_DATA)) {
		fprintf(stdout, "FAILED (length: %lu vs %lu)\n",
		    (unsigned long)evbuffer_get_length(evhttp_request_get_input_buffer(req)), (unsigned long)strlen(PUT_DATA));
		exit(1);
	}

	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), PUT_DATA) != 0) {
		fprintf(stdout, "FAILED (data)\n");
		fprintf(stdout, "Got :%s\n", evbuffer_pullup(evhttp_request_get_input_buffer(req),-1));
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
	struct event_base *base = arg;
	const char *what = "That ain't funny";

	if (req == NULL) {
		fprintf(stderr, "FAILED (timeout)\n");
		exit(1);
	}

	if (evhttp_request_get_response_code(req) != HTTP_OK) {

		fprintf(stderr, "FAILED (response code)\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type") == NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != strlen(what)) {
		fprintf(stderr, "FAILED (length %lu vs %lu)\n",
		    (unsigned long)evbuffer_get_length(evhttp_request_get_input_buffer(req)), (unsigned long)strlen(what));
		exit(1);
	}


	if (evbuffer_datacmp(evhttp_request_get_input_buffer(req), what) != 0) {
		fprintf(stderr, "FAILED (data)\n");
		exit(1);
	}

	test_ok = 1;
	event_base_loopexit(base, NULL);
}

static void
http_failure_readcb(struct bufferevent *bev, void *arg)
{
	const char *what = "400 Bad Request";
	if (evbuffer_contains(bufferevent_get_input(bev), what)) {
		test_ok = 2;
		bufferevent_disable(bev, EV_READ);
		event_base_loopexit(arg, NULL);
	}
}

/*
 * Testing that the HTTP server can deal with a malformed request.
 */
static void
http_failure_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_failure_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request = "illegal request\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

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
	tt_assert(evhttp_request_get_response_code(req) == HTTP_OK);

	test_ok = 1;

 end:
	evutil_timerclear(&tv);
	tv.tv_usec = 150000;
	event_base_loopexit(arg, &tv);
}

static void
close_detect_launch(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct event_base *base = evhttp_connection_get_base(evcon);
	struct evhttp_request *req;

	req = evhttp_request_new(close_detect_done, base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_fail_msg("Couldn't make request");
	}
}

static void
close_detect_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct event_base *base = evhttp_connection_get_base(evcon);
	struct timeval tv;

	if (req != NULL && evhttp_request_get_response_code(req) != HTTP_OK) {
		tt_abort_msg("Failed");
	}

	evutil_timerclear(&tv);
	tv.tv_sec = 0;   /* longer than the http time out */
	tv.tv_usec = 600000;   /* longer than the http time out */

	/* launch a new request on the persistent connection in .3 seconds */
	event_base_once(base, -1, EV_TIMEOUT, close_detect_launch, evcon, &tv);
 end:
	;
}


static void
http_close_detection_(struct basic_test_data *data, int with_delay)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	const struct timeval sec_tenth = { 0, 100000 };

	test_ok = 0;
	http = http_setup(&port, data->base, 0);

	/* .1 second timeout */
	evhttp_set_timeout_tv(http, &sec_tenth);

	evcon = evhttp_connection_base_new(data->base, NULL,
	    "127.0.0.1", port);
	evhttp_connection_set_timeout_tv(evcon, &sec_tenth);


	tt_assert(evcon);
	delayed_client = evcon;

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(close_detect_cb, evcon);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon,
	    req, EVHTTP_REQ_GET, with_delay ? "/largedelay" : "/test") == -1) {
		tt_abort_msg("couldn't make request");
	}

	event_base_dispatch(data->base);

	/* at this point, the http server should have no connection */
	tt_assert(TAILQ_FIRST(&http->connections) == NULL);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}
static void
http_close_detection_test(void *arg)
{
	http_close_detection_(arg, 0);
}
static void
http_close_detection_delay_test(void *arg)
{
	http_close_detection_(arg, 1);
}

static void
http_highport_test(void *arg)
{
	struct basic_test_data *data = arg;
	int i = -1;
	struct evhttp *myhttp = NULL;

	/* Try a few different ports */
	for (i = 0; i < 50; ++i) {
		myhttp = evhttp_new(data->base);
		if (evhttp_bind_socket(myhttp, "127.0.0.1", 65535 - i) == 0) {
			test_ok = 1;
			evhttp_free(myhttp);
			return;
		}
		evhttp_free(myhttp);
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
	int r;

	TAILQ_INIT(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test", &headers);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test&foo=bar", &headers);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "foo", "bar") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test+foo", &headers);
	tt_want(validate_header(&headers, "q", "test foo") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test%0Afoo", &headers);
	tt_want(validate_header(&headers, "q", "test\nfoo") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test%0Dfoo", &headers);
	tt_want(validate_header(&headers, "q", "test\rfoo") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test&&q2", &headers);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test+this", &headers);
	tt_want(validate_header(&headers, "q", "test this") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=test&q2=foo", &headers);
	tt_int_op(r, ==, 0);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "q2", "foo") == 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q&q2=foo", &headers);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=foo&q2", &headers);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=foo&q2&q3=x", &headers);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query("http://www.test.com/?q=&q2=&q3=", &headers);
	tt_int_op(r, ==, 0);
	tt_want(validate_header(&headers, "q", "") == 0);
	tt_want(validate_header(&headers, "q2", "") == 0);
	tt_want(validate_header(&headers, "q3", "") == 0);
	evhttp_clear_headers(&headers);

end:
	evhttp_clear_headers(&headers);
}

static void
http_parse_uri_test(void *ptr)
{
	const int nonconform = (ptr != NULL);
	const unsigned parse_flags =
	    nonconform ? EVHTTP_URI_NONCONFORMANT : 0;
	struct evhttp_uri *uri = NULL;
	char url_tmp[4096];
#define URI_PARSE(uri) \
	evhttp_uri_parse_with_flags((uri), parse_flags)

#define TT_URI(want) do { 						\
	char *ret = evhttp_uri_join(uri, url_tmp, sizeof(url_tmp));	\
	tt_want(ret != NULL);						\
	tt_want(ret == url_tmp);					\
	if (strcmp(ret,want) != 0)					\
		TT_FAIL(("\"%s\" != \"%s\"",ret,want));			\
	} while(0)

	tt_want(evhttp_uri_join(NULL, 0, 0) == NULL);
	tt_want(evhttp_uri_join(NULL, url_tmp, 0) == NULL);
	tt_want(evhttp_uri_join(NULL, url_tmp, sizeof(url_tmp)) == NULL);

	/* bad URIs: parsing */
#define BAD(s) do {							\
		if (URI_PARSE(s) != NULL)				\
			TT_FAIL(("Expected error parsing \"%s\"",s));	\
	} while(0)
	/* Nonconformant URIs we can parse: parsing */
#define NCF(s) do {							\
		uri = URI_PARSE(s);					\
		if (uri != NULL && !nonconform) {			\
			TT_FAIL(("Expected error parsing \"%s\"",s));	\
		} else if (uri == NULL && nonconform) {			\
			TT_FAIL(("Couldn't parse nonconformant URI \"%s\"", \
				s));					\
		}							\
		if (uri) {						\
			tt_want(evhttp_uri_join(uri, url_tmp,		\
				sizeof(url_tmp)));			\
			evhttp_uri_free(uri);				\
		}							\
	} while(0)

	NCF("http://www.test.com/ why hello");
	NCF("http://www.test.com/why-hello\x01");
	NCF("http://www.test.com/why-hello?\x01");
	NCF("http://www.test.com/why-hello#\x01");
	BAD("http://www.\x01.test.com/why-hello");
	BAD("http://www.%7test.com/why-hello");
	NCF("http://www.test.com/why-hell%7o");
	BAD("h%3ttp://www.test.com/why-hello");
	NCF("http://www.test.com/why-hello%7");
	NCF("http://www.test.com/why-hell%7o");
	NCF("http://www.test.com/foo?ba%r");
	NCF("http://www.test.com/foo#ba%r");
	BAD("99:99/foo");
	BAD("http://www.test.com:999x/");
	BAD("http://www.test.com:x/");
	BAD("http://[hello-there]/");
	BAD("http://[::1]]/");
	BAD("http://[::1/");
	BAD("http://[foob/");
	BAD("http://[/");
	BAD("http://[ffff:ffff:ffff:ffff:Ffff:ffff:ffff:"
	            "ffff:ffff:ffff:ffff:ffff:ffff:ffff]/");
	BAD("http://[vX.foo]/");
	BAD("http://[vX.foo]/");
	BAD("http://[v.foo]/");
	BAD("http://[v5.fo%o]/");
	BAD("http://[v5X]/");
	BAD("http://[v5]/");
	BAD("http://[]/");
	BAD("http://f\x01red@www.example.com/");
	BAD("http://f%0red@www.example.com/");
	BAD("http://www.example.com:9999999999999999999999999999999999999/");
	BAD("http://www.example.com:hihi/");
	BAD("://www.example.com/");

	/* bad URIs: joining */
	uri = evhttp_uri_new();
	tt_want(0==evhttp_uri_set_host(uri, "www.example.com"));
	tt_want(evhttp_uri_join(uri, url_tmp, sizeof(url_tmp)) != NULL);
	/* not enough space: */
	tt_want(evhttp_uri_join(uri, url_tmp, 3) == NULL);
	/* host is set, but path doesn't start with "/": */
	tt_want(0==evhttp_uri_set_path(uri, "hi_mom"));
	tt_want(evhttp_uri_join(uri, url_tmp, sizeof(url_tmp)) == NULL);
	tt_want(evhttp_uri_join(uri, NULL, sizeof(url_tmp))==NULL);
	tt_want(evhttp_uri_join(uri, url_tmp, 0)==NULL);
	evhttp_uri_free(uri);
	uri = URI_PARSE("mailto:foo@bar");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_host(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(!strcmp(evhttp_uri_get_scheme(uri), "mailto"));
	tt_want(!strcmp(evhttp_uri_get_path(uri), "foo@bar"));
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("mailto:foo@bar");
	evhttp_uri_free(uri);

	uri = evhttp_uri_new();
	/* Bad URI usage: setting invalid values */
	tt_want(-1 == evhttp_uri_set_scheme(uri,""));
	tt_want(-1 == evhttp_uri_set_scheme(uri,"33"));
	tt_want(-1 == evhttp_uri_set_scheme(uri,"hi!"));
	tt_want(-1 == evhttp_uri_set_userinfo(uri,"hello@"));
	tt_want(-1 == evhttp_uri_set_host(uri,"[1.2.3.4]"));
	tt_want(-1 == evhttp_uri_set_host(uri,"["));
	tt_want(-1 == evhttp_uri_set_host(uri,"www.[foo].com"));
	tt_want(-1 == evhttp_uri_set_port(uri,-3));
	tt_want(-1 == evhttp_uri_set_path(uri,"hello?world"));
	tt_want(-1 == evhttp_uri_set_query(uri,"hello#world"));
	tt_want(-1 == evhttp_uri_set_fragment(uri,"hello#world"));
	/* Valid URI usage: setting valid values */
	tt_want(0 == evhttp_uri_set_scheme(uri,"http"));
	tt_want(0 == evhttp_uri_set_scheme(uri,NULL));
	tt_want(0 == evhttp_uri_set_userinfo(uri,"username:pass"));
	tt_want(0 == evhttp_uri_set_userinfo(uri,NULL));
	tt_want(0 == evhttp_uri_set_host(uri,"www.example.com"));
	tt_want(0 == evhttp_uri_set_host(uri,"1.2.3.4"));
	tt_want(0 == evhttp_uri_set_host(uri,"[1:2:3:4::]"));
	tt_want(0 == evhttp_uri_set_host(uri,"[v7.wobblewobble]"));
	tt_want(0 == evhttp_uri_set_host(uri,NULL));
	tt_want(0 == evhttp_uri_set_host(uri,""));
	tt_want(0 == evhttp_uri_set_port(uri, -1));
	tt_want(0 == evhttp_uri_set_port(uri, 80));
	tt_want(0 == evhttp_uri_set_port(uri, 65535));
	tt_want(0 == evhttp_uri_set_path(uri, ""));
	tt_want(0 == evhttp_uri_set_path(uri, "/documents/public/index.html"));
	tt_want(0 == evhttp_uri_set_path(uri, NULL));
	tt_want(0 == evhttp_uri_set_query(uri, "key=val&key2=val2"));
	tt_want(0 == evhttp_uri_set_query(uri, "keyvalblarg"));
	tt_want(0 == evhttp_uri_set_query(uri, ""));
	tt_want(0 == evhttp_uri_set_query(uri, NULL));
	tt_want(0 == evhttp_uri_set_fragment(uri, ""));
	tt_want(0 == evhttp_uri_set_fragment(uri, "here?i?am"));
	tt_want(0 == evhttp_uri_set_fragment(uri, NULL));
	evhttp_uri_free(uri);

	/* Valid parsing */
	uri = URI_PARSE("http://www.test.com/?q=t%33est");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=t%33est") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://www.test.com/?q=t%33est");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://%77ww.test.com");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "%77ww.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://%77ww.test.com");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://www.test.com?q=test");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://www.test.com?q=test");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://www.test.com#fragment");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want_str_op(evhttp_uri_get_fragment(uri), ==, "fragment");
	TT_URI("http://www.test.com#fragment");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://8000/");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "8000") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://8000/");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://:8000/");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == 8000);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://:8000/");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://www.test.com:/"); /* empty port */
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want_str_op(evhttp_uri_get_path(uri), ==, "/");
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://www.test.com/");
	evhttp_uri_free(uri);

	uri = URI_PARSE("http://www.test.com:"); /* empty port 2 */
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "http") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("http://www.test.com");
	evhttp_uri_free(uri);

	uri = URI_PARSE("ftp://www.test.com/?q=test");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "ftp") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "www.test.com") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("ftp://www.test.com/?q=test");
	evhttp_uri_free(uri);

	uri = URI_PARSE("ftp://[::1]:999/?q=test");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "ftp") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "[::1]") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == 999);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("ftp://[::1]:999/?q=test");
	evhttp_uri_free(uri);

	uri = URI_PARSE("ftp://[ff00::127.0.0.1]/?q=test");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "ftp") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "[ff00::127.0.0.1]") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("ftp://[ff00::127.0.0.1]/?q=test");
	evhttp_uri_free(uri);

	uri = URI_PARSE("ftp://[v99.not_(any:time)_soon]/?q=test");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "ftp") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "[v99.not_(any:time)_soon]") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("ftp://[v99.not_(any:time)_soon]/?q=test");
	evhttp_uri_free(uri);

	uri = URI_PARSE("scheme://user:pass@foo.com:42/?q=test&s=some+thing#fragment");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "scheme") == 0);
	tt_want(strcmp(evhttp_uri_get_userinfo(uri), "user:pass") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "foo.com") == 0);
	tt_want(evhttp_uri_get_port(uri) == 42);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test&s=some+thing") == 0);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "fragment") == 0);
	TT_URI("scheme://user:pass@foo.com:42/?q=test&s=some+thing#fragment");
	evhttp_uri_free(uri);

	uri = URI_PARSE("scheme://user@foo.com/#fragment");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "scheme") == 0);
	tt_want(strcmp(evhttp_uri_get_userinfo(uri), "user") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "foo.com") == 0);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "fragment") == 0);
	TT_URI("scheme://user@foo.com/#fragment");
	evhttp_uri_free(uri);

	uri = URI_PARSE("scheme://%75ser@foo.com/#frag@ment");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "scheme") == 0);
	tt_want(strcmp(evhttp_uri_get_userinfo(uri), "%75ser") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "foo.com") == 0);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "frag@ment") == 0);
	TT_URI("scheme://%75ser@foo.com/#frag@ment");
	evhttp_uri_free(uri);

	uri = URI_PARSE("file:///some/path/to/the/file");
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "file") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(strcmp(evhttp_uri_get_host(uri), "") == 0);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/some/path/to/the/file") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("file:///some/path/to/the/file");
	evhttp_uri_free(uri);

	uri = URI_PARSE("///some/path/to/the-file");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_scheme(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(strcmp(evhttp_uri_get_host(uri), "") == 0);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/some/path/to/the-file") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("///some/path/to/the-file");
	evhttp_uri_free(uri);

	uri = URI_PARSE("/s:ome/path/to/the-file?q=99#fred");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_scheme(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_host(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/s:ome/path/to/the-file") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=99") == 0);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "fred") == 0);
	TT_URI("/s:ome/path/to/the-file?q=99#fred");
	evhttp_uri_free(uri);

	uri = URI_PARSE("relative/path/with/co:lon");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_scheme(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_host(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "relative/path/with/co:lon") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("relative/path/with/co:lon");
	evhttp_uri_free(uri);

	uri = URI_PARSE("bob?q=99&q2=q?33#fr?ed");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_scheme(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_host(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "bob") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=99&q2=q?33") == 0);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "fr?ed") == 0);
	TT_URI("bob?q=99&q2=q?33#fr?ed");
	evhttp_uri_free(uri);

	uri = URI_PARSE("#fr?ed");
	tt_want(uri != NULL);
	tt_want(evhttp_uri_get_scheme(uri) == NULL);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_host(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(strcmp(evhttp_uri_get_path(uri), "") == 0);
	tt_want(evhttp_uri_get_query(uri) == NULL);
	tt_want(strcmp(evhttp_uri_get_fragment(uri), "fr?ed") == 0);
	TT_URI("#fr?ed");
	evhttp_uri_free(uri);
#undef URI_PARSE
#undef TT_URI
#undef BAD
}

static void
http_uriencode_test(void *ptr)
{
	char *s=NULL, *s2=NULL;
	size_t sz;
	int bytes_decoded;

#define ENC(from,want,plus) do {				\
		s = evhttp_uriencode((from), -1, (plus));	\
		tt_assert(s);					\
		tt_str_op(s,==,(want));				\
		sz = -1;					\
		s2 = evhttp_uridecode((s), (plus), &sz);	\
		tt_assert(s2);					\
		tt_str_op(s2,==,(from));			\
		tt_int_op(sz,==,strlen(from));			\
		free(s);					\
		free(s2);					\
		s = s2 = NULL;					\
	} while (0)

#define DEC(from,want,dp) do {					\
		s = evhttp_uridecode((from),(dp),&sz);		\
		tt_assert(s);					\
		tt_str_op(s,==,(want));				\
		tt_int_op(sz,==,strlen(want));			\
		free(s);					\
		s = NULL;					\
	} while (0)

#define OLD_DEC(from,want)  do {				\
		s = evhttp_decode_uri((from));			\
		tt_assert(s);					\
		tt_str_op(s,==,(want));				\
		free(s);					\
		s = NULL;					\
	} while (0)


      	ENC("Hello", "Hello",0);
	ENC("99", "99",0);
	ENC("", "",0);
	ENC(
	 "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-.~_",
	 "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789-.~_",0);
	ENC(" ", "%20",0);
	ENC(" ", "+",1);
	ENC("\xff\xf0\xe0", "%FF%F0%E0",0);
	ENC("\x01\x19", "%01%19",1);
	ENC("http://www.ietf.org/rfc/rfc3986.txt",
	    "http%3A%2F%2Fwww.ietf.org%2Frfc%2Frfc3986.txt",1);

	ENC("1+2=3", "1%2B2%3D3",1);
	ENC("1+2=3", "1%2B2%3D3",0);

	/* Now try encoding with internal NULs. */
	s = evhttp_uriencode("hello\0world", 11, 0);
	tt_assert(s);
	tt_str_op(s,==,"hello%00world");
	free(s);
	s = NULL;

	/* Now try decoding just part of string. */
	s = malloc(6 + 1 /* NUL byte */);
	bytes_decoded = evhttp_decode_uri_internal("hello%20%20", 6, s, 0);
	tt_assert(s);
	tt_int_op(bytes_decoded,==,6);
	tt_str_op(s,==,"hello%");
	free(s);
	s = NULL;

	/* Now try out some decoding cases that we don't generate with
	 * encode_uri: Make sure that malformed stuff doesn't crash... */
	DEC("%%xhello th+ere \xff",
	    "%%xhello th+ere \xff", 0);
	/* Make sure plus decoding works */
	DEC("plus+should%20work+", "plus should work ",1);
	/* Try some lowercase hex */
	DEC("%f0%a0%b0", "\xf0\xa0\xb0",1);

	/* Try an internal NUL. */
	sz = 0;
	s = evhttp_uridecode("%00%00x%00%00", 1, &sz);
	tt_int_op(sz,==,5);
	tt_assert(!memcmp(s, "\0\0x\0\0", 5));
	free(s);
	s = NULL;

	/* Try with size == NULL */
	sz = 0;
	s = evhttp_uridecode("%00%00x%00%00", 1, NULL);
	tt_assert(!memcmp(s, "\0\0x\0\0", 5));
	free(s);
	s = NULL;

	/* Test out the crazy old behavior of the deprecated
	 * evhttp_decode_uri */
	OLD_DEC("http://example.com/normal+path/?key=val+with+spaces",
	        "http://example.com/normal+path/?key=val with spaces");

end:
	if (s)
		free(s);
	if (s2)
		free(s2);
#undef ENC
#undef DEC
#undef OLD_DEC
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
	base = event_base_new();
	http = http_setup(&port, base, 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, base);
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
	event_base_loopexit(exit_base,NULL);
}

static void
http_incomplete_errorcb(struct bufferevent *bev, short what, void *arg)
{
	if (what == (BEV_EVENT_READING|BEV_EVENT_EOF))
		test_ok++;
	else
		test_ok = -2;
	event_base_loopexit(exit_base,NULL);
}

static void
http_incomplete_writecb(struct bufferevent *bev, void *arg)
{
	if (arg != NULL) {
		evutil_socket_t fd = *(evutil_socket_t *)arg;
		/* terminate the write side to simulate EOF */
		shutdown(fd, SHUT_WR);
	}
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_incomplete_test_(struct basic_test_data *data, int use_timeout)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;

	exit_base = data->base;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);
	evhttp_set_timeout(http, 1);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev,
	    http_incomplete_readcb, http_incomplete_writecb,
	    http_incomplete_errorcb, use_timeout ? NULL : &fd);

	http_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	evutil_gettimeofday(&tv_start, NULL);

	event_base_dispatch(data->base);

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
http_incomplete_test(void *arg)
{
	http_incomplete_test_(arg, 0);
}
static void
http_incomplete_timeout_test(void *arg)
{
	http_incomplete_test_(arg, 1);
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

	if ((what & BEV_EVENT_EOF) != 0) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		const char *header;
		enum message_read_status done;

		/* req->kind = EVHTTP_RESPONSE; */
		done = evhttp_parse_firstline_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		done = evhttp_parse_headers_(req, bufferevent_get_input(bev));
		if (done != ALL_DATA_READ)
			goto out;

		header = evhttp_find_header(evhttp_request_get_input_headers(req), "Transfer-Encoding");
		if (header == NULL || strcmp(header, "chunked"))
			goto out;

		header = evhttp_find_header(evhttp_request_get_input_headers(req), "Connection");
		if (header == NULL || strcmp(header, "close"))
			goto out;

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 13 chars */
		if (strcmp(header, "d")) {
			free((void*)header);
			goto out;
		}
		free((void*)header);

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
		if (strcmp(header, "8")) {
			free((void*)header);
			goto out;
		}
		free((char *)header);

		if (strncmp((char *)evbuffer_pullup(bufferevent_get_input(bev), 8),
			"bwv 1052.", 8))
			goto out;

		evbuffer_drain(bufferevent_get_input(bev), 8 + 2);

		header = evbuffer_readln(bufferevent_get_input(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 0 chars */
		if (strcmp(header, "0")) {
			free((void*)header);
			goto out;
		}
		free((void *)header);

		test_ok = 2;

		evhttp_request_free(req);
	}

out:
	event_base_loopexit(arg, NULL);
}

static void
http_chunked_writecb(struct bufferevent *bev, void *arg)
{
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_chunked_request_done(struct evhttp_request *req, void *arg)
{
	if (evhttp_request_get_response_code(req) != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(evhttp_request_get_input_headers(req),
		"Transfer-Encoding") == NULL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != 13 + 18 + 8) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (strncmp((char *)evbuffer_pullup(evhttp_request_get_input_buffer(req), 13 + 18 + 8),
		"This is funnybut not hilarious.bwv 1052",
		13 + 18 + 8)) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_base_loopexit(arg, NULL);
}

static void
http_chunk_out_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	int i;

	exit_base = data->base;
	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev,
	    http_chunked_readcb, http_chunked_writecb,
	    http_chunked_errorcb, data->base);

	http_request =
	    "GET /chunked HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	evutil_gettimeofday(&tv_start, NULL);

	event_base_dispatch(data->base);

	bufferevent_free(bev);

	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	tt_int_op(tv_end.tv_sec, <, 1);

	tt_int_op(test_ok, ==, 2);

	/* now try again with the regular connection object */
	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/* make two requests to check the keepalive behavior */
	for (i = 0; i < 2; i++) {
		test_ok = 0;
		req = evhttp_request_new(http_chunked_request_done,data->base);

		/* Add the information that we care about */
		evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

		/* We give ownership of the request to the connection */
		if (evhttp_make_request(evcon, req,
			EVHTTP_REQ_GET, "/chunked") == -1) {
			tt_abort_msg("Couldn't make request");
		}

		event_base_dispatch(data->base);

		tt_assert(test_ok == 1);
	}

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_stream_out_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	exit_base = data->base;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done,
	    (void *)"This is funnybut not hilarious.bwv 1052");

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/streamed")
	    == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

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

	if (evhttp_request_get_response_code(req) != HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	evbuffer_add_buffer(reply, evhttp_request_get_input_buffer(req));
}

static void
http_stream_in_done(struct evhttp_request *req, void *arg)
{
	if (evbuffer_get_length(evhttp_request_get_input_buffer(req)) != 0) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	event_base_loopexit(exit_base, NULL);
}

/**
 * Makes a request and reads the response in chunks.
 */
static void
http_stream_in_test_(struct basic_test_data *data, char const *url,
    size_t expected_len, char const *expected)
{
	struct evhttp_connection *evcon;
	struct evbuffer *reply = evbuffer_new();
	struct evhttp_request *req = NULL;
	ev_uint16_t port = 0;

	exit_base = data->base;
	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL,"127.0.0.1", port);
	tt_assert(evcon);

	req = evhttp_request_new(http_stream_in_done, reply);
	evhttp_request_set_chunked_cb(req, http_stream_in_chunk);

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, url) == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	if (evbuffer_get_length(reply) != expected_len) {
		TT_DIE(("reply length %lu; expected %lu; FAILED (%s)\n",
				(unsigned long)evbuffer_get_length(reply),
				(unsigned long)expected_len,
				(char*)evbuffer_pullup(reply, -1)));
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
http_stream_in_test(void *arg)
{
	http_stream_in_test_(arg, "/chunked", 13 + 18 + 8,
	    "This is funnybut not hilarious.bwv 1052");

	http_stream_in_test_(arg, "/test", strlen(BASIC_REQUEST_BODY),
	    BASIC_REQUEST_BODY);
}

static void
http_stream_in_cancel_chunk(struct evhttp_request *req, void *arg)
{
	tt_int_op(evhttp_request_get_response_code(req), ==, HTTP_OK);

 end:
	evhttp_cancel_request(req);
	event_base_loopexit(arg, NULL);
}

static void
http_stream_in_cancel_done(struct evhttp_request *req, void *arg)
{
	/* should never be called */
	tt_fail_msg("In cancel done");
}

static void
http_stream_in_cancel_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct evhttp_connection *evcon;
	struct evhttp_request *req = NULL;
	ev_uint16_t port = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	req = evhttp_request_new(http_stream_in_cancel_done, data->base);
	evhttp_request_set_chunked_cb(req, http_stream_in_cancel_chunk);

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/chunked") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	test_ok = 1;
 end:
	evhttp_connection_free(evcon);
	evhttp_free(http);

}

static void
http_connection_fail_done(struct evhttp_request *req, void *arg)
{
       struct evhttp_connection *evcon = arg;
       struct event_base *base = evhttp_connection_get_base(evcon);

       /* An ENETUNREACH error results in an unrecoverable
        * evhttp_connection error (see evhttp_connection_fail_()).  The
        * connection will be reset, and the user will be notified with a NULL
        * req parameter. */
       tt_assert(!req);

       evhttp_connection_free(evcon);

       test_ok = 1;

 end:
       event_base_loopexit(base, NULL);
}

/* Test unrecoverable evhttp_connection errors by generating an ENETUNREACH
 * error on connection. */
static void
http_connection_fail_test(void *arg)
{
       struct basic_test_data *data = arg;
       ev_uint16_t port = 0;
       struct evhttp_connection *evcon = NULL;
       struct evhttp_request *req = NULL;

       exit_base = data->base;
       test_ok = 0;

       /* auto detect a port */
       http = http_setup(&port, data->base, 0);
       evhttp_free(http);
       http = NULL;

       /* Pick an unroutable address.  This administratively scoped multicast
	* address should do when working with TCP. */
       evcon = evhttp_connection_base_new(data->base, NULL, "239.10.20.30", 80);
       tt_assert(evcon);

       /*
        * At this point, we want to schedule an HTTP GET request
        * server using our make request method.
        */

       req = evhttp_request_new(http_connection_fail_done, evcon);
       tt_assert(req);

       if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/") == -1) {
               tt_abort_msg("Couldn't make request");
       }

       event_base_dispatch(data->base);

       tt_int_op(test_ok, ==, 1);

 end:
        ;
}

static void
http_connection_retry_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(evhttp_request_get_response_code(req), !=, HTTP_OK);
	if (evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Type") != NULL) {
		tt_abort_msg("(content type)\n");
	}

	tt_uint_op(evbuffer_get_length(evhttp_request_get_input_buffer(req)), ==, 0);

	test_ok = 1;
 end:
	event_base_loopexit(arg,NULL);
}

static struct event_base *http_make_web_server_base=NULL;
static void
http_make_web_server(evutil_socket_t fd, short what, void *arg)
{
	ev_uint16_t port = *(ev_uint16_t*)arg;
	http = http_setup(&port, http_make_web_server_base, 0);
}

static void
http_connection_retry_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv, tv_start, tv_end;

	exit_base = data->base;
	test_ok = 0;

	/* auto detect a port */
	http = http_setup(&port, data->base, 0);
	evhttp_free(http);
	http = NULL;

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	evhttp_connection_set_timeout(evcon, 1);
	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_connection_retry_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	evutil_gettimeofday(&tv_start, NULL);
	event_base_dispatch(data->base);
	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	tt_int_op(tv_end.tv_sec, <, 1);

	tt_int_op(test_ok, ==, 1);

	/*
	 * now test the same but with retries
	 */
	test_ok = 0;

	{
		const struct timeval tv_timeout = { 0, 500000 };
		const struct timeval tv_retry = { 0, 500000 };
		evhttp_connection_set_timeout_tv(evcon, &tv_timeout);
		evhttp_connection_set_initial_retry_tv(evcon, &tv_retry);
	}
	evhttp_connection_set_retries(evcon, 1);

	req = evhttp_request_new(http_connection_retry_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	evutil_gettimeofday(&tv_start, NULL);
	event_base_dispatch(data->base);
	evutil_gettimeofday(&tv_end, NULL);

	/* fails fast, .5 sec to wait to retry, fails fast again. */
	test_timeval_diff_leq(&tv_start, &tv_end, 500, 200);

	tt_assert(test_ok == 1);

	/*
	 * now test the same but with retries and give it a web server
	 * at the end
	 */
	test_ok = 0;

	evhttp_connection_set_timeout(evcon, 1);
	evhttp_connection_set_retries(evcon, 3);

	req = evhttp_request_new(http_dispatcher_test_done, data->base);
	tt_assert(req);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	/* start up a web server .2 seconds after the connection tried
	 * to send a request
	 */
	evutil_timerclear(&tv);
	tv.tv_usec = 200000;
	http_make_web_server_base = data->base;
	event_base_once(data->base, -1, EV_TIMEOUT, http_make_web_server, &port, &tv);

	evutil_gettimeofday(&tv_start, NULL);
	event_base_dispatch(data->base);
	evutil_gettimeofday(&tv_end, NULL);
	/* We'll wait twice as long as we did last time. */
	test_timeval_diff_leq(&tv_start, &tv_end, 1000, 400);

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
	struct evhttp *http = NULL;

	escaped = evhttp_htmlescape("<script>");
	tt_assert(escaped);
	tt_str_op(escaped, ==, "&lt;script&gt;");
	free(escaped);

	escaped = evhttp_htmlescape("\"\'&");
	tt_assert(escaped);
	tt_str_op(escaped, ==, "&quot;&#039;&amp;");

	http = evhttp_new(NULL);
	tt_assert(http);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, 0);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, -1);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, 0);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, -1);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, NULL), ==, 0);

 end:
	if (escaped)
		free(escaped);
	if (http)
		evhttp_free(http);
}

static void
http_multi_line_header_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev= NULL;
	evutil_socket_t fd = -1;
	const char *http_start_request;
	ev_uint16_t port = 0;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_start_request =
	    "GET /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "X-Multi-Extra-WS:  libevent  \r\n"
	    "\t\t\t2.1 \r\n"
	    "X-Multi:  aaaaaaaa\r\n"
	    " a\r\n"
	    "\tEND\r\n"
	    "X-Last: last\r\n"
	    "\r\n";

	bufferevent_write(bev, http_start_request, strlen(http_start_request));
	found_multi = found_multi2 = 0;

	event_base_dispatch(data->base);

	tt_int_op(found_multi, ==, 1);
	tt_int_op(found_multi2, ==, 1);
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
	event_base_loopexit(arg, NULL);
}

static void
http_negative_content_length_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_bad, data->base);

	/* Cause the response to have a negative content-length */
	evhttp_add_header(evhttp_request_get_output_headers(req), "X-Negative", "makeitso");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

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
	tt_int_op(evhttp_request_get_response_code(req), ==, HTTP_BADREQUEST);
end:
	event_base_loopexit(arg, NULL);
}

static void
http_large_entity_test_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(evhttp_request_get_response_code(req), ==, HTTP_ENTITYTOOLARGE);
end:
	event_base_loopexit(arg, NULL);
}

static void
http_data_length_constraints_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	char long_str[8192];

	test_ok = 0;

	http = http_setup(&port, data->base, 0);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_data_length_constraints_test_done, data->base);
	tt_assert(req);

	memset(long_str, 'a', 8192);
	long_str[8191] = '\0';
	/* Add the information that we care about */
	evhttp_set_max_headers_size(http, 8191);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Longheader", long_str);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	req = evhttp_request_new(http_data_length_constraints_test_done, data->base);
	tt_assert(req);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* GET /?arg=verylongvalue HTTP/1.1 */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, long_str) == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	evhttp_set_max_body_size(http, 8190);
	req = evhttp_request_new(http_data_length_constraints_test_done, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	req = evhttp_request_new(http_large_entity_test_done, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Expect", "100-continue");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

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
	struct event_base *base;
	struct evhttp_request *req;
	struct bufferevent *bev;
	evutil_socket_t fd;
	int gotclosecb: 1;
};

static void
terminate_chunked_trickle_cb(evutil_socket_t fd, short events, void *arg)
{
	struct terminate_state *state = arg;
	struct evbuffer *evb;
	struct timeval tv;

	if (evhttp_request_get_connection(state->req) == NULL) {
		test_ok = 1;
		evhttp_request_free(state->req);
		event_base_loopexit(state->base,NULL);
		return;
	}

	evb = evbuffer_new();
	evbuffer_add_printf(evb, "%p", evb);
	evhttp_send_reply_chunk(state->req, evb);
	evbuffer_free(evb);

	tv.tv_sec = 0;
	tv.tv_usec = 3000;
	EVUTIL_ASSERT(state);
	EVUTIL_ASSERT(state->base);
	event_base_once(state->base, -1, EV_TIMEOUT, terminate_chunked_trickle_cb, arg, &tv);
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
	event_base_once(state->base, -1, EV_TIMEOUT, terminate_chunked_trickle_cb, arg, &tv);
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
http_terminate_chunked_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	struct timeval tv;
	const char *http_request;
	ev_uint16_t port = 0;
	evutil_socket_t fd = -1;
	struct terminate_state terminate_state;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);
	evhttp_del_cb(http, "/test");
	tt_assert(evhttp_set_cb(http, "/test",
		terminate_chunked_cb, &terminate_state) == 0);

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, terminate_readcb, http_writecb,
	    http_errorcb, data->base);

	memset(&terminate_state, 0, sizeof(terminate_state));
	terminate_state.base = data->base;
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
	event_base_once(data->base, -1, EV_TIMEOUT, terminate_chunked_client, &terminate_state,
	    &tv);

	event_base_dispatch(data->base);

	if (terminate_state.gotclosecb == 0)
		test_ok = 0;

 end:
	if (fd >= 0)
		evutil_closesocket(fd);
	if (http)
		evhttp_free(http);
}

static struct regress_dns_server_table ipv6_search_table[] = {
	{ "localhost", "AAAA", "::1", 0 },
	{ NULL, NULL, NULL, 0 }
};

static void
http_ipv6_for_domain_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct evdns_base *dns_base = NULL;
	ev_uint16_t portnum = 0;
	char address[64];

	tt_assert(regress_dnsserver(data->base, &portnum, ipv6_search_table));

	dns_base = evdns_base_new(data->base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	http_connection_test_(arg, 0 /* not persistent */, "localhost", dns_base, 1 /* ipv6 */);

 end:
	if (dns_base)
		evdns_base_free(dns_base, 0);
	regress_clean_dnsserver();
}

#define HTTP_LEGACY(name)						\
	{ #name, run_legacy_test_fn, TT_ISOLATED|TT_LEGACY, &legacy_setup, \
		    http_##name##_test }

#define HTTP(name) \
	{ #name, http_##name##_test, TT_ISOLATED, &basic_setup, NULL }

struct testcase_t http_testcases[] = {
	{ "primitives", http_primitives, 0, NULL, NULL },
	{ "base", http_base_test, TT_FORK, NULL, NULL },
	{ "bad_headers", http_bad_header_test, 0, NULL, NULL },
	{ "parse_query", http_parse_query_test, 0, NULL, NULL },
	{ "parse_uri", http_parse_uri_test, 0, NULL, NULL },
	{ "parse_uri_nc", http_parse_uri_test, 0, &basic_setup, (void*)"nc" },
	{ "uriencode", http_uriencode_test, 0, NULL, NULL },
	HTTP(basic),
	HTTP(cancel),
	HTTP(virtual_host),
	HTTP(post),
	HTTP(put),
	HTTP(delete),
	HTTP(allowed_methods),
	HTTP(failure),
	HTTP(connection),
	HTTP(persist_connection),
	HTTP(connection_async),
	HTTP(close_detection),
	HTTP(close_detection_delay),
	HTTP(bad_request),
	HTTP(incomplete),
	HTTP(incomplete_timeout),
	HTTP(terminate_chunked),

	HTTP(highport),
	HTTP(dispatcher),
	HTTP(multi_line_header),
	HTTP(negative_content_length),
	HTTP(chunk_out),
	HTTP(stream_out),

	HTTP(stream_in),
	HTTP(stream_in_cancel),

	HTTP(connection_fail),
	HTTP(connection_retry),
	HTTP(data_length_constraints),

	HTTP(ipv6_for_domain),

	END_OF_TESTCASES
};

