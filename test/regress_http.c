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
#include "event2/bufferevent_ssl.h"
#include "event2/util.h"
#include "event2/listener.h"
#include "log-internal.h"
#include "http-internal.h"
#include "regress.h"
#include "regress_testutils.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

/* set if a test needs to call loopexit on a base */
static struct event_base *exit_base;

static char const BASIC_REQUEST_BODY[] = "This is funny";

/* defines an extended HTTP method "CUSTOM"
 * without body */
#define EVHTTP_REQ_CUSTOM	((EVHTTP_REQ_MAX) << 1)

static int ext_method_cb(struct evhttp_ext_method *p)
{
	if (p == NULL)
		return -1;
	if (p->method) {
		if (strcmp(p->method, "CUSTOM") == 0) {
			p->type = EVHTTP_REQ_CUSTOM;
			p->flags = 0;	/*EVHTTP_METHOD_HAS_BODY*/
			return 0;
		}
	} else {
		if (p->type == EVHTTP_REQ_CUSTOM) {
			p->method = "CUSTOM";
			return 0;
		}
	}
	return -1;
}

static void http_basic_cb(struct evhttp_request *req, void *arg);
static void http_timeout_cb(struct evhttp_request *req, void *arg);
static void http_large_cb(struct evhttp_request *req, void *arg);
static void http_chunked_cb(struct evhttp_request *req, void *arg);
static void http_chunked_input_cb(struct evhttp_request *req, void *arg);
static void http_post_cb(struct evhttp_request *req, void *arg);
static void http_put_cb(struct evhttp_request *req, void *arg);
static void http_genmethod_cb(struct evhttp_request *req, void *arg);
static void http_custom_cb(struct evhttp_request *req, void *arg);
static void http_delay_cb(struct evhttp_request *req, void *arg);
static void http_large_delay_cb(struct evhttp_request *req, void *arg);
static void http_badreq_cb(struct evhttp_request *req, void *arg);
static void http_dispatcher_cb(struct evhttp_request *req, void *arg);
static void http_on_complete_cb(struct evhttp_request *req, void *arg);

#define HTTP_BIND_IPV6 1
#define HTTP_OPENSSL 2
#define HTTP_SSL_FILTER 4
#define HTTP_MBEDTLS 8
static int
http_bind(struct evhttp *myhttp, ev_uint16_t *pport, int mask)
{
	int port;
	struct evhttp_bound_socket *sock;
	int ipv6 = mask & HTTP_BIND_IPV6;

	if (ipv6)
		sock = evhttp_bind_socket_with_handle(myhttp, "::1", *pport);
	else
		sock = evhttp_bind_socket_with_handle(myhttp, "127.0.0.1", *pport);

	if (sock == NULL) {
		if (ipv6)
			return -1;
		else
			event_errx(1, "Could not start web server");
	}

	port = regress_get_socket_port(evhttp_bound_socket_get_fd(sock));
	if (port < 0)
		return -1;
	*pport = (ev_uint16_t) port;

	return 0;
}

#ifdef EVENT__HAVE_OPENSSL
static struct bufferevent *
https_bev(struct event_base *base, void *arg)
{
	SSL *ssl = SSL_new(get_ssl_ctx());

	SSL_use_certificate(ssl, ssl_getcert(ssl_getkey()));
	SSL_use_PrivateKey(ssl, ssl_getkey());

	return bufferevent_openssl_socket_new(
		base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE);
}
#endif
#ifdef EVENT__HAVE_MBEDTLS
static struct bufferevent *
https_mbedtls_bev(struct event_base *base, void *arg)
{
	mbedtls_ssl_context *ssl = mbedtls_ssl_new(get_mbedtls_config(MBEDTLS_SSL_IS_SERVER));
	return bufferevent_mbedtls_socket_new(
		base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE);
}
#endif
static struct evhttp *
http_setup_gencb(ev_uint16_t *pport, struct event_base *base, int mask,
	void (*cb)(struct evhttp_request *, void *), void *cbarg)
{
	struct evhttp *myhttp;

	/* Try a few different ports */
	myhttp = evhttp_new(base);

	if (http_bind(myhttp, pport, mask) < 0)
		return NULL;
#ifdef EVENT__HAVE_OPENSSL
	if (mask & HTTP_OPENSSL) {
		init_ssl();
		evhttp_set_bevcb(myhttp, https_bev, NULL);
	}
#endif
#ifdef EVENT__HAVE_MBEDTLS
	if (mask & HTTP_MBEDTLS) {
		evhttp_set_bevcb(myhttp, https_mbedtls_bev, NULL);
	}
#endif

	evhttp_set_gencb(myhttp, cb, cbarg);

	/* add support for extended HTTP methods */
	evhttp_set_ext_method_cmp(myhttp, ext_method_cb);

	/* Register a callback for certain types of requests */
	evhttp_set_cb(myhttp, "/test", http_basic_cb, myhttp);
	evhttp_set_cb(myhttp, "/test nonconformant", http_basic_cb, myhttp);
	evhttp_set_cb(myhttp, "/timeout", http_timeout_cb, myhttp);
	evhttp_set_cb(myhttp, "/large", http_large_cb, base);
	evhttp_set_cb(myhttp, "/chunked", http_chunked_cb, base);
	evhttp_set_cb(myhttp, "/chunked_input", http_chunked_input_cb, base);
	evhttp_set_cb(myhttp, "/streamed", http_chunked_cb, base);
	evhttp_set_cb(myhttp, "/postit", http_post_cb, base);
	evhttp_set_cb(myhttp, "/putit", http_put_cb, base);
	evhttp_set_cb(myhttp, "/deleteit", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/propfind", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/proppatch", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/mkcol", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/lockit", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/unlockit", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/copyit", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/moveit", http_genmethod_cb, base);
	evhttp_set_cb(myhttp, "/custom", http_custom_cb, base);
	evhttp_set_cb(myhttp, "/delay", http_delay_cb, base);
	evhttp_set_cb(myhttp, "/largedelay", http_large_delay_cb, base);
	evhttp_set_cb(myhttp, "/badrequest", http_badreq_cb, base);
	evhttp_set_cb(myhttp, "/oncomplete", http_on_complete_cb, base);
	evhttp_set_cb(myhttp, "/", http_dispatcher_cb, base);
	return (myhttp);
}
static struct evhttp *
http_setup(ev_uint16_t *pport, struct event_base *base, int mask)
{ return http_setup_gencb(pport, base, mask, NULL, NULL); }

#ifndef NI_MAXSERV
#define NI_MAXSERV 1024
#endif

static evutil_socket_t
http_connect(const char *address, ev_uint16_t port)
{
	/* Stupid code for connecting */
	struct evutil_addrinfo ai, *aitop;
	char strport[NI_MAXSERV];

	struct sockaddr *sa;
	size_t slen;
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
	if (!d)
		d = (unsigned char *)"";
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
	/** For ssl */
	if (what & BEV_EVENT_CONNECTED)
		return;
	test_ok = -2;
	event_base_loopexit(arg, NULL);
}

static int found_multi = 0;
static int found_multi2 = 0;

static void
http_basic_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	struct evhttp_connection *evcon;
	int empty = evhttp_find_header(evhttp_request_get_input_headers(req), "Empty") != NULL;

	TT_BLATHER(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	evcon = evhttp_request_get_connection(req);
	tt_assert(evhttp_connection_get_server(evcon) == arg);

	{
		const struct sockaddr *sa;
		char addrbuf[128];

		sa = evhttp_connection_get_addr(evcon);
		tt_assert(sa);

		if (sa->sa_family == AF_INET) {
			evutil_format_sockaddr_port_((struct sockaddr *)sa, addrbuf, sizeof(addrbuf));
			tt_assert(!strncmp(addrbuf, "127.0.0.1:", strlen("127.0.0.1:")));
		} else if (sa->sa_family == AF_INET6) {
			evutil_format_sockaddr_port_((struct sockaddr *)sa, addrbuf, sizeof(addrbuf));
			tt_assert(!strncmp(addrbuf, "[::1]:", strlen("[::1]:")));
		} else {
			tt_fail_msg("Unsupported family");
		}
	}

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

end:
	evbuffer_free(evb);
}

static void http_timeout_reply_cb(evutil_socket_t fd, short events, void *arg)
{
	struct evhttp_request *req = arg;
	evhttp_send_reply(req, HTTP_OK, "Everything is fine", NULL);
	test_ok++;
}
static void
http_timeout_cb(struct evhttp_request *req, void *arg)
{
	struct timeval when = { 0, 100 };
	event_base_once(exit_base, -1, EV_TIMEOUT,
	    http_timeout_reply_cb, req, &when);
}

static void
http_large_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int i;

	for (i = 0; i < 1<<20; ++i) {
		evbuffer_add_printf(evb, BASIC_REQUEST_BODY);
	}
	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);
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
	TT_BLATHER(("%s: called\n", __func__));

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
http_chunked_input_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *buf = evbuffer_new();
	TT_BLATHER(("%s: called\n", __func__));

	evbuffer_add_buffer(buf, evhttp_request_get_input_buffer(req));
	evhttp_send_reply(req, HTTP_OK, "OK", buf);

	evbuffer_free(buf);
}

static struct bufferevent *
create_bev(struct event_base *base, evutil_socket_t fd, int ssl_mask, int flags_)
{
	int flags = BEV_OPT_DEFER_CALLBACKS | flags_;
	struct bufferevent *bev = NULL;

	if (!ssl_mask) {
		bev = bufferevent_socket_new(base, fd, flags);
	} else if (ssl_mask & HTTP_OPENSSL){
#ifdef EVENT__HAVE_OPENSSL
		SSL *ssl = SSL_new(get_ssl_ctx());
		if (ssl_mask & HTTP_SSL_FILTER) {
			struct bufferevent *underlying =
				bufferevent_socket_new(base, fd, flags);
			bev = bufferevent_openssl_filter_new(
				base, underlying, ssl, BUFFEREVENT_SSL_CONNECTING, flags);
		} else {
			bev = bufferevent_openssl_socket_new(
				base, fd, ssl, BUFFEREVENT_SSL_CONNECTING, flags);
		}
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
#endif
	} else if (ssl_mask & HTTP_MBEDTLS) {
#ifdef EVENT__HAVE_MBEDTLS
		mbedtls_ssl_context *ssl = mbedtls_ssl_new(get_mbedtls_config(MBEDTLS_SSL_IS_CLIENT));
		if (ssl_mask & HTTP_SSL_FILTER) {
			struct bufferevent *underlying =
			bufferevent_socket_new(base, fd, flags);
			bev = bufferevent_mbedtls_filter_new(
				base, underlying, ssl, BUFFEREVENT_SSL_CONNECTING, flags);
		} else {
			bev = bufferevent_mbedtls_socket_new(
				base, fd, ssl, BUFFEREVENT_SSL_CONNECTING, flags);
		}
		bufferevent_mbedtls_set_allow_dirty_shutdown(bev, 1);
#endif
	}

	return bev;
}

static void
http_half_writecb(struct bufferevent *bev, void *arg)
{
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		if (!test_ok) {
			const char http_request[] = "host\r\n"
				"Connection: close\r\n"
				"\r\n";
			bufferevent_write(bev, http_request, strlen(http_request));
		}
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_basic_test_impl(void *arg, int ssl, const char *request_line)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0, port2 = 0;
	int server_flags = ssl;
	struct evhttp *http = http_setup(&port, data->base, server_flags);
	struct evbuffer *out;

	exit_base = data->base;

	/* bind to a second socket */
	if (http_bind(http, &port2, server_flags) == -1) {
		fprintf(stdout, "FAILED (bind)\n");
		exit(1);
	}

	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, http_readcb, http_half_writecb,
	    http_errorcb, data->base);
	out = bufferevent_get_output(bev);

	/* first half of the http request */
	evbuffer_add_printf(out,
	    "%s\r\n"
	    "Host: some", request_line);

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 3);

	/* connect to the second port */
	bufferevent_free(bev);

	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);
	out = bufferevent_get_output(bev);

	evbuffer_add_printf(out,
	    "%s\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n", request_line);

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 2);

	/* Connect to the second port again. This time, send an absolute uri. */
	bufferevent_free(bev);

	fd = http_connect("127.0.0.1", port2);

	/* Stupid thing to send a request */
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "GET http://somehost.net/test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 2);

	evhttp_free(http);
end:
	if (bev)
		bufferevent_free(bev);
}
static void http_basic_test(void *arg)\
{ http_basic_test_impl(arg, 0, "GET /test HTTP/1.1"); }
static void http_basic_trailing_space_test(void *arg)
{ http_basic_test_impl(arg, 0, "GET /test HTTP/1.1 "); }


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
	TT_BLATHER(("%s: called (what=%04x, arg=%p)", __func__, what, arg));
	/* ignore */
}

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

	shutdown(bufferevent_getfd(bev), EVUTIL_SHUT_WR);
}

static void
http_badreq_successcb(evutil_socket_t fd, short what, void *arg)
{
	TT_BLATHER(("%s: called (what=%04x, arg=%p)", __func__, what, arg));
	event_base_loopexit(exit_base, NULL);
}

static void
http_bad_request_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct timeval tv;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	const char *http_request;
	ev_uint16_t port=0, port2=0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;
	exit_base = data->base;

	/* bind to a second socket */
	if (http_bind(http, &port2, 0) == -1)
		TT_DIE(("Bind socket failed"));

	/* NULL request test */
	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_badreq_readcb, http_writecb,
	    http_badreq_errorcb, data->base);
	bufferevent_enable(bev, EV_READ);

	/* real NULL request */
	http_request = "";

	bufferevent_write(bev, http_request, strlen(http_request));

	shutdown(fd, EVUTIL_SHUT_WR);
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
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

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
	if (fd >= 0)
		evutil_closesocket(fd);
}

static struct evhttp_connection *delayed_client;

static void
http_large_delay_cb(struct evhttp_request *req, void *arg)
{
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_usec = 500000;

	event_base_once(arg, -1, EV_TIMEOUT, http_delay_reply, req, &tv);
	evhttp_connection_fail_(delayed_client, EVREQ_HTTP_EOF);
}

static void
http_genmethod_cb(struct evhttp_request *req, void *arg)
{
	const char *uri = evhttp_request_get_uri(req);
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(evhttp_request_get_input_headers(req), "Empty") != NULL;
	enum evhttp_cmd_type method;

	if (!strcmp(uri, "/deleteit"))
	    method = EVHTTP_REQ_DELETE;
	else if (!strcmp(uri, "/propfind"))
	    method = EVHTTP_REQ_PROPFIND;
	else if (!strcmp(uri, "/proppatch"))
	    method = EVHTTP_REQ_PROPPATCH;
	else if (!strcmp(uri, "/mkcol"))
	    method = EVHTTP_REQ_MKCOL;
	else if (!strcmp(uri, "/lockit"))
	    method = EVHTTP_REQ_LOCK;
	else if (!strcmp(uri, "/unlockit"))
	    method = EVHTTP_REQ_UNLOCK;
	else if (!strcmp(uri, "/copyit"))
	    method = EVHTTP_REQ_COPY;
	else if (!strcmp(uri, "/moveit"))
	    method = EVHTTP_REQ_MOVE;
	else {
		fprintf(stdout, "FAILED (unexpected path)\n");
		exit(1);
	}
	/* Expecting correct request method */
	if (evhttp_request_get_command(req) != method) {
		fprintf(stdout, "FAILED (delete type)\n");
		exit(1);
	}

	TT_BLATHER(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static void
http_genmethod_test(void *arg, enum evhttp_cmd_type method, const char *name, const char *path)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	struct evbuffer *evb;
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;
	test_ok = 0;

	tt_assert(http);
	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	evhttp_set_allowed_methods(http, method);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);
	evb = bufferevent_get_output(bev);
	evbuffer_add_printf(
	    evb,
	    "%s %s HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n"
	    "body", name, path);

	event_base_dispatch(data->base);

	bufferevent_free(bev);
	evutil_closesocket(fd);
	fd = EVUTIL_INVALID_SOCKET;

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	if (fd >= 0)
		evutil_closesocket(fd);
}

/*
 * HTTP CUSTOM test,  just piggyback on the basic test
 */
static void
http_custom_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	int empty = evhttp_find_header(evhttp_request_get_input_headers(req), "Empty") != NULL;

	/* Expecting a CUSTOM request */
	if (evhttp_request_get_command(req) != EVHTTP_REQ_CUSTOM) {
		fprintf(stdout, "FAILED (custom type)\n");
		exit(1);
	}

	TT_BLATHER(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static void
http_custom_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	evutil_socket_t fd = -1;
	const char *http_request;
	ev_uint16_t port = 0;
	struct evhttp *http;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);
	/* Allow custom */
	evhttp_set_allowed_methods(http, EVHTTP_REQ_CUSTOM);

	tt_assert(http);
	fd = http_connect("127.0.0.1", port);
	tt_int_op(fd, >=, 0);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "CUSTOM /custom HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev);
	evutil_closesocket(fd);
	fd = -1;

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	if (fd >= 0)
		evutil_closesocket(fd);
}

static void
http_delete_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_DELETE, "DELETE", "/deleteit");
}

static void
http_propfind_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_PROPFIND, "PROPFIND", "/propfind");
}

static void
http_proppatch_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_PROPPATCH, "PROPPATCH", "/proppatch");
}

static void
http_mkcol_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_MKCOL, "MKCOL", "/mkcol");
}

static void
http_lock_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_LOCK, "LOCK", "/lockit");
}

static void
http_unlock_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_UNLOCK, "UNLOCK", "/unlockit");
}

static void
http_copy_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_COPY, "COPY", "/copyit");
}

static void
http_move_test(void *arg)
{
	http_genmethod_test(arg, EVHTTP_REQ_MOVE, "MOVE", "/moveit");
}

static void
http_sent_cb(struct evhttp_request *req, void *arg)
{
	ev_uintptr_t val = (ev_uintptr_t)arg;
	struct evbuffer *b;

	if (val != 0xDEADBEEF) {
		fprintf(stdout, "FAILED on_complete_cb argument\n");
		exit(1);
	}

	b = evhttp_request_get_output_buffer(req);
	if (evbuffer_get_length(b) != 0) {
		fprintf(stdout, "FAILED on_complete_cb output buffer not written\n");
		exit(1);
	}

	TT_BLATHER(("%s: called\n", __func__));

	++test_ok;
}

static void
http_on_complete_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();

	evhttp_request_set_on_complete_cb(req, http_sent_cb, (void *)0xDEADBEEF);

	TT_BLATHER(("%s: called\n", __func__));
	evbuffer_add_printf(evb, BASIC_REQUEST_BODY);

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);

	++test_ok;
}

static void
http_on_complete_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	const char *http_request;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;
	test_ok = 0;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request =
	    "GET /oncomplete HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 4);
 end:
	if (fd >= 0)
		evutil_closesocket(fd);
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
	struct bufferevent *bev1, *bev2, *bev3, *bev4;
	evutil_socket_t fd1=-1, fd2=-1, fd3=-1, fd4=-1;
	const char *http_request;
	char *result1=NULL, *result2=NULL, *result3=NULL, *result4=NULL;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;
	test_ok = 0;

	fd1 = http_connect("127.0.0.1", port);
	tt_assert(fd1 != EVUTIL_INVALID_SOCKET);

	/* GET is out; PATCH & CUSTOM are in. */
	evhttp_set_allowed_methods(http, EVHTTP_REQ_PATCH | EVHTTP_REQ_CUSTOM);

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
	tt_assert(fd2 != EVUTIL_INVALID_SOCKET);

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
	tt_assert(fd3 != EVUTIL_INVALID_SOCKET);

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

	fd4 = http_connect("127.0.0.1", port);
	tt_int_op(fd4, >=, 0);

	bev4 = bufferevent_socket_new(data->base, fd4, 0);
	bufferevent_enable(bev4, EV_READ|EV_WRITE);
	bufferevent_setcb(bev4, NULL, NULL,
	    http_allowed_methods_eventcb, &result4);

	http_request =
	    "CUSTOM /test HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev4, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev1);
	bufferevent_free(bev2);
	bufferevent_free(bev3);
	bufferevent_free(bev4);

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

	/* Custom method (and allowed) */
	tt_assert(result4);
	tt_assert(!strncmp(result4, "HTTP/1.1 200 ", strlen("HTTP/1.1 200 ")));

 end:
	if (result1)
		free(result1);
	if (result2)
		free(result2);
	if (result3)
		free(result3);
	if (result4)
		free(result4);
	if (fd1 >= 0)
		evutil_closesocket(fd1);
	if (fd2 >= 0)
		evutil_closesocket(fd2);
	if (fd3 >= 0)
		evutil_closesocket(fd3);
	if (fd4 >= 0)
		evutil_closesocket(fd4);
}

static void http_request_no_action_done(struct evhttp_request *, void *);
static void http_request_done(struct evhttp_request *, void *);
static void http_request_empty_done(struct evhttp_request *, void *);

static void
http_connection_test_(struct basic_test_data *data, int persistent,
	const char *address, struct evdns_base *dnsbase, int ipv6, int family,
	int ssl)
{
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *http;

	int mask = 0;
	if (ipv6)
		mask |= HTTP_BIND_IPV6;
	if (ssl)
		mask |= HTTP_OPENSSL;

	http = http_setup(&port, data->base, mask);

	test_ok = 0;
	if (!http && ipv6) {
		tt_skip();
	}
	tt_assert(http);

	evhttp_set_allowed_methods(http, EVHTTP_REQ_GET | EVHTTP_REQ_CUSTOM);

	if (ssl) {
#ifdef EVENT__HAVE_OPENSSL
		SSL *ssl = SSL_new(get_ssl_ctx());
		struct bufferevent *bev = bufferevent_openssl_socket_new(
			data->base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_DEFER_CALLBACKS);
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

		evcon = evhttp_connection_base_bufferevent_new(data->base, dnsbase, bev, address, port);
#else
		tt_skip();
#endif
	} else {
		evcon = evhttp_connection_base_new(data->base, dnsbase, address, port);
	}
	tt_assert(evcon);
	evhttp_connection_set_family(evcon, family);

	tt_assert(evhttp_connection_get_base(evcon) == data->base);

	exit_base = data->base;

	tt_assert(evhttp_connection_get_server(evcon) == NULL);

	/* add support for CUSTOM method */
	evhttp_connection_set_ext_method_cmp(evcon, ext_method_cb);

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

	/* make a CUSTOM request */
	test_ok = 0;

	req = evhttp_request_new(http_request_empty_done, data->base);

	/* our CUSTOM method doesn't have Body */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_CUSTOM, "/test") == -1) {
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
	http_connection_test_(arg, 0, "127.0.0.1", NULL, 0, AF_UNSPEC, 0);
}
static void
http_persist_connection_test(void *arg)
{
	http_connection_test_(arg, 1, "127.0.0.1", NULL, 0, AF_UNSPEC, 0);
}

static struct regress_dns_server_table search_table[] = {
	{ "localhost", "A", "127.0.0.1", 0, 0 },
	{ NULL, NULL, NULL, 0, 0 }
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
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;
	tt_assert(regress_dnsserver(data->base, &portnum, search_table, NULL));

	dns_base = evdns_base_new(data->base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	test_ok = 0;

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
http_autofree_connection_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req[2] = { NULL };
	struct evhttp *http = http_setup(&port, data->base, 0);
	size_t i;

	test_ok = 0;

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/*
	 * At this point, we want to schedule two request to the HTTP
	 * server using our make request method.
	 */
	req[0] = evhttp_request_new(http_request_empty_done, data->base);
	req[1] = evhttp_request_new(http_request_empty_done, data->base);

	/* Add the information that we care about */
	for (i = 0; i < ARRAY_SIZE(req); ++i) {
		evhttp_add_header(evhttp_request_get_output_headers(req[i]), "Host", "somehost");
		evhttp_add_header(evhttp_request_get_output_headers(req[i]), "Connection", "close");
		evhttp_add_header(evhttp_request_get_output_headers(req[i]), "Empty", "itis");

		if (evhttp_make_request(evcon, req[i], EVHTTP_REQ_GET, "/test") == -1) {
			tt_abort_msg("couldn't make request");
		}
	}

	/*
	 * Tell libevent to free the connection when the request completes
	 *	We then set the evcon pointer to NULL since we don't want to free it
	 *	when this function ends.
	 */
	evhttp_connection_free_on_completion(evcon);
	evcon = NULL;

	for (i = 0; i < ARRAY_SIZE(req); ++i)
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
http_request_never_call(struct evhttp_request *req, void *arg)
{
	fprintf(stdout, "FAILED\n");
	exit(1);
}
static void
http_failed_request_done(struct evhttp_request *req, void *arg)
{
	tt_assert(!req);
end:
	event_base_loopexit(arg, NULL);
}
#ifndef _WIN32
static void
http_timed_out_request_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(evhttp_request_get_response_code(req), !=, HTTP_OK);
end:
	event_base_loopexit(arg, NULL);
}
#endif

static void
http_request_error_cb_with_cancel(enum evhttp_request_error error, void *arg)
{
	if (error != EVREQ_HTTP_REQUEST_CANCEL) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}
	test_ok = 1;

	{
		struct timeval tv;
		evutil_timerclear(&tv);
		tv.tv_sec = 0;
		tv.tv_usec = 500 * 1000;
		event_base_loopexit(exit_base, &tv);
	}
}
static void
http_do_cancel(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_request *req = arg;
	evhttp_cancel_request(req);
	++test_ok;
}
static void
http_no_write(struct evbuffer *buffer, const struct evbuffer_cb_info *info, void *arg)
{
	fprintf(stdout, "FAILED\n");
	exit(1);
}
static void
http_free_evcons(struct evhttp_connection **evcons)
{
	struct evhttp_connection *evcon, **orig = evcons;

	if (!evcons)
		return;

	while ((evcon = *evcons++)) {
		evhttp_connection_free(evcon);
	}
	free(orig);
}
/** fill the backlog to force server drop packages for timeouts */
static struct evhttp_connection **
http_fill_backlog(struct event_base *base, int port)
{
#define BACKLOG_SIZE 256
		struct evhttp_connection **evcon = malloc(sizeof(*evcon) * (BACKLOG_SIZE + 1));
		int i;

		for (i = 0; i < BACKLOG_SIZE; ++i) {
			struct evhttp_request *req;

			evcon[i] = evhttp_connection_base_new(base, NULL, "127.0.0.1", port);
			tt_assert(evcon[i]);
			evhttp_connection_set_timeout(evcon[i], 5);

			req = evhttp_request_new(http_request_never_call, NULL);
			tt_assert(req);
			tt_int_op(evhttp_make_request(evcon[i], req, EVHTTP_REQ_GET, "/delay"), !=, -1);
		}
		evcon[i] = NULL;

		return evcon;
 end:
		fprintf(stderr, "Couldn't fill the backlog");
		return NULL;
}

enum http_cancel_test_type {
	BASIC = 1,
	BY_HOST = 2,
	NO_NS = 4,
	INACTIVE_SERVER = 8,
	SERVER_TIMEOUT = 16,
	NS_TIMEOUT = 32,
};
static struct evhttp_request *
http_cancel_test_bad_request_new(enum http_cancel_test_type type,
	struct event_base *base)
{
#ifndef _WIN32
	if (!(type & NO_NS) && (type & SERVER_TIMEOUT))
		return evhttp_request_new(http_timed_out_request_done, base);
	else
#endif
	if ((type & INACTIVE_SERVER) || (type & NO_NS))
		return evhttp_request_new(http_failed_request_done, base);
	else
		return NULL;
}
static void
http_cancel_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct bufferevent *bufev = NULL;
	struct timeval tv;
	struct evdns_base *dns_base = NULL;
	ev_uint16_t portnum = 0;
	char address[64];
	struct evhttp *inactive_http = NULL;
	struct event_base *inactive_base = NULL;
	struct evhttp_connection **evcons = NULL;
	struct event_base *base_to_fill = data->base;

	enum http_cancel_test_type type =
		(enum http_cancel_test_type)data->setup_data;
	struct evhttp *http = http_setup(&port, data->base, 0);

	if (type & BY_HOST) {
		const char *timeout = (type & NS_TIMEOUT) ? "6" : "3";

		tt_assert(regress_dnsserver(data->base, &portnum, search_table, NULL));

		dns_base = evdns_base_new(data->base, 0/* init name servers */);
		tt_assert(dns_base);

		/** XXX: Hack the port to make timeout after resolving */
		if (type & NO_NS)
			++portnum;

		evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
		evdns_base_nameserver_ip_add(dns_base, address);

		evdns_base_set_option(dns_base, "timeout:", timeout);
		evdns_base_set_option(dns_base, "initial-probe-timeout:", timeout);
		evdns_base_set_option(dns_base, "attempts:", "1");
	}

	exit_base = data->base;

	test_ok = 0;

	if (type & INACTIVE_SERVER) {
		port = 0;
		inactive_base = event_base_new();
		inactive_http = http_setup(&port, inactive_base, 0);

		base_to_fill = inactive_base;
	}

	if (type & SERVER_TIMEOUT)
		evcons = http_fill_backlog(base_to_fill, port);

	evcon = evhttp_connection_base_new(
		data->base, dns_base,
		type & BY_HOST ? "localhost" : "127.0.0.1",
		port);
	if (type & INACTIVE_SERVER)
		evhttp_connection_set_timeout(evcon, 5);
	tt_assert(evcon);

	bufev = evhttp_connection_get_bufferevent(evcon);
	/* Guarantee that we stack in connect() not after waiting EV_READ after
	 * write() */
	if (type & SERVER_TIMEOUT)
		evbuffer_add_cb(bufferevent_get_output(bufev), http_no_write, NULL);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_never_call, NULL);
	evhttp_request_set_error_cb(req, http_request_error_cb_with_cancel);

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

	if (type & NO_NS || type & INACTIVE_SERVER)
		tt_int_op(test_ok, ==, 2); /** no servers responses */
	else
		tt_int_op(test_ok, ==, 3);

	/* try to make another request over the same connection */
	test_ok = 0;

	http_free_evcons(evcons);
	if (type & SERVER_TIMEOUT)
		evcons = http_fill_backlog(base_to_fill, port);

	req = http_cancel_test_bad_request_new(type, data->base);
	if (!req)
		req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_base_dispatch(data->base);

	/* make another request: request empty reply */
	test_ok = 0;

	http_free_evcons(evcons);
	if (type & SERVER_TIMEOUT)
		evcons = http_fill_backlog(base_to_fill, port);

	req = http_cancel_test_bad_request_new(type, data->base);
	if (!req)
		req = evhttp_request_new(http_request_empty_done, data->base);

	/* Add the information that we care about */
	evhttp_add_header(evhttp_request_get_output_headers(req), "Empty", "itis");

	/* We give ownership of the request to the connection */
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test"),
		  !=, -1);

	event_base_dispatch(data->base);

 end:
	http_free_evcons(evcons);
	if (bufev)
		evbuffer_remove_cb(bufferevent_get_output(bufev), http_no_write, NULL);
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
	if (dns_base)
		evdns_base_free(dns_base, 0);
	regress_clean_dnsserver();
	if (inactive_http)
		evhttp_free(inactive_http);
	if (inactive_base)
		event_base_free(inactive_base);
}

static void
http_request_no_action_done(struct evhttp_request *req, void *arg)
{
	EVUTIL_ASSERT(exit_base);
	event_base_loopexit(exit_base, NULL);
}

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	const char *what = arg;

	if (!req) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

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
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;

	/* virtual host */
	second = evhttp_new(NULL);
	evhttp_set_cb(second, "/funnybunny", http_basic_cb, http);
	third = evhttp_new(NULL);
	evhttp_set_cb(third, "/blackcoffee", http_basic_cb, http);

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
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

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
	if (!req) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

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
	TT_BLATHER(("%s: called\n", __func__));
	evbuffer_add_printf(evb, "DISPATCHER_TEST");

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);
}

static void
http_dispatcher_test_done(struct evhttp_request *req, void *arg)
{
	struct event_base *base = arg;
	const char *what = "DISPATCHER_TEST";

	if (!req) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

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
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

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
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

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
	TT_BLATHER(("%s: called\n", __func__));

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
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

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
	TT_BLATHER(("%s: called\n", __func__));

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
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	const char *http_request;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, http_failure_readcb, http_writecb,
	    http_errorcb, data->base);

	http_request = "illegal request\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	bufferevent_free(bev);

	evhttp_free(http);

	tt_int_op(test_ok, ==, 2);
 end:
	if (fd >= 0)
		evutil_closesocket(fd);
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
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

	/* .1 second timeout */
	evhttp_set_timeout_tv(http, &sec_tenth);

	evcon = evhttp_connection_base_new(data->base, NULL,
	    "127.0.0.1", port);
	tt_assert(evcon);
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
http_parse_query_str_test(void *ptr)
{
	struct evkeyvalq headers;
	int r;

	TAILQ_INIT(&headers);

	r = evhttp_parse_query_str("http://www.test.com/?q=test", &headers);
	tt_assert(evhttp_find_header(&headers, "q") == NULL);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query_str("q=test", &headers);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

end:
	evhttp_clear_headers(&headers);
}
static void
http_parse_query_str_flags_test(void *ptr)
{
	struct evkeyvalq headers;
	int r;

	TAILQ_INIT(&headers);

	/** ~EVHTTP_URI_QUERY_LAST_VAL */
	r = evhttp_parse_query_str_flags("q=test&q=test2", &headers, 0);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	/** EVHTTP_URI_QUERY_LAST_VAL */
	r = evhttp_parse_query_str_flags("q=test&q=test2", &headers, EVHTTP_URI_QUERY_LAST_VAL);
	tt_want(validate_header(&headers, "q", "test2") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	/** ~EVHTTP_URI_QUERY_NONCONFORMANT */
	r = evhttp_parse_query_str_flags("q=test&q2", &headers, 0);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query_str_flags("q=test&&q2=test2", &headers, 0);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query_str_flags("q=test&=1&q2=test2", &headers, 0);
	tt_int_op(r, ==, -1);
	evhttp_clear_headers(&headers);

	/** EVHTTP_URI_QUERY_NONCONFORMANT */
	r = evhttp_parse_query_str_flags("q=test&q2", &headers, EVHTTP_URI_QUERY_NONCONFORMANT);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "q2", "") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query_str_flags("q=test&&q2=test2", &headers, EVHTTP_URI_QUERY_NONCONFORMANT);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "q2", "test2") == 0);
	tt_int_op(r, ==, 0);
	evhttp_clear_headers(&headers);

	r = evhttp_parse_query_str_flags("q=test&=1&q2=test2", &headers, EVHTTP_URI_QUERY_NONCONFORMANT);
	tt_want(validate_header(&headers, "q", "test") == 0);
	tt_want(validate_header(&headers, "q2", "test2") == 0);
	tt_int_op(r, ==, 0);
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
#define URI_PARSE_FLAGS(uri, flags) \
	evhttp_uri_parse_with_flags((uri), flags)
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

	// EVHTTP_URI_HOST_STRIP_BRACKETS
	uri = URI_PARSE_FLAGS("ftp://[ff00::127.0.0.1]/?q=test", EVHTTP_URI_HOST_STRIP_BRACKETS);
	tt_want(strcmp(evhttp_uri_get_scheme(uri), "ftp") == 0);
	tt_want(strcmp(evhttp_uri_get_host(uri), "ff00::127.0.0.1") == 0);
	tt_want(strcmp(evhttp_uri_get_path(uri), "/") == 0);
	tt_want(strcmp(evhttp_uri_get_query(uri), "q=test") == 0);
	tt_want(evhttp_uri_get_userinfo(uri) == NULL);
	tt_want(evhttp_uri_get_port(uri) == -1);
	tt_want(evhttp_uri_get_fragment(uri) == NULL);
	TT_URI("ftp://[ff00::127.0.0.1]/?q=test");

	tt_want(0 == evhttp_uri_set_host(uri, "foo"));
	tt_want(strcmp(evhttp_uri_get_host(uri), "foo") == 0);
	TT_URI("ftp://foo/?q=test");

	tt_want(0 == evhttp_uri_set_host(uri, "[ff00::127.0.0.1]"));
	tt_want(strcmp(evhttp_uri_get_host(uri), "ff00::127.0.0.1") == 0);
	TT_URI("ftp://[ff00::127.0.0.1]/?q=test");

	evhttp_uri_free(uri);

#undef URI_PARSE_FLAGS
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
	struct evhttp *http;
	
	test_ok = 0;
	base = event_base_new();
	tt_assert(base);
	http = http_setup(&port, base, 0);

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

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
	/** For ssl */
	if (what & BEV_EVENT_CONNECTED)
		return;

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
		shutdown(fd, EVUTIL_SHUT_WR);
	}
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_incomplete_test_(struct basic_test_data *data, int use_timeout, int ssl)
{
	struct bufferevent *bev;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;
	struct evhttp *http = http_setup(&port, data->base, ssl);

	exit_base = data->base;
	test_ok = 0;

	evhttp_set_timeout(http, 1);

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = create_bev(data->base, fd, ssl, 0);
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
		fd = EVUTIL_INVALID_SOCKET;
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
	if (fd >= 0)
		evutil_closesocket(fd);
}
static void http_incomplete_test(void *arg)
{ http_incomplete_test_(arg, 0, 0); }
static void http_incomplete_timeout_test(void *arg)
{ http_incomplete_test_(arg, 1, 0); }


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
	struct evhttp_request *req = NULL;

	/** SSL */
	if (what & BEV_EVENT_CONNECTED)
		return;

	if (!test_ok)
		goto out;

	test_ok = -1;

	if ((what & BEV_EVENT_EOF) != 0) {
		const char *header;
		enum message_read_status done;
		req = evhttp_request_new(NULL, NULL);

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
	}

out:
	if (req)
		evhttp_request_free(req);

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
http_send_chunk_test_read_cb(struct bufferevent *bev, void *arg)
{
	TT_BLATHER(("%s: called\n", __func__));
}
/* sends 3 chunks */
static void
http_send_chunk_test_write_cb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *output = bufferevent_get_output(bev);

	TT_BLATHER(("%s: called, test_ok=%i\n", __func__, test_ok));

	if (test_ok < 3) {
		size_t len = strlen(BASIC_REQUEST_BODY) + 1;
		evbuffer_add_printf(output, "%x\r\n", (unsigned)len);
		evbuffer_add(output, BASIC_REQUEST_BODY, strlen(BASIC_REQUEST_BODY));
		/* to allow using evbuffer_readln() for simplicity */
		evbuffer_add(output, "\n", 1);
		evbuffer_add(output, "\r\n", 2);
	} else if (test_ok == 3) {
		/* last chunk */
		evbuffer_add(output, "0\r\n\r\n", 5);
	} else {
		/* stop */
		bufferevent_disable(bev, EV_WRITE);
		bufferevent_enable(bev, EV_READ);
	}

	test_ok++;
}
static void
http_send_chunk_test_error_cb(struct bufferevent *bev, short what, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	char *line;

	TT_BLATHER(("%s: called\n", __func__));

	test_ok = 0;

	/* suboptimal */
	while (evbuffer_get_length(input)) {
		size_t n_read_out = 0;
		line = evbuffer_readln(input, &n_read_out, EVBUFFER_EOL_LF);
		if (!line)
			break;
		/* don't bother about parsing http request,
		 * just count number of BASIC_REQUEST_BODY */
		if (strcmp(line, BASIC_REQUEST_BODY) == 0) {
			++test_ok;
		}
		free(line);
	}

	event_base_loopexit(exit_base, NULL);
}
static void
http_send_chunk_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0 /* ssl */);

	exit_base = data->base;
	test_ok = 0;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	bev = create_bev(data->base, fd, 0 /* ssl */, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev,
	    http_send_chunk_test_read_cb,
	    http_send_chunk_test_write_cb,
	    http_send_chunk_test_error_cb,
	    data->base);

	http_request =
	    "POST /chunked_input HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Transfer-Encoding: chunked\r\n"
	    "Connection: close\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));

	event_base_dispatch(data->base);

	/**
	 * http_send_chunk_test_error_cb() find BASIC_REQUEST_BODY 3 times
	 */
	tt_int_op(test_ok, ==, 3);

 end:
	if (bev)
		bufferevent_free(bev);
	if (http)
		evhttp_free(http);
}
static void
http_chunk_out_test_impl(void *arg, int ssl)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	const char *http_request;
	ev_uint16_t port = 0;
	struct timeval tv_start, tv_end;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	int i;
	struct evhttp *http = http_setup(&port, data->base, ssl);

	exit_base = data->base;
	test_ok = 0;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
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
	bev = NULL;

	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	tt_int_op(tv_end.tv_sec, <, 1);

	tt_int_op(test_ok, ==, 2);

	/* now try again with the regular connection object */
	bev = create_bev(data->base, -1, ssl, BEV_OPT_CLOSE_ON_FREE);
	evcon = evhttp_connection_base_bufferevent_new(
		data->base, NULL, bev, "127.0.0.1", port);
	tt_assert(evcon);

	/* make two requests to check the keepalive behavior */
	for (i = 0; i < 2; i++) {
		test_ok = 0;
		req = evhttp_request_new(http_chunked_request_done, data->base);

		/* Add the information that we care about */
		evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");

		/* We give ownership of the request to the connection */
		if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/chunked") == -1) {
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
static void http_chunk_out_test(void *arg)
{ http_chunk_out_test_impl(arg, 0); }

static void
http_stream_out_test_impl(void *arg, int ssl)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct bufferevent *bev;
	struct evhttp *http = http_setup(&port, data->base, ssl);

	test_ok = 0;
	exit_base = data->base;

	bev = create_bev(data->base, -1, ssl, 0);
	evcon = evhttp_connection_base_bufferevent_new(
		data->base, NULL, bev, "127.0.0.1", port);
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
static void http_stream_out_test(void *arg)
{ http_stream_out_test_impl(arg, 0); }

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
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;

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
	struct evhttp *http = http_setup(&port, data->base, 0);

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
http_connection_fail_test_impl(void *arg, int ssl)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct bufferevent *bev;
	struct evhttp *http = http_setup(&port, data->base, ssl);

	exit_base = data->base;
	test_ok = 0;

	/* auto detect a port */
	evhttp_free(http);

	bev = create_bev(data->base, -1, ssl, 0);
	/* Pick an unroutable address. This administratively scoped multicast
	 * address should do when working with TCP. */
	evcon = evhttp_connection_base_bufferevent_new(
		data->base, NULL, bev, "239.10.20.30", 80);
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
static void http_connection_fail_test(void *arg)
{ http_connection_fail_test_impl(arg, 0); }

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

struct http_server
{
	ev_uint16_t port;
	int ssl;
	struct evhttp *http;
};
static struct event_base *http_make_web_server_base=NULL;
static void
http_make_web_server(evutil_socket_t fd, short what, void *arg)
{
	struct http_server *hs = (struct http_server *)arg;
	hs->http = http_setup(&hs->port, http_make_web_server_base, hs->ssl);
}

static void
http_simple_test_impl(void *arg, int ssl, int dirty, const char *uri)
{
	struct basic_test_data *data = arg;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct bufferevent *bev;
	struct http_server hs = { 0, ssl, NULL, };
	struct evhttp *http = http_setup(&hs.port, data->base, ssl);

	exit_base = data->base;
	test_ok = 0;

	bev = create_bev(data->base, -1, ssl, 0);
#ifdef EVENT__HAVE_OPENSSL
	bufferevent_openssl_set_allow_dirty_shutdown(bev, dirty);
#endif
#ifdef EVENT__HAVE_MBEDTLS
	bufferevent_mbedtls_set_allow_dirty_shutdown(bev, dirty);
#endif

	evcon = evhttp_connection_base_bufferevent_new(
		data->base, NULL, bev, "127.0.0.1", hs.port);
	tt_assert(evcon);
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	req = evhttp_request_new(http_request_done, (void*) BASIC_REQUEST_BODY);
	tt_assert(req);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri) == -1)
		tt_abort_msg("Couldn't make request");

	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 1);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}
static void http_simple_test(void *arg)
{ http_simple_test_impl(arg, 0, 0, "/test"); }
static void http_simple_nonconformant_test(void *arg)
{ http_simple_test_impl(arg, 0, 0, "/test nonconformant"); }

static void
http_connection_retry_test_basic(void *arg, const char *addr, struct evdns_base *dns_base, int ssl)
{
	struct basic_test_data *data = arg;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv, tv_start, tv_end;
	struct bufferevent *bev;
	struct http_server hs = { 0, ssl, NULL, };
	struct evhttp *http = http_setup(&hs.port, data->base, ssl);

	exit_base = data->base;
	test_ok = 0;

	/* auto detect a port */
	evhttp_free(http);

	bev = create_bev(data->base, -1, ssl, 0);
	evcon = evhttp_connection_base_bufferevent_new(data->base, dns_base, bev, addr, hs.port);
	tt_assert(evcon);
	if (dns_base)
		tt_assert(!evhttp_connection_set_flags(evcon, EVHTTP_CON_REUSE_CONNECTED_ADDR));

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
	/** Shutdown dns server, to test conn_address reusing */
	if (dns_base)
		regress_clean_dnsserver();

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
	event_base_once(data->base, -1, EV_TIMEOUT, http_make_web_server, &hs, &tv);

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
		evhttp_free(hs.http);
}

static void
http_connection_retry_conn_address_test_impl(void *arg, int ssl)
{
	struct basic_test_data *data = arg;
	ev_uint16_t portnum = 0;
	struct evdns_base *dns_base = NULL;
	char address[64];

	tt_assert(regress_dnsserver(data->base, &portnum, search_table, NULL));
	dns_base = evdns_base_new(data->base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	http_connection_retry_test_basic(arg, "localhost", dns_base, ssl);

 end:
	if (dns_base)
		evdns_base_free(dns_base, 0);
	/** dnsserver will be cleaned in http_connection_retry_test_basic() */
}
static void http_connection_retry_conn_address_test(void *arg)
{ http_connection_retry_conn_address_test_impl(arg, 0); }

static void
http_connection_retry_test_impl(void *arg, int ssl)
{
	http_connection_retry_test_basic(arg, "127.0.0.1", NULL, ssl);
}
static void
http_connection_retry_test(void *arg)
{ http_connection_retry_test_impl(arg, 0); }

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
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, http), ==, 0);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, http), ==, -1);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, 0);
	tt_int_op(evhttp_del_cb(http, "/test"), ==, -1);
	tt_int_op(evhttp_set_cb(http, "/test", http_basic_cb, http), ==, 0);

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
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	const char *http_start_request;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	exit_base = data->base;
	test_ok = 0;

	tt_ptr_op(http, !=, NULL);

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	tt_ptr_op(bev, !=, NULL);
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
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

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
http_expectation_failed_done(struct evhttp_request *req, void *arg)
{
	tt_assert(req);
	tt_int_op(evhttp_request_get_response_code(req), ==, HTTP_EXPECTATIONFAILED);
end:
	event_base_loopexit(arg, NULL);
}

static void
http_data_length_constraints_test_impl(void *arg, int read_on_write_error)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	char *long_str = NULL;
	const size_t continue_size = 1<<20;
	const size_t size = (1<<20) * 3;
	void (*cb)(struct evhttp_request *, void *);
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;
	cb = http_failed_request_done;
	if (read_on_write_error)
		cb = http_data_length_constraints_test_done;

	tt_assert(continue_size < size);

	long_str = malloc(size);
	memset(long_str, 'a', size);
	long_str[size - 1] = '\0';

	TT_BLATHER(("Creating connection to :%i", port));
	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	if (read_on_write_error)
		tt_assert(!evhttp_connection_set_flags(evcon, EVHTTP_CON_READ_ON_WRITE_ERROR));

	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	evhttp_set_max_headers_size(http, size - 1);
	TT_BLATHER(("Set max header size %zu", size - 1));

	req = evhttp_request_new(http_data_length_constraints_test_done, data->base);
	tt_assert(req);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Longheader", long_str);
	TT_BLATHER(("GET /?arg=val"));
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	req = evhttp_request_new(http_data_length_constraints_test_done, data->base);
	tt_assert(req);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	/* GET /?arg=verylongvalue HTTP/1.1 */
	TT_BLATHER(("GET %s", long_str));
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, long_str) == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	evhttp_set_max_body_size(http, size - 2);
	TT_BLATHER(("Set body header size %zu", size - 2));

	if (read_on_write_error)
		cb = http_large_entity_test_done;
	req = evhttp_request_new(cb, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	TT_BLATHER(("POST /"));
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	req = evhttp_request_new(http_large_entity_test_done, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Expect", "100-continue");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	TT_BLATHER(("POST / (Expect: 100-continue, http_large_entity_test_done)"));
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	long_str[continue_size] = '\0';

	req = evhttp_request_new(http_dispatcher_test_done, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Expect", "100-continue");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	TT_BLATHER(("POST / (Expect: 100-continue, http_dispatcher_test_done)"));
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	event_base_dispatch(data->base);

	if (read_on_write_error)
		cb = http_expectation_failed_done;
	req = evhttp_request_new(cb, data->base);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Expect", "101-continue");
	evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", long_str);
	TT_BLATHER(("POST / (Expect: 101-continue)"));
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
	if (long_str)
		free(long_str);
}
static void http_data_length_constraints_test(void *arg)
{ http_data_length_constraints_test_impl(arg, 0); }
static void http_read_on_write_error_test(void *arg)
{ http_data_length_constraints_test_impl(arg, 1); }

static void
http_lingering_close_test_impl(void *arg, int lingering)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	char *long_str = NULL;
	size_t size = (1<<20) * 3;
	void (*cb)(struct evhttp_request *, void *);
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

	if (lingering)
		tt_assert(!evhttp_set_flags(http, EVHTTP_SERVER_LINGERING_CLOSE));
	evhttp_set_max_body_size(http, size / 2);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	long_str = malloc(size);
	memset(long_str, 'a', size);
	long_str[size - 1] = '\0';

	if (lingering)
		cb = http_large_entity_test_done;
	else
		cb = http_failed_request_done;
	req = evhttp_request_new(cb, data->base);
	tt_assert(req);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
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
	if (long_str)
		free(long_str);
}
static void http_non_lingering_close_test(void *arg)
{ http_lingering_close_test_impl(arg, 0); }
static void http_lingering_close_test(void *arg)
{ http_lingering_close_test_impl(arg, 1); }

/*
 * Testing client reset of server chunked connections
 */

struct terminate_state {
	struct event_base *base;
	struct evhttp_request *req;
	struct bufferevent *bev;
	evutil_socket_t fd;
	int gotclosecb: 1;
	int oneshot: 1;
};

static void
terminate_chunked_trickle_cb(evutil_socket_t fd, short events, void *arg)
{
	struct terminate_state *state = arg;
	struct evbuffer *evb;

	if (!state->req) {
		return;
	}

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

	if (!state->oneshot) {
		struct timeval tv;
		tv.tv_sec = 0;
		tv.tv_usec = 3000;
		EVUTIL_ASSERT(state);
		EVUTIL_ASSERT(state->base);
		event_base_once(state->base, -1, EV_TIMEOUT, terminate_chunked_trickle_cb, arg, &tv);
	}
}

static void
terminate_chunked_close_cb(struct evhttp_connection *evcon, void *arg)
{
	struct terminate_state *state = arg;
	state->gotclosecb = 1;

	/** TODO: though we can do this unconditionally */
	if (state->oneshot) {
		evhttp_request_free(state->req);
		state->req = NULL;
		event_base_loopexit(state->base,NULL);
	}
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
http_terminate_chunked_test_impl(void *arg, int oneshot)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	struct timeval tv;
	const char *http_request;
	ev_uint16_t port = 0;
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	struct terminate_state terminate_state;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

	evhttp_del_cb(http, "/test");
	tt_assert(evhttp_set_cb(http, "/test",
		terminate_chunked_cb, &terminate_state) == 0);

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = bufferevent_socket_new(data->base, fd, 0);
	bufferevent_setcb(bev, terminate_readcb, http_writecb,
	    http_errorcb, data->base);

	memset(&terminate_state, 0, sizeof(terminate_state));
	terminate_state.base = data->base;
	terminate_state.fd = fd;
	terminate_state.bev = bev;
	terminate_state.gotclosecb = 0;
	terminate_state.oneshot = oneshot;

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
static void
http_terminate_chunked_test(void *arg)
{
	http_terminate_chunked_test_impl(arg, 0);
}
static void
http_terminate_chunked_oneshot_test(void *arg)
{
	http_terminate_chunked_test_impl(arg, 1);
}

static struct regress_dns_server_table ipv6_search_table[] = {
	{ "localhost", "AAAA", "::1", 0, 0 },
	{ NULL, NULL, NULL, 0, 0 }
};

static void
http_ipv6_for_domain_test_impl(void *arg, int family)
{
	struct basic_test_data *data = arg;
	struct evdns_base *dns_base = NULL;
	ev_uint16_t portnum = 0;
	char address[64];

	tt_assert(regress_dnsserver(data->base, &portnum, ipv6_search_table, NULL));

	dns_base = evdns_base_new(data->base, 0/* init name servers */);
	tt_assert(dns_base);

	/* Add ourself as the only nameserver, and make sure we really are
	 * the only nameserver. */
	evutil_snprintf(address, sizeof(address), "127.0.0.1:%d", portnum);
	evdns_base_nameserver_ip_add(dns_base, address);

	http_connection_test_(arg, 0 /* not persistent */, "localhost", dns_base,
		1 /* ipv6 */, family, 0);

 end:
	if (dns_base)
		evdns_base_free(dns_base, 0);
	regress_clean_dnsserver();
}
static void
http_ipv6_for_domain_test(void *arg)
{
	http_ipv6_for_domain_test_impl(arg, AF_UNSPEC);
}

static void
http_request_get_addr_on_close(struct evhttp_connection *evcon, void *arg)
{
	const struct sockaddr *storage;
	char addrbuf[128];
	char local[] = "127.0.0.1:";

	test_ok = 0;
	tt_assert(evcon);

	storage = evhttp_connection_get_addr(evcon);
	tt_assert(storage);

	evutil_format_sockaddr_port_((struct sockaddr *)storage, addrbuf, sizeof(addrbuf));
	tt_assert(!strncmp(addrbuf, local, sizeof(local) - 1));

	test_ok = 1;
	return;

end:
	test_ok = 0;
}

static void
http_get_addr_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;
	exit_base = data->base;

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);
	evhttp_connection_set_closecb(evcon, http_request_get_addr_on_close, arg);

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, (void *)BASIC_REQUEST_BODY);

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}

	event_base_dispatch(data->base);

	http_request_get_addr_on_close(evcon, NULL);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void
http_set_family_test(void *arg)
{
	http_connection_test_(arg, 0, "127.0.0.1", NULL, 0, AF_UNSPEC, 0);
}
static void
http_set_family_ipv4_test(void *arg)
{
	http_connection_test_(arg, 0, "127.0.0.1", NULL, 0, AF_INET, 0);
}
static void
http_set_family_ipv6_test(void *arg)
{
	http_ipv6_for_domain_test_impl(arg, AF_INET6);
}

static void
http_write_during_read(evutil_socket_t fd, short what, void *arg)
{
	struct bufferevent *bev = arg;
	struct timeval tv;

	bufferevent_write(bev, "foobar", strlen("foobar"));

	evutil_timerclear(&tv);
	tv.tv_sec = 1;
	event_base_loopexit(exit_base, &tv);
}
static void
http_write_during_read_test_impl(void *arg, int ssl)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct bufferevent *bev = NULL;
	struct timeval tv;
	evutil_socket_t fd;
	const char *http_request;
	struct evhttp *http = http_setup(&port, data->base, ssl);

	test_ok = 0;
	exit_base = data->base;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);
	bev = create_bev(data->base, fd, ssl, 0);
	bufferevent_setcb(bev, NULL, NULL, NULL, data->base);
	bufferevent_disable(bev, EV_READ);

	http_request =
	    "GET /large HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));
	evutil_timerclear(&tv);
	tv.tv_usec = 10000;
	event_base_once(data->base, -1, EV_TIMEOUT, http_write_during_read, bev, &tv);

	event_base_dispatch(data->base);

end:
	if (bev)
		bufferevent_free(bev);
	if (http)
		evhttp_free(http);
}
static void http_write_during_read_test(void *arg)
{ http_write_during_read_test_impl(arg, 0); }

static void
http_request_own_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;
	exit_base = data->base;

	evhttp_free(http);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	req = evhttp_request_new(http_request_no_action_done, NULL);

	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		tt_abort_msg("Couldn't make request");
	}
	evhttp_request_own(req);

	event_base_dispatch(data->base);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (req)
		evhttp_request_free(req);

	test_ok = 1;
}

static void http_run_bev_request(struct event_base *base, int port,
	const char *fmt, ...)
{
	struct bufferevent *bev = NULL;
	va_list ap;
	evutil_socket_t fd;
	struct evbuffer *out;

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	/* Stupid thing to send a request */
	bev = create_bev(base, fd, 0, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb,
	    http_errorcb, base);
	out = bufferevent_get_output(bev);

	va_start(ap, fmt);
	evbuffer_add_vprintf(out, fmt, ap);
	va_end(ap);

	event_base_dispatch(base);

end:
	if (bev)
		bufferevent_free(bev);
}
static void
http_request_extra_body_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	ev_uint16_t port = 0;
	int i;
	struct evhttp *http =
		http_setup_gencb(&port, data->base, 0, http_timeout_cb, NULL);
	struct evbuffer *body = NULL;

	exit_base = data->base;
	test_ok = 0;

	body = evbuffer_new();
	for (i = 0; i < 10000; ++i)
		evbuffer_add_printf(body, "this is the body that HEAD should not have");

	http_run_bev_request(data->base, port,
		"HEAD /timeout HTTP/1.1\r\n"
		"Host: somehost\r\n"
		"Connection: close\r\n"
		"Content-Length: %i\r\n"
		"\r\n%s",
		(int)evbuffer_get_length(body),
		evbuffer_pullup(body, -1)
	);
	tt_assert(test_ok == -2);

	http_run_bev_request(data->base, port,
		"HEAD /__gencb__ HTTP/1.1\r\n"
		"Host: somehost\r\n"
		"Connection: close\r\n"
		"Content-Length: %i\r\n"
		"\r\n%s",
		(int)evbuffer_get_length(body),
		evbuffer_pullup(body, -1)
	);
	tt_assert(test_ok == -2);

 end:
	evhttp_free(http);
	if (bev)
		bufferevent_free(bev);
	if (body)
		evbuffer_free(body);
}

struct http_newreqcb_test_state
{
	int connections_started;
	int connections_noticed;
	int connections_throttled;
	int connections_good;
	int connections_error;
	int connections_done;
};

static void
http_newreqcb_test_state_check(struct http_newreqcb_test_state* state)
{
	tt_int_op(state->connections_started, >=, 0);
	tt_int_op(state->connections_started, >=, state->connections_noticed);
	tt_int_op(state->connections_throttled, >=, state->connections_error);

	tt_int_op(state->connections_done, <=, state->connections_started);
	if (state->connections_good + state->connections_error == state->connections_started) {
		tt_int_op(state->connections_throttled, ==, state->connections_error);
		tt_int_op(state->connections_good + state->connections_error, ==, state->connections_done);
		event_base_loopexit(exit_base, NULL);
	}

	return;
end:
	tt_fail();
	exit(17);
}

static void
http_request_done_newreqcb(struct evhttp_request *req, void *arg)
{
	struct http_newreqcb_test_state* state = arg;
	if (req && evhttp_request_get_response_code(req) == HTTP_OK) {
		++state->connections_good;
		evhttp_request_set_error_cb(req, NULL);
	}
	++state->connections_done;

	http_newreqcb_test_state_check(state);
}

static void
http_request_error_newreqcb(enum evhttp_request_error err, void *arg)
{
	struct http_newreqcb_test_state* state = arg;
	++state->connections_error;

	http_newreqcb_test_state_check(state);
}

static int
http_newreqcb(struct evhttp_request* req, void *arg)
{
	struct http_newreqcb_test_state* state = arg;
	++state->connections_noticed;
	http_newreqcb_test_state_check(state);
	if (1 == state->connections_noticed % 7) {
		state->connections_throttled++;
		return -1;
	}
	return 0;
}


static void
http_newreqcb_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);
	struct evhttp_connection *evcons[100];
	struct http_newreqcb_test_state newreqcb_test_state;
	unsigned n;

	exit_base = data->base;
	test_ok = 0;

	memset(&newreqcb_test_state, 0, sizeof(newreqcb_test_state));
	memset(evcons, 0, sizeof(evcons));

	evhttp_set_newreqcb(http, http_newreqcb, &newreqcb_test_state);

	for (n = 0; n < sizeof(evcons)/sizeof(evcons[0]); ++n) {
		struct evhttp_connection* evcon = NULL;
		struct evhttp_request *req = NULL;
		evcons[n] = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
		evcon = evcons[n];
		evhttp_connection_set_retries(evcon, 0);

		tt_assert(evcon);

		req = evhttp_request_new(http_request_done_newreqcb, &newreqcb_test_state);
		evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");
		evhttp_request_set_error_cb(req, http_request_error_newreqcb);

		/* We give ownership of the request to the connection */
		if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
			tt_abort_msg("Couldn't make request");
		}

		++newreqcb_test_state.connections_started;
		http_newreqcb_test_state_check(&newreqcb_test_state);
	}

	event_base_dispatch(data->base);

	http_newreqcb_test_state_check(&newreqcb_test_state);
	tt_int_op(newreqcb_test_state.connections_throttled, >, 0);

 end:
	evhttp_free(http);

	for (n = 0; n < sizeof(evcons)/sizeof(evcons[0]); ++n) {
		if (evcons[n])
			evhttp_connection_free(evcons[n]);

	}

}

static void
http_timeout_read_client_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;
	exit_base = data->base;

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	evhttp_connection_set_connect_timeout_tv(evcon, &tv);
	evhttp_connection_set_write_timeout_tv(evcon, &tv);
	tv.tv_usec = 500000;
	evhttp_connection_set_read_timeout_tv(evcon, &tv);

	req = evhttp_request_new(http_request_done, (void*)"");
	tt_assert(req);
	evhttp_add_header(evhttp_request_get_output_headers(req), "Host", "somehost");
	tt_int_op(evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/delay"), ==, 0);
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 1);

 end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

/*
 * Error callback tests
 */

#define ERRCBFLAG_GENCB  (0x01)
#define ERRCBFLAG_ERRCB  (0x02)
#define ERRCBFLAG_BOTHCB (ERRCBFLAG_GENCB | ERRCBFLAG_ERRCB)

struct error_callback_test {
	unsigned char flags;
	enum evhttp_cmd_type type;
	int response_code;
	int length;
} error_callback_tests[] = {
	{0                , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 152} , /* 0 */
	{0                , EVHTTP_REQ_POST , HTTP_NOTIMPLEMENTED , 101} , /* 1 */
	{ERRCBFLAG_GENCB  , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 89}  , /* 2 */
	{ERRCBFLAG_GENCB  , EVHTTP_REQ_POST , HTTP_NOTIMPLEMENTED , 101} , /* 3 */
	{ERRCBFLAG_ERRCB  , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 3}   , /* 4 */
	{ERRCBFLAG_ERRCB  , EVHTTP_REQ_POST , HTTP_NOTIMPLEMENTED , 101} , /* 5 */
	{ERRCBFLAG_BOTHCB , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 3}   , /* 6 */
	{ERRCBFLAG_BOTHCB , EVHTTP_REQ_POST , HTTP_NOTIMPLEMENTED , 3}   , /* 7 */
	{ERRCBFLAG_ERRCB  , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 0}   , /* 8 */
	{ERRCBFLAG_ERRCB  , EVHTTP_REQ_GET  , HTTP_NOTFOUND       , 152} , /* 9 */
};

struct error_callback_state
{
	struct basic_test_data *data;
	unsigned test_index;
	struct error_callback_test *test;
	int test_failed;
};

static void
http_error_callback_gencb(struct evhttp_request *req, void *arg)
{
	struct error_callback_state *state_info = arg;

	switch (state_info->test_index) {
	case 2:
	case 6:
		evhttp_send_error(req, HTTP_NOTFOUND, NULL);
		break;
	default:
		evhttp_send_error(req, HTTP_INTERNAL, NULL);
		break;
	}
}

static int
http_error_callback_errorcb(struct evhttp_request *req, struct evbuffer *buf,
    int error, const char *reason, void *arg)
{
	struct error_callback_state *state_info = arg;
	int return_code = -1;

	switch (state_info->test_index) {
	case 4:
	case 6:
	case 7:
		evbuffer_add_printf(buf, "%d", error);
		return_code = 0;
		break;
	case 8: /* Add nothing to buffer and then return 0 to trigger default */
		return_code = 0;
		break;
	case 9: /* Add text to buffer but then return -1 to trigger default */
		evbuffer_add_printf(buf, "%d", error);
		break;
	default:
		/* Do nothing */
		break;
	}

	return return_code;
}

static void
http_error_callback_test_done(struct evhttp_request *req, void *arg)
{
	struct evkeyvalq *headers;
	const char *header_text;
	struct error_callback_state *state_info = arg;
	struct error_callback_test *test_info;

	test_info = state_info->test;

	tt_assert(req);
	tt_assert_op_type(evhttp_request_get_command(req), ==,
	    test_info->type, enum evhttp_cmd_type, "%d");
	tt_int_op(evhttp_request_get_response_code(req), ==,
	    test_info->response_code);

	headers = evhttp_request_get_input_headers(req);
	tt_assert(headers);
	header_text  = evhttp_find_header(headers, "Content-Type");
	tt_assert_msg(header_text, "Missing Content-Type");
	tt_str_op(header_text, ==, "text/html");
	tt_int_op(evbuffer_get_length(evhttp_request_get_input_buffer(req)),
	    ==, test_info->length);

	event_base_loopexit(state_info->data->base, NULL);
	return;

end:
	state_info->test_failed = 1;
	event_base_loopexit(state_info->data->base, NULL);
}

static void
http_error_callback_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct evhttp *http = NULL;
	ev_uint16_t port = 0;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct error_callback_state state_info;

	test_ok = 0;

	http = http_setup(&port, data->base, 0);
	evhttp_set_allowed_methods(http,
	    EVHTTP_REQ_GET |
	    EVHTTP_REQ_HEAD |
	    EVHTTP_REQ_PUT |
	    EVHTTP_REQ_DELETE);

	evcon = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
	tt_assert(evcon);

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/* Initialise the state info */
	state_info.data 	= data;
	state_info.test		= error_callback_tests;
	state_info.test_failed	= 0;

	/* Perform all the tests */
	for (state_info.test_index = 0;
	     (state_info.test_index < ARRAY_SIZE(error_callback_tests)) &&
	     (!state_info.test_failed);
	     state_info.test_index++)
	{
		evhttp_set_gencb(http,
		    ((state_info.test->flags & ERRCBFLAG_GENCB) != 0 ?
		    http_error_callback_gencb : NULL),
		    &state_info);
		evhttp_set_errorcb(http,
		    ((state_info.test->flags & ERRCBFLAG_ERRCB) != 0 ?
		    http_error_callback_errorcb : NULL),
		    &state_info);

		req = evhttp_request_new(http_error_callback_test_done,
		    &state_info);
		tt_assert(req);
		if (evhttp_make_request(evcon, req, state_info.test->type,
			"/missing") == -1) {
			tt_abort_msg("Couldn't make request");
			exit(1);
		}
		event_base_dispatch(data->base);

		if (!state_info.test_failed)
			test_ok++;
		else
			tt_abort_printf(("Sub-test %d failed",
			    state_info.test_index));
		state_info.test++;
	}

end:
	if (evcon)
		evhttp_connection_free(evcon);
	if (http)
		evhttp_free(http);
}

static void http_add_output_buffer(int fd, short events, void *arg)
{
	evbuffer_add(arg, POST_DATA, strlen(POST_DATA));
}
static void
http_timeout_read_server_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct timeval tv;
	struct bufferevent *bev;
	struct evbuffer *out;
	int fd = -1;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);

	test_ok = 0;

	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	evhttp_set_write_timeout_tv(http, &tv);
	tv.tv_usec = 500000;
	evhttp_set_read_timeout_tv(http, &tv);

	fd = http_connect("127.0.0.1", port);
	bev = create_bev(data->base, fd, 0, 0);
	bufferevent_setcb(bev, http_readcb, http_writecb, http_errorcb, data->base);
	out = bufferevent_get_output(bev);

	evbuffer_add_printf(out,
	    "POST /postit HTTP/1.1\r\n"
	    "Host: somehost\r\n"
	    "Content-Length: " EV_SIZE_FMT "\r\n"
	    "\r\n", strlen(POST_DATA));

	tv.tv_usec = 200000;
	event_base_once(data->base, -1, EV_TIMEOUT, http_add_output_buffer, out, &tv);

	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 3);

 end:
	if (bev)
		bufferevent_free(bev);
	if (fd != -1)
		evutil_closesocket(fd);
	if (http)
		evhttp_free(http);
}




static void
http_max_connections_test(void *arg)
{
	struct basic_test_data *data = arg;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);
	struct evhttp_connection *evcons[2];
	struct http_newreqcb_test_state newreqcb_test_state;
	unsigned n;

	exit_base = data->base;
	test_ok = 0;

	memset(&newreqcb_test_state, 0, sizeof(newreqcb_test_state));
	memset(evcons, 0, sizeof(evcons));

	evhttp_set_max_connections(http, ARRAY_SIZE(evcons)-1);

	for (n = 0; n < sizeof(evcons)/sizeof(evcons[0]); ++n) {
		struct evhttp_connection* evcon = NULL;
		struct evhttp_request *req = NULL;
		evcons[n] = evhttp_connection_base_new(data->base, NULL, "127.0.0.1", port);
		evcon = evcons[n];
		evhttp_connection_set_retries(evcon, 0);

		tt_assert(evcon);

		req = evhttp_request_new(http_request_done_newreqcb, &newreqcb_test_state);
		evhttp_add_header(evhttp_request_get_output_headers(req), "Connection", "close");
		evhttp_request_set_error_cb(req, http_request_error_newreqcb);

		/* We give ownership of the request to the connection */
		if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
			tt_abort_msg("Couldn't make request");
		}

		++newreqcb_test_state.connections_started;
		http_newreqcb_test_state_check(&newreqcb_test_state);
	}

	/* XXX: http_newreqcb_test_state_check will not stop the base, since:
	 * - connections_done == 2
	 * - connections_good == 1
	 *
	 * hence timeout
	 */
	{
		struct timeval tv = { 0, 300e3 };
		event_base_loopexit(data->base, &tv);
	}

	event_base_dispatch(data->base);

	http_newreqcb_test_state_check(&newreqcb_test_state);
	tt_int_op(newreqcb_test_state.connections_error, ==, 0);
	tt_int_op(newreqcb_test_state.connections_done, ==, 2);
	tt_int_op(newreqcb_test_state.connections_good, ==, 1);

end:
	evhttp_free(http);

	for (n = 0; n < ARRAY_SIZE(evcons); ++n) {
		if (evcons[n]) {
			evhttp_connection_free(evcons[n]);
		}
	}
}


#define HTTP_LEGACY(name)						\
	{ #name, run_legacy_test_fn, TT_ISOLATED|TT_LEGACY, &legacy_setup, \
		    http_##name##_test }

#define HTTP_CAST_ARG(a) ((void *)(a))
#define HTTP_OFF_N(title, name, arg) \
	{ #title, http_##name##_test, TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, HTTP_CAST_ARG(arg) }
#define HTTP_RET_N(title, name, test_opts, arg) \
	{ #title, http_##name##_test, TT_ISOLATED|TT_RETRIABLE|test_opts, &basic_setup, HTTP_CAST_ARG(arg) }
#define HTTP_N(title, name, test_opts, arg) \
	{ #title, http_##name##_test, TT_ISOLATED|test_opts, &basic_setup, HTTP_CAST_ARG(arg) }
#define HTTP(name) HTTP_N(name, name, 0, NULL)
#define HTTPS(name) \
	{ "https_openssl_" #name, https_##name##_test, TT_ISOLATED, &basic_setup, NULL }
#define HTTPS_MBEDTLS(name) \
	{ "https_mbedtls_" #name, https_mbedtls_##name##_test, TT_ISOLATED, &mbedtls_setup, NULL }

#ifdef EVENT__HAVE_OPENSSL
static void https_basic_test(void *arg)
{ http_basic_test_impl(arg, HTTP_OPENSSL, "GET /test HTTP/1.1"); }
static void https_filter_basic_test(void *arg)
{ http_basic_test_impl(arg, HTTP_OPENSSL | HTTP_SSL_FILTER, "GET /test HTTP/1.1"); }
static void https_incomplete_test(void *arg)
{ http_incomplete_test_(arg, 0, HTTP_OPENSSL); }
static void https_incomplete_timeout_test(void *arg)
{ http_incomplete_test_(arg, 1, HTTP_OPENSSL); }
static void https_simple_test(void *arg)
{ http_simple_test_impl(arg, HTTP_OPENSSL, 0, "/test"); }
static void https_simple_dirty_test(void *arg)
{ http_simple_test_impl(arg, HTTP_OPENSSL, 1, "/test"); }
static void https_connection_retry_conn_address_test(void *arg)
{ http_connection_retry_conn_address_test_impl(arg, HTTP_OPENSSL); }
static void https_connection_retry_test(void *arg)
{ http_connection_retry_test_impl(arg, HTTP_OPENSSL); }
static void https_chunk_out_test(void *arg)
{ http_chunk_out_test_impl(arg, HTTP_OPENSSL); }
static void https_filter_chunk_out_test(void *arg)
{ http_chunk_out_test_impl(arg, HTTP_OPENSSL | HTTP_SSL_FILTER); }
static void https_stream_out_test(void *arg)
{ http_stream_out_test_impl(arg, HTTP_OPENSSL); }
static void https_connection_fail_test(void *arg)
{ http_connection_fail_test_impl(arg, HTTP_OPENSSL); }
static void https_write_during_read_test(void *arg)
{ http_write_during_read_test_impl(arg, HTTP_OPENSSL); }
static void https_connection_test(void *arg)
{ http_connection_test_(arg, 0, "127.0.0.1", NULL, 0, AF_UNSPEC, HTTP_OPENSSL); }
static void https_persist_connection_test(void *arg)
{ http_connection_test_(arg, 1, "127.0.0.1", NULL, 0, AF_UNSPEC, HTTP_OPENSSL); }
#endif

#ifdef EVENT__HAVE_MBEDTLS
static void https_mbedtls_basic_test(void *arg)
{ http_basic_test_impl(arg, HTTP_MBEDTLS, "GET /test HTTP/1.1"); }
static void https_mbedtls_filter_basic_test(void *arg)
{ http_basic_test_impl(arg, HTTP_MBEDTLS | HTTP_SSL_FILTER, "GET /test HTTP/1.1"); }
static void https_mbedtls_incomplete_test(void *arg)
{ http_incomplete_test_(arg, 0, HTTP_MBEDTLS); }
static void https_mbedtls_incomplete_timeout_test(void *arg)
{ http_incomplete_test_(arg, 1, HTTP_MBEDTLS); }
static void https_mbedtls_simple_test(void *arg)
{ http_simple_test_impl(arg, HTTP_MBEDTLS, 0, "/test"); }
static void https_mbedtls_simple_dirty_test(void *arg)
{ http_simple_test_impl(arg, HTTP_MBEDTLS, 1, "/test"); }
static void https_mbedtls_connection_retry_conn_address_test(void *arg)
{ http_connection_retry_conn_address_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_connection_retry_test(void *arg)
{ http_connection_retry_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_chunk_out_test(void *arg)
{ http_chunk_out_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_filter_chunk_out_test(void *arg)
{ http_chunk_out_test_impl(arg, HTTP_MBEDTLS | HTTP_SSL_FILTER); }
static void https_mbedtls_stream_out_test(void *arg)
{ http_stream_out_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_connection_fail_test(void *arg)
{ http_connection_fail_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_write_during_read_test(void *arg)
{ http_write_during_read_test_impl(arg, HTTP_MBEDTLS); }
static void https_mbedtls_connection_test(void *arg)
{ http_connection_test_(arg, 0, "127.0.0.1", NULL, 0, AF_UNSPEC, HTTP_MBEDTLS); }
static void https_mbedtls_persist_connection_test(void *arg)
{ http_connection_test_(arg, 1, "127.0.0.1", NULL, 0, AF_UNSPEC, HTTP_MBEDTLS); }
#endif

struct testcase_t http_testcases[] = {
	{ "primitives", http_primitives, 0, NULL, NULL },
	{ "base", http_base_test, TT_FORK, NULL, NULL },
	{ "bad_headers", http_bad_header_test, 0, NULL, NULL },
	{ "parse_query", http_parse_query_test, 0, NULL, NULL },
	{ "parse_query_str", http_parse_query_str_test, 0, NULL, NULL },
	{ "parse_query_str_flags", http_parse_query_str_flags_test, 0, NULL, NULL },
	{ "parse_uri", http_parse_uri_test, 0, NULL, NULL },
	{ "parse_uri_nc", http_parse_uri_test, 0, &basic_setup, (void*)"nc" },
	{ "uriencode", http_uriencode_test, 0, NULL, NULL },
	HTTP(basic),
	HTTP(basic_trailing_space),
	HTTP(simple),
	HTTP(simple_nonconformant),

	HTTP_N(cancel, cancel, 0, BASIC),
	HTTP_RET_N(cancel_by_host, cancel, 0, BY_HOST),
	HTTP_RET_N(cancel_by_host_inactive_server, cancel, TT_NO_LOGS, BY_HOST | INACTIVE_SERVER),
	HTTP_RET_N(cancel_by_host_no_ns, cancel, TT_NO_LOGS, BY_HOST | NO_NS),
	HTTP_N(cancel_inactive_server, cancel, 0, INACTIVE_SERVER),
	HTTP_N(cancel_by_host_no_ns_inactive_server, cancel, TT_NO_LOGS, BY_HOST | NO_NS | INACTIVE_SERVER),
	HTTP_OFF_N(cancel_by_host_server_timeout, cancel, BY_HOST | INACTIVE_SERVER | SERVER_TIMEOUT),
	HTTP_OFF_N(cancel_server_timeout, cancel, INACTIVE_SERVER | SERVER_TIMEOUT),
	HTTP_OFF_N(cancel_by_host_no_ns_server_timeout, cancel, BY_HOST | NO_NS | INACTIVE_SERVER | SERVER_TIMEOUT),
	HTTP_OFF_N(cancel_by_host_ns_timeout_server_timeout, cancel, BY_HOST | NO_NS | NS_TIMEOUT | INACTIVE_SERVER | SERVER_TIMEOUT),
	HTTP_RET_N(cancel_by_host_ns_timeout, cancel, TT_NO_LOGS, BY_HOST | NO_NS | NS_TIMEOUT),
	HTTP_RET_N(cancel_by_host_ns_timeout_inactive_server, cancel, TT_NO_LOGS, BY_HOST | NO_NS | NS_TIMEOUT | INACTIVE_SERVER),

	HTTP(virtual_host),
	HTTP(post),
	HTTP(put),
	HTTP(delete),
	HTTP(propfind),
	HTTP(proppatch),
	HTTP(mkcol),
	HTTP(lock),
	HTTP(unlock),
	HTTP(copy),
	HTTP(move),
	HTTP(custom),
	HTTP(allowed_methods),
	HTTP(failure),
	HTTP(connection),
	HTTP(persist_connection),
	HTTP(autofree_connection),
	HTTP(connection_async),
	HTTP(close_detection),
	HTTP(close_detection_delay),
	HTTP(bad_request),
	HTTP(incomplete),
	HTTP(incomplete_timeout),
	HTTP(terminate_chunked),
	HTTP(terminate_chunked_oneshot),
	HTTP(on_complete),

	HTTP(highport),
	HTTP(dispatcher),
	HTTP(multi_line_header),
	HTTP(negative_content_length),
	HTTP(send_chunk),
	HTTP(chunk_out),
	HTTP(stream_out),

	HTTP(stream_in),
	HTTP(stream_in_cancel),

	HTTP(connection_fail),
	{ "connection_retry", http_connection_retry_test, TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },
	{ "connection_retry_conn_address", http_connection_retry_conn_address_test,
	  TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },

	HTTP(data_length_constraints),
	HTTP(read_on_write_error),
	HTTP(non_lingering_close),
	HTTP(lingering_close),

	HTTP(ipv6_for_domain),
	HTTP(get_addr),

	HTTP(set_family),
	HTTP(set_family_ipv4),
	HTTP(set_family_ipv6),

	HTTP(write_during_read),
	HTTP(request_own),
	HTTP(error_callback),

	HTTP(request_extra_body),

	HTTP(newreqcb),
	HTTP(max_connections),

	HTTP(timeout_read_client),
	HTTP(timeout_read_server),

#ifdef EVENT__HAVE_OPENSSL
	HTTPS(basic),
	HTTPS(filter_basic),
	HTTPS(simple),
	HTTPS(simple_dirty),
	HTTPS(incomplete),
	HTTPS(incomplete_timeout),
	{ "https_connection_retry", https_connection_retry_test, TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },
	{ "https_connection_retry_conn_address", https_connection_retry_conn_address_test,
	  TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },
	HTTPS(chunk_out),
	HTTPS(filter_chunk_out),
	HTTPS(stream_out),
	HTTPS(connection_fail),
	HTTPS(write_during_read),
	HTTPS(connection),
	HTTPS(persist_connection),
#endif

#ifdef EVENT__HAVE_MBEDTLS
	HTTPS_MBEDTLS(basic),
	HTTPS_MBEDTLS(filter_basic),
	HTTPS_MBEDTLS(simple),
	HTTPS_MBEDTLS(simple_dirty),
	HTTPS_MBEDTLS(incomplete),
	HTTPS_MBEDTLS(incomplete_timeout),
	{ "https_mbedtls_connection_retry", https_mbedtls_connection_retry_test, TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },
	{ "https_mbedtls_connection_retry_conn_address", https_mbedtls_connection_retry_conn_address_test,
	  TT_ISOLATED|TT_OFF_BY_DEFAULT, &basic_setup, NULL },
	HTTPS_MBEDTLS(chunk_out),
	HTTPS_MBEDTLS(filter_chunk_out),
	HTTPS_MBEDTLS(stream_out),
	HTTPS_MBEDTLS(connection_fail),
	HTTPS_MBEDTLS(write_during_read),
	HTTPS_MBEDTLS(connection),
	HTTPS_MBEDTLS(persist_connection),
#endif

	END_OF_TESTCASES
};

struct testcase_t http_iocp_testcases[] = {
	{ "simple", http_simple_test, TT_FORK|TT_NEED_BASE|TT_ENABLE_IOCP, &basic_setup, NULL },
#ifdef EVENT__HAVE_OPENSSL
	{ "https_openssl_simple", https_simple_test, TT_FORK|TT_NEED_BASE|TT_ENABLE_IOCP, &basic_setup, NULL },
#endif
#ifdef EVENT__HAVE_MBEDTLS
	{ "https_mbedtls_simple", https_mbedtls_simple_test, TT_FORK|TT_NEED_BASE|TT_ENABLE_IOCP, &mbedtls_setup, NULL },
#endif
	END_OF_TESTCASES
};
