/*
 * Copyright (c) 2003-2006 Niels Provos <provos@citi.umich.edu>
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

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/signal.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "event.h"
#include "evhttp.h"
#include "log.h"
#include "http-internal.h"

extern int pair[];
extern int test_ok;

static struct evhttp *http;
/* set if a test needs to call loopexit on a base */
static struct event_base *base;

void http_suite(void);

static void http_basic_cb(struct evhttp_request *req, void *arg);
static void http_chunked_cb(struct evhttp_request *req, void *arg);
static void http_post_cb(struct evhttp_request *req, void *arg);
static void http_put_cb(struct evhttp_request *req, void *arg);
static void http_delete_cb(struct evhttp_request *req, void *arg);
static void http_delay_cb(struct evhttp_request *req, void *arg);
static void http_dispatcher_cb(struct evhttp_request *req, void *arg);

static struct evhttp *
http_setup(short *pport, struct event_base *base)
{
	int i;
	struct evhttp *myhttp;
	short port = -1;

	/* Try a few different ports */
	myhttp = evhttp_new(base);
	for (i = 0; i < 50; ++i) {
		if (evhttp_bind_socket(myhttp, "127.0.0.1", 8080 + i) != -1) {
			port = 8080 + i;
			break;
		}
	}

	if (port == -1)
		event_errx(1, "Could not start web server");

	/* Register a callback for certain types of requests */
	evhttp_set_cb(myhttp, "/test", http_basic_cb, NULL);
	evhttp_set_cb(myhttp, "/chunked", http_chunked_cb, NULL);
	evhttp_set_cb(myhttp, "/postit", http_post_cb, NULL);
	evhttp_set_cb(myhttp, "/putit", http_put_cb, NULL);
	evhttp_set_cb(myhttp, "/deleteit", http_delete_cb, NULL);
	evhttp_set_cb(myhttp, "/delay", http_delay_cb, NULL);
	evhttp_set_cb(myhttp, "/", http_dispatcher_cb, NULL);

	*pport = port;
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
	int fd;
	
#ifdef WIN32
	if (!(he = gethostbyname(address))) {
		event_warn("gethostbyname");
	}
	memcpy(&sin.sin_addr, &he->h_addr, sizeof(struct in_addr));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	slen = sizeof(struct sockaddr_in);
	sa = (struct sockaddr*)&sin;
#else
	memset(&ai, 0, sizeof (ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = SOCK_STREAM;
	evutil_snprintf(strport, sizeof (strport), "%d", port);
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
	const char *what = "This is funny";

 	event_debug(("%s: %s\n", __func__, EVBUFFER_DATA(EVBUFFER_INPUT(bev))));
	
	if (evbuffer_find(EVBUFFER_INPUT(bev),
		(const unsigned char*) what, strlen(what)) != NULL) {
		struct evhttp_request *req = evhttp_request_new(NULL, NULL);
		int done;

		req->kind = EVHTTP_RESPONSE;
		done = evhttp_parse_lines(req, EVBUFFER_INPUT(bev));

		if (done == 1 &&
		    evhttp_find_header(req->input_headers,
			"Content-Type") != NULL)
			test_ok++;
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
	if (EVBUFFER_LENGTH(EVBUFFER_OUTPUT(bev)) == 0) {
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
	evbuffer_add_printf(evb, "This is funny");

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static void
http_chunked_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();
	event_debug(("%s: called\n", __func__));

	/* generate a chunked reply */
	evhttp_send_reply_start(req, HTTP_OK, "Everything is fine");

	/* first chunk */
	evbuffer_add_printf(evb, "This is funny");
	evhttp_send_reply_chunk(req, evb);

	/* second chunk */
	evbuffer_add_printf(evb, "but not hilarious.");
	evhttp_send_reply_chunk(req, evb);

	/* third and last chunk */
	evbuffer_add_printf(evb, "bwv 1052");
	evhttp_send_reply_chunk(req, evb);

	/* finish request */
	evhttp_send_reply_end(req);

	evbuffer_free(evb);
}

static void
http_basic_test(void)
{
	struct bufferevent *bev;
	int fd;
	const char *http_request;
	short port = -1;

	test_ok = 0;
	fprintf(stdout, "Testing Basic HTTP Server: ");

	http = http_setup(&port, NULL);

	/* bind to a second socket */
	if (evhttp_bind_socket(http, "127.0.0.1", port + 1) == -1) {
		fprintf(stdout, "FAILED (bind)\n");
		exit(1);
	}
	
	fd = http_connect("127.0.0.1", port);

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

	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* connect to the second port */
	bufferevent_free(bev);
	EVUTIL_CLOSESOCKET(fd);

	fd = http_connect("127.0.0.1", port + 1);

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
	close(fd);

	evhttp_free(http);
	
	if (test_ok != 4) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	fprintf(stdout, "OK\n");
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
	timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 200 * 1000;

	event_once(-1, EV_TIMEOUT, http_delay_reply, req, &tv);
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
	evbuffer_add_printf(evb, "This is funny");

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine",
	    !empty ? evb : NULL);

	evbuffer_free(evb);
}

static void
http_delete_test(void)
{
	struct bufferevent *bev;
	int fd;
	const char *http_request;
	short port = -1;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP DELETE Request: ");

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
	close(fd);

	evhttp_free(http);
	
	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
}

static void http_request_done(struct evhttp_request *, void *);
static void http_request_empty_done(struct evhttp_request *, void *);

static void
http_connection_test(int persistent)
{
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	
	test_ok = 0;
	fprintf(stdout, "Testing Request Connection Pipeline %s: ",
	    persistent ? "(persistent)" : "");

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* try to make another request over the same connection */
	test_ok = 0;
	
	req = evhttp_request_new(http_request_done, NULL);

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
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	/* make another request: request empty reply */
	test_ok = 0;
	
	req = evhttp_request_new(http_request_empty_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
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
	timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 500 * 1000;

	evhttp_cancel_request(req);

	event_loopexit(&tv);

	++test_ok;
}

static void
http_cancel_test(void)
{
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv;
	
	test_ok = 0;
	fprintf(stdout, "Testing Request Cancelation: ");

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_request_never_call, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/delay") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100 * 1000;

	event_once(-1, EV_TIMEOUT, http_do_cancel, req, &tv);

	event_dispatch();

	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* try to make another request over the same connection */
	test_ok = 0;
	
	req = evhttp_request_new(http_request_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	/* make another request: request empty reply */
	test_ok = 0;
	
	req = evhttp_request_new(http_request_empty_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Empty", "itis");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
}

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	const char *what = "This is funny";

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
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct evhttp *second = NULL, *third = NULL;
	
	test_ok = 0;
	fprintf(stdout, "Testing Virtual Hosts: ");

	http = http_setup(&port, NULL);

	/* virtual host */
	second = evhttp_new(NULL);
	evhttp_set_cb(second, "/funnybunny", http_basic_cb, NULL);
	third = evhttp_new(NULL);
	evhttp_set_cb(third, "/blackcoffee", http_basic_cb, NULL);

	if (evhttp_add_virtual_host(http, "foo.com", second) == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	if (evhttp_add_virtual_host(http, "bar.*.foo.com", third) == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* make a request with a different host and expect an error */
	req = evhttp_request_new(http_request_expect_error, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/funnybunny") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	test_ok = 0;

	/* make a request with the right host and expect a response */
	req = evhttp_request_new(http_request_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "bar.magic.foo.com");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/blackcoffee") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
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
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP Dispatcher: ");

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_dispatcher_test_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/?arg=val") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
}

/*
 * HTTP POST test.
 */

void http_postrequest_done(struct evhttp_request *, void *);

#define POST_DATA "Okay.  Not really printf"

static void
http_post_test(void)
{
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP POST Request: ");

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * At this point, we want to schedule an HTTP POST request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_postrequest_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	evbuffer_add_printf(req->output_buffer, POST_DATA);
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_POST, "/postit") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
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
	evbuffer_add_printf(evb, "This is funny");

	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);
}

void
http_postrequest_done(struct evhttp_request *req, void *arg)
{
	const char *what = "This is funny";

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
  short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP PUT Request: ");

	http = http_setup(&port, NULL);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * Schedule the HTTP PUT request
	 */

	req = evhttp_request_new(http_putrequest_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "someotherhost");
	evbuffer_add_printf(req->output_buffer, PUT_DATA);
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_PUT, "/putit") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
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
		//exit(1);
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
	if (evbuffer_find(EVBUFFER_INPUT(bev),
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
	int fd;
	const char *http_request;
	short port = -1;

	test_ok = 0;
	fprintf(stdout, "Testing Bad HTTP Request: ");

	http = http_setup(&port, NULL);
	
	fd = http_connect("127.0.0.1", port);

	/* Stupid thing to send a request */
	bev = bufferevent_new(fd, http_failure_readcb, http_writecb,
	    http_errorcb, NULL);

	http_request = "illegal request\r\n";

	bufferevent_write(bev, http_request, strlen(http_request));
	
	event_dispatch();

	bufferevent_free(bev);
	close(fd);

	evhttp_free(http);
	
	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
}

static void
close_detect_done(struct evhttp_request *req, void *arg)
{
	if (req == NULL || req->response_code != HTTP_OK) {
	
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	test_ok = 1;
	event_loopexit(NULL);
}

static void
close_detect_launch(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req;

	req = evhttp_request_new(close_detect_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
}

static void
close_detect_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct timeval tv;

	if (req->response_code != HTTP_OK) {
	
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	timerclear(&tv);
	tv.tv_sec = 3;   /* longer than the http time out */

	/* launch a new request on the persistent connection in 6 seconds */
	event_once(-1, EV_TIMEOUT, close_detect_launch, evcon, &tv);
}


static void
http_close_detection(void)
{
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	
	test_ok = 0;
	fprintf(stdout, "Testing Connection Close Detection: ");

	http = http_setup(&port, NULL);

	/* 2 second timeout */
	evhttp_set_timeout(http, 2);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * At this point, we want to schedule a request to the HTTP
	 * server using our make request method.
	 */

	req = evhttp_request_new(close_detect_cb, evcon);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/test") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
}

static void
http_highport_test(void)
{
	int i = -1;
	struct evhttp *myhttp = NULL;
 
	fprintf(stdout, "Testing HTTP Server with high port: ");

	/* Try a few different ports */
	for (i = 0; i < 50; ++i) {
		myhttp = evhttp_start("127.0.0.1", 65535 - i);
		if (myhttp != NULL) {
			fprintf(stdout, "OK\n");
			evhttp_free(myhttp);
			return;
		}
	}

	fprintf(stdout, "FAILED\n");
	exit(1);
}

static void
http_bad_header_test(void)
{
	struct evkeyvalq headers;

	fprintf(stdout, "Testing HTTP Header filtering: ");

	TAILQ_INIT(&headers);

	if (evhttp_add_header(&headers, "One", "Two") != 0)
		goto fail;
	
	if (evhttp_add_header(&headers, "One\r", "Two") != -1)
		goto fail;

	if (evhttp_add_header(&headers, "One\n", "Two") != -1)
		goto fail;

	if (evhttp_add_header(&headers, "One", "Two\r") != -1)
		goto fail;

	if (evhttp_add_header(&headers, "One", "Two\n") != -1)
		goto fail;

	evhttp_clear_headers(&headers);

	fprintf(stdout, "OK\n");
	return;
fail:
	fprintf(stdout, "FAILED\n");
	exit(1);
}

static void
http_base_test(void)
{
	struct bufferevent *bev;
	int fd;
	const char *http_request;
	short port = -1;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP Server Event Base: ");

	base = event_init();

	/* 
	 * create another bogus base - which is being used by all subsequen
	 * tests - yuck!
	 */
	event_init();

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
	close(fd);

	evhttp_free(http);

	event_base_free(base);
	base = NULL;
	
	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
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
#ifndef SHUT_WR
#define SHUT_WR 1
#endif
	if (arg != NULL) {
		int fd = *(int *)arg;
		/* terminate the write side to simulate EOF */
		shutdown(fd, SHUT_WR);
	}
	if (EVBUFFER_LENGTH(EVBUFFER_OUTPUT(bev)) == 0) {
		/* enable reading of the reply */
		bufferevent_enable(bev, EV_READ);
		test_ok++;
	}
}

static void
http_incomplete_test(int use_timeout)
{
	struct bufferevent *bev;
	int fd;
	const char *http_request;
	short port = -1;
	struct timeval tv_start, tv_end;

	test_ok = 0;
	fprintf(stdout, "Testing Incomplete HTTP Request (%s): ",
	    use_timeout ? "timeout" : "eof");

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

	gettimeofday(&tv_start, NULL);
	
	event_dispatch();

	gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	if (use_timeout) {
		bufferevent_free(bev);
		close(fd);
	}

	evhttp_free(http);

	if (use_timeout && tv_end.tv_sec >= 3) {
		fprintf(stdout, "FAILED (time)\n");
		exit (1);
	} else if (!use_timeout && tv_end.tv_sec >= 1) {
		/* we should be done immediately */
		fprintf(stdout, "FAILED (time)\n");
		exit (1);
	}


	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
	
	fprintf(stdout, "OK\n");
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
		int done;
		
		req->kind = EVHTTP_RESPONSE;
		done = evhttp_parse_lines(req, EVBUFFER_INPUT(bev));

		if (done != 1)
			goto out;

		header = evhttp_find_header(req->input_headers, "Transfer-Encoding");
		if (header == NULL || strcmp(header, "chunked"))
			goto out;

		header = evhttp_find_header(req->input_headers, "Connection");
		if (header == NULL || strcmp(header, "close"))
			goto out;

		header = evbuffer_readln(EVBUFFER_INPUT(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 13 chars */
		if (strcmp(header, "d"))
			goto out;
		free((char*)header);

		if (strncmp((char *)evbuffer_pullup(EVBUFFER_INPUT(bev), 13),
			"This is funny", 13))
			goto out;

		evbuffer_drain(EVBUFFER_INPUT(bev), 13 + 2);

		header = evbuffer_readln(EVBUFFER_INPUT(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 18 chars */
		if (strcmp(header, "12"))
			goto out;
		free((char *)header);

		if (strncmp((char *)evbuffer_pullup(EVBUFFER_INPUT(bev), 18),
			"but not hilarious.", 18))
			goto out;

		evbuffer_drain(EVBUFFER_INPUT(bev), 18 + 2);

		header = evbuffer_readln(EVBUFFER_INPUT(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 8 chars */
		if (strcmp(header, "8"))
			goto out;
		free((char *)header);

		if (strncmp((char *)evbuffer_pullup(EVBUFFER_INPUT(bev), 8),
			"bwv 1052.", 8))
			goto out;

		evbuffer_drain(EVBUFFER_INPUT(bev), 8 + 2);

		header = evbuffer_readln(EVBUFFER_INPUT(bev), NULL, EVBUFFER_EOL_CRLF);
		if (header == NULL)
			goto out;
		/* 0 chars */
		if (strcmp(header, "0"))
			goto out;
		free((char *)header);

		test_ok = 2;
	}

out:
	event_loopexit(NULL);
}

static void
http_chunked_writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(EVBUFFER_OUTPUT(bev)) == 0) {
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
http_chunked_test(void)
{
	struct bufferevent *bev;
	int fd;
	const char *http_request;
	short port = -1;
	struct timeval tv_start, tv_end;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;

	test_ok = 0;
	fprintf(stdout, "Testing Chunked HTTP Reply: ");

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

	gettimeofday(&tv_start, NULL);
	
	event_dispatch();

	gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	if (tv_end.tv_sec >= 1) {
		fprintf(stdout, "FAILED (time)\n");
		exit (1);
	}


	if (test_ok != 2) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* now try again with the regular connection object */
	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
	req = evhttp_request_new(http_chunked_request_done, NULL);

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");

	/* We give ownership of the request to the connection */
	if (evhttp_make_request(evcon, req,
		EVHTTP_REQ_GET, "/chunked") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_dispatch();

	if (test_ok != 1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
}

static void
http_connection_retry_done(struct evhttp_request *req, void *arg)
{
	if (req->response_code == HTTP_OK) {
		fprintf(stderr, "FAILED\n");
		exit(1);
	}

	if (evhttp_find_header(req->input_headers, "Content-Type") != NULL) {
		fprintf(stderr, "FAILED (content type)\n");
		exit(1);
	}

	if (EVBUFFER_LENGTH(req->input_buffer)) {
		fprintf(stderr, "FAILED (length)\n");
		exit(1);
	}
	
	test_ok = 1;
	event_loopexit(NULL);
}

static void
http_make_web_server(int fd, short what, void *arg)
{
	short port = -1;
	http = http_setup(&port, NULL);
}

static void
http_connection_retry(void)
{
	short port = -1;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	struct timeval tv, tv_start, tv_end;

	test_ok = 0;
	fprintf(stdout, "Testing HTTP Connection Retry: ");

	/* auto detect the port */
	http = http_setup(&port, NULL);
	evhttp_free(http);

	evcon = evhttp_connection_new("127.0.0.1", port);
	if (evcon == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evhttp_connection_set_timeout(evcon, 1);
	/* also bind to local host */
	evhttp_connection_set_local_address(evcon, "127.0.0.1");

	/*
	 * At this point, we want to schedule an HTTP GET request
	 * server using our make request method.
	 */

	req = evhttp_request_new(http_connection_retry_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	gettimeofday(&tv_start, NULL);
	event_dispatch();
	gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	if (tv_end.tv_sec >= 1) {
		fprintf(stdout, "FAILED (time)\n");
		exit(1);
	}

	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}

	/*
	 * now test the same but with retries
	 */
	test_ok = 0;

	evhttp_connection_set_timeout(evcon, 1);
	evhttp_connection_set_retries(evcon, 1);

	req = evhttp_request_new(http_connection_retry_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	gettimeofday(&tv_start, NULL);
	event_dispatch();
	gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	if (tv_end.tv_sec <= 1 || tv_end.tv_sec >= 6) {
		fprintf(stdout, "FAILED (time)\n");
		exit(1);
	}

	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}

	/*
	 * now test the same but with retries and give it a web server
	 * at the end
	 */
	test_ok = 0;

	evhttp_connection_set_timeout(evcon, 1);
	evhttp_connection_set_retries(evcon, 3);

	req = evhttp_request_new(http_dispatcher_test_done, NULL);
	if (req == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* Add the information that we care about */
	evhttp_add_header(req->output_headers, "Host", "somehost");
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
		"/?arg=val") == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* start up a web server one second after the connection tried
	 * to send a request
	 */
	timerclear(&tv);
	tv.tv_sec = 1;
	event_once(-1, EV_TIMEOUT, http_make_web_server, NULL, &tv);

	gettimeofday(&tv_start, NULL);
	event_dispatch();
	gettimeofday(&tv_end, NULL);

	evutil_timersub(&tv_end, &tv_start, &tv_end);
	if (tv_end.tv_sec <= 1 || tv_end.tv_sec >= 6) {
		fprintf(stdout, "FAILED (time)\n");
		exit(1);
	}

	if (test_ok != 1) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}

	evhttp_connection_free(evcon);
	evhttp_free(http);
	
	fprintf(stdout, "OK\n");
}

static void
http_primitives(void)
{
	char *escaped;
	fprintf(stdout, "Testing HTTP Primitives: ");

	escaped = evhttp_htmlescape("<script>");
	if (strcmp(escaped, "&lt;script&gt;"))
		goto failed;
	free(escaped);

	escaped = evhttp_htmlescape("\"\'&");
	if (strcmp(escaped, "&quot;&#039;&amp;"))
		goto failed;
	free(escaped);

	fprintf(stdout, "OK\n");

	return;

failed:
	fprintf(stdout, "FAILED\n");
	exit(1);
}

void
http_suite(void)
{
	http_primitives();

	http_base_test();
	http_bad_header_test();
	http_basic_test();
	http_cancel_test();
	http_connection_test(0 /* not-persistent */);
	http_connection_test(1 /* persistent */);
	http_virtual_host_test();
	http_close_detection();
	http_post_test();
	http_put_test();
	http_delete_test();
	http_failure_test();
	http_highport_test();
	http_dispatcher_test();

	http_incomplete_test(0 /* use_timeout */);
	http_incomplete_test(1 /* use_timeout */);

	http_chunked_test();

	http_connection_retry();
}
