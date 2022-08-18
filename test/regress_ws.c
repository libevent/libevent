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
#include "event2/ws.h"
#include "event2/listener.h"
#include "log-internal.h"
#include "http-internal.h"
#include "regress.h"
#include "regress_http.h"
#include "regress_ws.h"
#include "regress_testutils.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#if EV_WINDOWS
#define SKIP_UNDER_WINDOWS TT_SKIP
#else
#define SKIP_UNDER_WINDOWS 0
#endif

static struct event_base *exit_base;

static void
on_ws_msg_cb(struct evws_connection *evws, char *data, size_t len, void *arg)
{
	ev_uintptr_t val = (ev_uintptr_t)arg;

	if (val != 0xDEADBEEF) {
		fprintf(stdout, "FAILED on_complete_cb argument\n");
		exit(1);
	}

	if (!strcmp(data, "Send echo")) {
		evws_send(evws, "Reply echo", strlen("Reply echo"));
		test_ok++;
	} else if (!strcmp(data, "Close")) {
		evws_close(evws, 0);
		test_ok++;
	}
}

static void
on_ws_close_cb(struct evws_connection *evws, void *arg)
{
	ev_uintptr_t val = (ev_uintptr_t)arg;

	if (val != 0xDEADBEEF) {
		fprintf(stdout, "FAILED on_complete_cb argument\n");
		exit(1);
	}
	test_ok++;
}

void
http_on_ws_cb(struct evhttp_request *req, void *arg)
{
	struct evws_connection *evws;

	evws = evws_new_session(req, on_ws_msg_cb, (void *)0xDEADBEEF);
	if (!evws)
		return;
	test_ok++;

	evws_connection_set_closecb(evws, on_ws_close_cb, (void *)0xDEADBEEF);
	evws_send(evws, "Hello", strlen("Hello"));
}

static void
http_ws_errorcb(struct bufferevent *bev, short what, void *arg)
{
	/** For ssl */
	if (what & BEV_EVENT_CONNECTED)
		return;
	test_ok++;
	event_base_loopexit(arg, NULL);
}

static void
http_ws_readcb_phase2(struct bufferevent *bev, void *arg)
{
	event_base_loopexit(arg, NULL);
}

#define htonll(x)    \
	((1 == htonl(1)) \
			? (x)    \
			: ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static void
send_ws_msg(struct evbuffer *buf, const char *msg)
{
	size_t len = strlen(msg);
	uint8_t a = 0, b = 0, c = 0, d = 0;
	uint8_t mask_key[4] = {1, 2, 3, 4}; /* should be random */
	uint8_t m;

	a |= 1 << 7; /* fin */
	a |= 1;		 /* text frame */

	b |= 1 << 7; /* mask */

	/* payload len */
	if (len < 126) {
		b |= len;
	} else if (len < (1 << 16)) {
		b |= 126;
		c = htons(len);
	} else {
		b |= 127;
		d = htonll(len);
	}

	evbuffer_add(buf, &a, 1);
	evbuffer_add(buf, &b, 1);

	if (c)
		evbuffer_add(buf, &c, sizeof(c));
	else if (d)
		evbuffer_add(buf, &d, sizeof(d));

	evbuffer_add(buf, &mask_key, 4);

	for (size_t i = 0; i < len; i++) {
		m = msg[i] ^ mask_key[i % 4];
		evbuffer_add(buf, &m, 1);
	}
}

static void
http_ws_readcb_hdr(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_input(bev);
	size_t nread = 0, n = 0;
	char *line;

	while ((line = evbuffer_readln(input, &nread, EVBUFFER_EOL_CRLF))) {
		if (n == 0 &&
			!strncmp(line, "HTTP/1.1 101 ", strlen("HTTP/1.1 101 "))) {
			test_ok++;
		} else if (!strcmp(line,
					   "Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=")) {
			test_ok++;
		} else if (strlen(line) == 0) {
			free(line);
			bufferevent_setcb(
				bev, http_ws_readcb_phase2, http_writecb, http_ws_errorcb, arg);
			send_ws_msg(output, "Send echo");
			test_ok++;
			return;
		}
		free(line);
		n++;
	};
}

static void
http_ws_readcb_bad(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	size_t nread;
	char *line;

	line = evbuffer_readln(input, &nread, EVBUFFER_EOL_CRLF);
	if (!strncmp(line, "HTTP/1.1 401 ", strlen("HTTP/1.1 401 "))) {
		test_ok++;
	}
	if (line)
		free(line);
}

void
http_ws_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	ev_uint16_t port = 0;
	int ssl = 0;
	struct evhttp *http = http_setup(&port, data->base, ssl);
	struct evbuffer *out;

	exit_base = data->base;

	/* Send HTTP-only request to WS endpoint */
	fd = http_connect("127.0.0.1", port);
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(
		bev, http_ws_readcb_bad, http_writecb, http_ws_errorcb, data->base);
	out = bufferevent_get_output(bev);

	evbuffer_add_printf(out, "GET /ws HTTP/1.1\r\n"
							 "Host: somehost\r\n"
							 "Connection: close\r\n"
							 "\r\n");

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 2);

	bufferevent_free(bev);

	/* Check for WS handshake and Sec-WebSocket-Accept correctness */
	fd = http_connect("127.0.0.1", port);
	bev = create_bev(data->base, fd, ssl, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(
		bev, http_ws_readcb_hdr, http_writecb, http_ws_errorcb, data->base);
	out = bufferevent_get_output(bev);

	evbuffer_add_printf(out, "GET /ws HTTP/1.1\r\n"
							 "Host: somehost\r\n"
							 "Connection: Upgrade\r\n"
							 "Upgrade: websocket\r\n"
							 "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
							 "\r\n");

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 5);

	evhttp_free(http);
end:
	if (bev)
		bufferevent_free(bev);
}
