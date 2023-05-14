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

#include <stdbool.h>
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
#include <string.h>
#ifdef EVENT__HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "event2/event.h"
#include "event2/http.h"
#include "event2/buffer.h"
#include "event2/bufferevent_ssl.h"
#include "event2/ws.h"
#include "regress.h"
#include "regress_http.h"
#include "regress_ws.h"

#undef htonll
#define htonll(x)    \
	((1 == htonl(1)) \
			? (x)    \
			: ((uint64_t)htonl((x)&0xFFFFFFFF) << 32) | htonl((x) >> 32))
#undef ntohll
#define ntohll(x) htonll(x)


static struct event_base *exit_base;

static void
on_ws_msg_cb(struct evws_connection *evws, int type, const unsigned char *data,
	size_t len, void *arg)
{
	ev_uintptr_t val = (ev_uintptr_t)arg;
	char msg[4096];

	if (val != 0xDEADBEEF) {
		fprintf(stdout, "FAILED on_complete_cb argument\n");
		exit(1);
	}


	snprintf(msg, sizeof(msg), "%.*s", (int)len, data);
	if (!strcmp(msg, "Send echo")) {
		const char *reply = "Reply echo";

		evws_send(evws, reply, strlen(reply));
		test_ok++;
	} else if (!strcmp(msg, "Client: hello")) {
		test_ok++;
	} else if (!strcmp(msg, "Close")) {
		evws_close(evws, 0);
		test_ok++;
	} else {
		/* unexpected test message */
		event_base_loopexit(arg, NULL);
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
	const char *hello = "Server: hello";

	evws = evws_new_session(req, on_ws_msg_cb, (void *)0xDEADBEEF, 0);
	if (!evws)
		return;
	test_ok++;

	evws_connection_set_closecb(evws, on_ws_close_cb, (void *)0xDEADBEEF);
	evws_send(evws, hello, strlen(hello));
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

static char *
receive_ws_msg(struct evbuffer *buf, size_t *out_len, unsigned *options)
{
	unsigned char *data;
	int fin, opcode, mask;
	uint64_t payload_len;
	size_t header_len;
	const unsigned char *mask_key;
	char *out_buf = NULL;
	size_t data_len = evbuffer_get_length(buf);
	size_t i;

	data = evbuffer_pullup(buf, data_len);

	fin = !!(*data & 0x80);
	opcode = *data & 0x0F;
	mask = !!(*(data + 1) & 0x80);
	payload_len = *(data + 1) & 0x7F;

	header_len = 2 + (mask ? 4 : 0);

	if (payload_len < 126) {
		if (header_len > data_len)
			return NULL;

	} else if (payload_len == 126) {
		header_len += 2;
		if (header_len > data_len)
			return NULL;

		payload_len = ntohs(*(uint16_t *)(data + 2));

	} else if (payload_len == 127) {
		header_len += 8;
		if (header_len > data_len)
			return NULL;

		payload_len = ntohll(*(uint64_t *)(data + 2));
	}

	if (header_len + payload_len > data_len)
		return NULL;

	mask_key = data + header_len - 4;
	for (i = 0; mask && i < payload_len; i++)
		data[header_len + i] ^= mask_key[i % 4];

	*out_len = payload_len;

	/* text */
	if (opcode == 0x01) {
		out_buf = calloc(payload_len + 1, 1);
	} else { /* binary */
		out_buf = malloc(payload_len);
	}
	memcpy(out_buf, (const char *)data + header_len, payload_len);

	if (!fin) {
		*options = 1;
	}

	evbuffer_drain(buf, header_len + payload_len);
	return out_buf;
}

static void
send_ws_msg(struct evbuffer *buf, const char *msg, bool final)
{
	size_t len = strlen(msg);
	uint8_t a = 0, b = 0, c = 0, d = 0;
	uint8_t mask_key[4] = {1, 2, 3, 4}; /* should be random */
	uint8_t m;
	size_t i;

	if (final)
		a |= 1 << 7; /* fin */
	a |= 1;			 /* text frame */

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

	for (i = 0; i < len; i++) {
		m = msg[i] ^ mask_key[i % 4];
		evbuffer_add(buf, &m, 1);
	}
}

static void
http_ws_readcb_phase2(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_output(bev);

	while (evbuffer_get_length(input) >= 2) {
		size_t len = 0;
		unsigned options = 0;
		char *msg;

		msg = receive_ws_msg(input, &len, &options);
		if (msg) {
			if (!strcmp(msg, "Server: hello")) {
				send_ws_msg(output, "Send ", false);
				send_ws_msg(output, "echo", true);
				test_ok++;
			} else if (!strcmp(msg, "Reply echo")) {
				send_ws_msg(output, "Close", true);
				test_ok++;
			} else {
				test_ok--;
			}
			free(msg);
		}
	}
}

static void
http_ws_readcb_hdr(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_output(bev);
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
			send_ws_msg(output, "Client:", false);
			send_ws_msg(output, " ", false);
			send_ws_msg(output, "hello", true);
			test_ok++;
			if (evbuffer_get_length(input) > 0) {
				http_ws_readcb_phase2(bev, arg);
			}
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
	tt_int_op(test_ok, ==, 13);

	evhttp_free(http);
end:
	if (bev)
		bufferevent_free(bev);
}
