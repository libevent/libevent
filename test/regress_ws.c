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

#define TEST_WS_FRAGMENT_LEN (6 * 1024 * 1024)
#define TEST_WS_CLOSE_TOO_BIG 1009

struct ws_limit_test_state {
	struct event_base *base;
	int phase;
};

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

		evws_send_text(evws, reply);
		test_ok++;
	} else if (!strcmp(msg, "Client: hello")) {
		test_ok++;
	} else if (!strcmp(msg, "Bye")) {
		evws_send_binary(evws, "\xde\xad\xbe\xef\x55", 5);
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
	evws_send_text(evws, hello);
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
receive_ws_msg(struct evbuffer *buf, size_t *out_len, bool *is_text_type)
{
	unsigned char *data;
	int opcode, mask;
	uint64_t payload_len;
	size_t header_len;
	const unsigned char *mask_key;
	char *out_buf = NULL;
	size_t data_len = evbuffer_get_length(buf);
	size_t i;

	data = evbuffer_pullup(buf, data_len);

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
		*is_text_type = true;
	} else { /* binary */
		out_buf = malloc(payload_len);
	}
	memcpy(out_buf, (const char *)data + header_len, payload_len);

	evbuffer_drain(buf, header_len + payload_len);
	return out_buf;
}

enum WSOptions {
	WS_FIN = 1 << 7,
	WS_TEXT = 1 << 0,
	WS_BINARY = 1 << 1,
};

static void
send_ws_msg(
	struct evbuffer *buf, const char *msg, size_t len, enum WSOptions options)
{
	uint8_t a = 0, b = 0;
	uint16_t c = 0;
       	uint64_t d = 0;
	uint8_t mask_key[4] = {1, 2, 3, 4}; /* should be random */
	uint8_t m;
	size_t i;

	a = options;
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
		bool is_text_type = false;
		char *msg;

		msg = receive_ws_msg(input, &len, &is_text_type);
		if (msg) {
			if (is_text_type) {
				if (!strcmp(msg, "Server: hello")) {
					send_ws_msg(output, "Send ", strlen("Send "), WS_TEXT);
					send_ws_msg(
						output, "echo", strlen("echo"), WS_TEXT | WS_FIN);
					test_ok++;
				} else if (!strcmp(msg, "Reply echo")) {
					send_ws_msg(output, "Bye", strlen("Bye"), WS_TEXT | WS_FIN);
					test_ok++;
				} else {
					test_ok--;
				}
			} else {
				if (len == 5 && !memcmp(msg, "\xde\xad\xbe\xef\x55", 5)) {
					send_ws_msg(
						output, "Close", strlen("Close"), WS_TEXT | WS_FIN);
					test_ok++;
				} else {
					test_ok--;
				}
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
			send_ws_msg(output, "Client:", strlen("Client:"), WS_TEXT);
			send_ws_msg(output, " ", strlen(" "), WS_TEXT);
			send_ws_msg(output, "hello", strlen("hello"), WS_TEXT | WS_FIN);
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

static void
send_ws_repeated_msg(struct evbuffer *buf, unsigned char ch, size_t len,
	enum WSOptions options)
{
	uint8_t a = 0, b = 0;
	uint16_t c = 0;
	uint64_t d = 0;
	uint8_t mask_key[4] = {1, 2, 3, 4};
	unsigned char block[4096];
	size_t i, chunk;

	memset(block, ch, sizeof(block));

	a = options;
	b |= 1 << 7;

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

	for (i = 0; i < sizeof(block); ++i) {
		block[i] ^= mask_key[i % 4];
	}

	while (len) {
		chunk = len < sizeof(block) ? len : sizeof(block);
		evbuffer_add(buf, block, chunk);
		len -= chunk;
	}
}

static int
receive_ws_close_code(struct evbuffer *buf, uint16_t *reason_out)
{
	unsigned char *data;
	size_t data_len = evbuffer_get_length(buf);
	size_t payload_len;
	uint16_t reason;

	if (data_len < 4) {
		return 0;
	}

	data = evbuffer_pullup(buf, data_len);
	if (data == NULL) {
		return 0;
	}

	if ((data[0] & 0x0F) != 0x08) {
		return 0;
	}

	payload_len = data[1] & 0x7F;
	if (data[1] & 0x80) {
		return 0;
	}
	if (payload_len != 2) {
		return 0;
	}

	if (data_len < 4) {
		return 0;
	}

	memcpy(&reason, data + 2, sizeof(reason));
	*reason_out = ntohs(reason);
	evbuffer_drain(buf, 4);
	return 1;
}

static void
on_ws_msg_limit_cb(struct evws_connection *evws, int type,
	const unsigned char *data, size_t len, void *arg)
{
	(void)evws;
	(void)type;
	(void)data;
	(void)len;
	(void)arg;
	test_ok = -1;
	event_base_loopexit(exit_base, NULL);
}

static void
http_on_ws_limit_cb(struct evhttp_request *req, void *arg)
{
	struct evws_connection *evws;

	evws = evws_new_session(req, on_ws_msg_limit_cb, NULL, 0);
	if (!evws)
		return;
	(void)arg;
}

static void
http_ws_msg_limit_errorcb(struct bufferevent *bev, short what, void *arg)
{
	struct ws_limit_test_state *state = arg;

	(void)bev;
	if (what & BEV_EVENT_CONNECTED)
		return;
	if (test_ok == 0) {
		test_ok = -3;
	}
	event_base_loopexit(state->base, NULL);
}

static void
http_ws_msg_limit_readcb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *input = bufferevent_get_input(bev);
	struct evbuffer *output = bufferevent_get_output(bev);
	size_t nread = 0;
	char *line;
	uint16_t reason;
	struct ws_limit_test_state *state = arg;

	if (state->phase == 0) {
		while ((line = evbuffer_readln(input, &nread, EVBUFFER_EOL_CRLF))) {
			if (strlen(line) == 0) {
				free(line);
				send_ws_repeated_msg(
					output, 'A', TEST_WS_FRAGMENT_LEN, WS_TEXT);
				send_ws_repeated_msg(
					output, 'B', TEST_WS_FRAGMENT_LEN, WS_TEXT | WS_FIN);
				state->phase = 1;
				return;
			}
			free(line);
		}
		return;
	}

	if (receive_ws_close_code(input, &reason)) {
		test_ok = (reason == TEST_WS_CLOSE_TOO_BIG) ? 1 : -2;
		event_base_loopexit(exit_base, NULL);
	}
}

static void
http_ws_test_with_connection(void *arg, const char* conn_value)
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
							 "Connection: %s\r\n"
							 "Upgrade: websocket\r\n"
							 "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
							 "\r\n", conn_value);

	test_ok = 0;
	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 16);

	evhttp_free(http);
end:
	if (bev)
		bufferevent_free(bev);
}

void
http_ws_test(void *arg)
{
	http_ws_test_with_connection(arg, "Upgrade");
	http_ws_test_with_connection(arg, "keep-alive, Upgrade");
}

void
http_ws_msg_limit_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	struct evhttp *http = NULL;
	struct evbuffer *out;
	struct ws_limit_test_state state;
	evutil_socket_t fd;
	ev_uint16_t port = 0;

	exit_base = data->base;
	test_ok = 0;
	memset(&state, 0, sizeof(state));
	state.base = data->base;

	http = http_setup(&port, data->base, 0);
	evhttp_set_cb(http, "/ws-limit", http_on_ws_limit_cb, data->base);

	fd = http_connect("127.0.0.1", port);
	tt_assert(fd != EVUTIL_INVALID_SOCKET);

	bev = create_bev(data->base, fd, 0, BEV_OPT_CLOSE_ON_FREE);
	tt_assert(bev);
	bufferevent_setcb(
		bev, http_ws_msg_limit_readcb, http_writecb,
		http_ws_msg_limit_errorcb, &state);

	out = bufferevent_get_output(bev);
	evbuffer_add_printf(out, "GET /ws-limit HTTP/1.1\r\n"
		"Host: somehost\r\n"
		"Connection: Upgrade\r\n"
		"Upgrade: websocket\r\n"
		"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
		"\r\n");

	event_base_dispatch(data->base);
	tt_int_op(test_ok, ==, 1);

end:
	if (bev)
		bufferevent_free(bev);
	if (http)
		evhttp_free(http);
}

static struct bufferevent *
ws_threadsafe_bevcb(struct event_base *base, void *arg)
{
	return bufferevent_socket_new(
		base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
}

static int ws_early_free_session_was_null;

static void
http_on_ws_early_free_cb(struct evhttp_request *req, void *arg)
{
	struct evws_connection *evws;

	evws = evws_new_session(req, on_ws_msg_cb, (void *)0xDEADBEEF,
		BEV_OPT_THREADSAFE);
	if (evws == NULL) {
		ws_early_free_session_was_null = 1;
		test_ok++;
	}
}

static void
ws_early_free_drain_readcb(struct bufferevent *bev, void *arg)
{
	evbuffer_drain(bufferevent_get_input(bev), evbuffer_get_length(
		bufferevent_get_input(bev)));
}

void
http_ws_early_free_test(void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev = NULL;
	evutil_socket_t fd;
	ev_uint16_t port = 0;
	struct evhttp *http = http_setup(&port, data->base, 0);
	struct evbuffer *out;
	struct timeval tv = {5, 0};

	exit_base = data->base;
	ws_early_free_session_was_null = 0;

	evhttp_set_bevcb(http, ws_threadsafe_bevcb, NULL);
	evhttp_set_cb(http, "/ws_early_free", http_on_ws_early_free_cb, NULL);

	fd = http_connect("127.0.0.1", port);
	bev = create_bev(data->base, fd, 0, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, ws_early_free_drain_readcb, http_writecb,
		http_ws_errorcb, data->base);
	out = bufferevent_get_output(bev);

	evbuffer_add_printf(out,
		"GET /ws_early_free HTTP/1.1\r\n"
		"Host: somehost\r\n"
		"Connection: Upgrade\r\n"
		"Upgrade: websocket\r\n"
		"Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
		"\r\n");

	test_ok = 0;
	event_base_loopexit(data->base, &tv);
	event_base_dispatch(data->base);

	tt_int_op(ws_early_free_session_was_null, ==, 1);

	evhttp_free(http);
end:
	if (bev)
		bufferevent_free(bev);
}

