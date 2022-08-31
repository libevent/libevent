#include "event2/event-config.h"
#include "evconfig-private.h"

#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/event.h"
#include "event2/http.h"
#include "event2/ws.h"
#include "util-internal.h"
#include "mm-internal.h"
#include "sha1.h"
#include "event2/bufferevent.h"
#include "sys/queue.h"
#include "http-internal.h"

#include <assert.h>
#include <string.h>
#include <stdbool.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/stat.h>
#else /* _WIN32 */
#include <winsock2.h>
#include <ws2tcpip.h>
#endif /* _WIN32 */

#ifdef EVENT__HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef EVENT__HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#define WS_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct evws_connection {
	TAILQ_ENTRY(evws_connection) next;

	struct bufferevent *bufev;

	void (*cb)(struct evws_connection *, char *, size_t, void *);
	void *cb_arg;

	void (*closecb)(struct evws_connection *, void *);
	void *cbclose_arg;

	/* for server connections, the http server they are connected with */
	struct evhttp *http_server;

	bool closed;
};

enum WebSocketFrameType {
	CONTINUATION_FRAME = 0,

	ERROR_FRAME = 0xFF,
	INCOMPLETE_FRAME = 0xFE,

	CLOSING_FRAME = 0x8,

	INCOMPLETE_TEXT_FRAME = 0x81,
	INCOMPLETE_BINARY_FRAME = 0x82,

	TEXT_FRAME = 0x1,
	BINARY_FRAME = 0x2,

	PING_FRAME = 0x9,
	PONG_FRAME = 0xA
};

/*
 * Clean up a WebSockets connection object
 */

void
evws_connection_free(struct evws_connection *evws)
{
	/* notify interested parties that this connection is going down */
	if (evws->closecb != NULL)
		(*evws->closecb)(evws, evws->cbclose_arg);

	if (evws->http_server != NULL) {
		struct evhttp *http = evws->http_server;
		TAILQ_REMOVE(&http->ws_sessions, evws, next);
		http->connection_cnt--;
	}

	if (evws->bufev != NULL) {
		bufferevent_free(evws->bufev);
	}

	mm_free(evws);
}

static const char basis_64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int
Base64encode(char *encoded, const char *string, int len)
{
	int i;
	char *p;

	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
						((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
						((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		} else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
							((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}

static char *
ws_gen_accept_key(const char *ws_key, char out[32])
{
	char buf[1024];
	char digest[20];

	snprintf(buf, sizeof(buf), "%s" WS_UUID, ws_key);

	SHA1(digest, buf, strlen(buf));
	Base64encode(out, digest, sizeof(digest));
	return out;
}

static void
close_after_write_cb(struct bufferevent *bev, void *ctx)
{
	if (evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		evws_connection_free(ctx);
	}
}

static void
close_event_cb(struct bufferevent *bev, short what, void *ctx)
{
	evws_connection_free(ctx);
}

void
evws_close(struct evws_connection *evws, uint16_t reason)
{
	uint8_t fr[4] = {0x8 | 0x80, 2, 0};
	struct evbuffer *output;
	uint16_t *u16;

	if (evws->closed)
		return;
	evws->closed = true;

	u16 = (uint16_t *)&fr[2];
	*u16 = htons((int16_t)reason);
	output = bufferevent_get_output(evws->bufev);
	evbuffer_add(output, fr, 4);

	/* wait for close frame writing complete and close connection */
	bufferevent_setcb(
		evws->bufev, NULL, close_after_write_cb, close_event_cb, evws);
}

static void
evws_force_disconnect_(struct evws_connection *evws)
{
	evws_close(evws, WS_CR_NONE);
}

/* parse base frame according to
 * https://www.rfc-editor.org/rfc/rfc6455#section-5.2
 */
static enum WebSocketFrameType
get_ws_frame(unsigned char *in_buffer, int buf_len, unsigned char **payload_ptr,
	int *out_len)
{
	unsigned char opcode;
	unsigned char fin;
	unsigned char masked;
	int payload_len;
	int pos;
	int length_field;
	unsigned int mask;

	if (buf_len < 2) {
		return INCOMPLETE_FRAME;
	}

	opcode = in_buffer[0] & 0x0F;
	fin = (in_buffer[0] >> 7) & 0x01;
	masked = (in_buffer[1] >> 7) & 0x01;

	payload_len = 0;
	pos = 2;
	length_field = in_buffer[1] & (~0x80);

	if (length_field <= 125) {
		payload_len = length_field;
	} else if (length_field == 126) { /* msglen is 16bit */
		if (buf_len < 4)
			return INCOMPLETE_FRAME;
		payload_len = ntohs(*(uint16_t *)(in_buffer + 2));
		pos += 2;
	} else if (length_field == 127) { /* msglen is 64bit */
		if (buf_len < 10)
			return INCOMPLETE_FRAME;
		payload_len = ntohs(*(uint64_t *)(in_buffer + 2));
		pos += 8;
	}
	if (buf_len < payload_len + pos + (masked ? 4 : 0)) {
		return INCOMPLETE_FRAME;
	}

	/* According to RFC it seems that unmasked data should be prohibited
	 * but we support it for nonconformant clients
	 */
	if (masked) {
		unsigned char *c;

		mask = *((unsigned int *)(in_buffer + pos));
		pos += 4;

		/* unmask data */
		c = in_buffer + pos;
		for (int i = 0; i < payload_len; i++) {
			c[i] = c[i] ^ ((unsigned char *)(&mask))[i % 4];
		}
	}

	*payload_ptr = in_buffer + pos;
	*out_len = payload_len;

	/* are reserved for further frames */
	if ((opcode >= 3 && opcode <= 7) || (opcode >= 0xb))
		return ERROR_FRAME;

	if (opcode <= 0x3 && !fin) {
		switch (opcode) {
		case CONTINUATION_FRAME:
			return INCOMPLETE_TEXT_FRAME;
		case TEXT_FRAME:
			return INCOMPLETE_TEXT_FRAME;
		case BINARY_FRAME:
			return INCOMPLETE_BINARY_FRAME;
		}
	}
	return opcode;
}


static void
ws_evhttp_read_cb(struct bufferevent *bufev, void *arg)
{
	struct evws_connection *evws = arg;
	unsigned char *payload;
	enum WebSocketFrameType type;
	int msg_len, in_len;
	struct evbuffer *input = bufferevent_get_input(evws->bufev);

	while ((in_len = evbuffer_get_length(input))) {
		unsigned char *data = evbuffer_pullup(input, in_len);

		type = get_ws_frame(data, in_len, &payload, &msg_len);

		if (type == TEXT_FRAME) {
			if (evws->cb) {
				char *text = mm_malloc(msg_len + 1);

				memcpy(text, payload, msg_len);
				text[msg_len] = 0;
				evws->cb(evws, text, msg_len, evws->cb_arg);
				free(text);
			}
		} else if (type == INCOMPLETE_TEXT_FRAME || type == INCOMPLETE_FRAME) {
			/* incomplete frame received, wait for next chunk */
			return;
		} else if (type == INCOMPLETE_BINARY_FRAME || type == BINARY_FRAME ||
				   type == CLOSING_FRAME || type == ERROR_FRAME) {
			evws_force_disconnect_(evws);
		} else if (type == PING_FRAME) {
			/* ping frame */
		} else if (type == PONG_FRAME) {
			/* pong frame */
		} else {
			event_warn("%s: unexpected frame type %d\n", __func__, type);
			evws_force_disconnect_(evws);
		}
		evbuffer_drain(input, payload - data + msg_len);
	}
}

static void
ws_evhttp_error_cb(struct bufferevent *bufev, short what, void *arg)
{
	/* when client just disappears after connection (wscat closed by Cmd+Q) */
	if (what & BEV_EVENT_EOF) {
		close_after_write_cb(bufev, arg);
	}
}

struct evws_connection *
evws_new_session(struct evhttp_request *req, ws_on_msg_cb cb, void *arg)
{
	struct evws_connection *evws = NULL;
	struct evkeyvalq *in_hdrs;
	const char *upgrade, *connection, *ws_key, *ws_protocol;
	struct evkeyvalq *out_hdrs;
	struct evhttp_connection *evcon;

	in_hdrs = evhttp_request_get_input_headers(req);
	upgrade = evhttp_find_header(in_hdrs, "Upgrade");
	if (upgrade == NULL || strcmp(upgrade, "websocket"))
		goto error;

	connection = evhttp_find_header(in_hdrs, "Connection");
	if (connection == NULL || strcmp(connection, "Upgrade"))
		goto error;

	ws_key = evhttp_find_header(in_hdrs, "Sec-WebSocket-Key");
	if (ws_key == NULL)
		goto error;

	out_hdrs = evhttp_request_get_output_headers(req);
	evhttp_add_header(out_hdrs, "Upgrade", "websocket");
	evhttp_add_header(out_hdrs, "Connection", "Upgrade");

	evhttp_add_header(out_hdrs, "Sec-WebSocket-Accept",
		ws_gen_accept_key(ws_key, (char[32]){0}));

	ws_protocol = evhttp_find_header(in_hdrs, "Sec-WebSocket-Protocol");
	if (ws_protocol != NULL)
		evhttp_add_header(out_hdrs, "Sec-WebSocket-Protocol", ws_protocol);

	if ((evws = mm_calloc(1, sizeof(struct evws_connection))) == NULL) {
		event_warn("%s: calloc failed", __func__);
		goto error;
	}

	evws->cb = cb;
	evws->cb_arg = arg;

	evcon = evhttp_request_get_connection(req);
	evws->http_server = evcon->http_server;

	evws->bufev = evhttp_start_ws_(req);
	bufferevent_setcb(
		evws->bufev, ws_evhttp_read_cb, NULL, ws_evhttp_error_cb, evws);

	TAILQ_INSERT_TAIL(&evws->http_server->ws_sessions, evws, next);
	evws->http_server->connection_cnt++;

	return evws;

error:
	evhttp_send_reply(req, HTTP_BADREQUEST, NULL, NULL);
	return NULL;
}

static void
make_ws_frame(struct evbuffer *output, enum WebSocketFrameType frame_type,
	unsigned char *msg, int len)
{
	int pos = 0;
	unsigned char header[16] = {0};

	header[pos++] = (unsigned char)frame_type;
	if (len <= 125) {
		header[pos++] = len;
	} else if (len <= 65535) {
		header[pos++] = 126;			   /* 16 bit length */
		header[pos++] = (len >> 8) & 0xFF; /* rightmost first */
		header[pos++] = len & 0xFF;
	} else {				 /* >2^16-1 */
		header[pos++] = 127; /* 64 bit length */

		pos += 8;
	}
	evbuffer_add(output, header, pos);
	evbuffer_add(output, msg, len);
}

void
evws_send(struct evws_connection *evws, const char *packet_str, size_t str_len)
{
	struct evbuffer *output = bufferevent_get_output(evws->bufev);

	make_ws_frame(output, TEXT_FRAME, (unsigned char *)packet_str, str_len);
}

void
evws_connection_set_closecb(struct evws_connection *evws,
	void (*cb)(struct evws_connection *, void *), void *cbarg)
{
	evws->closecb = cb;
	evws->cbclose_arg = cbarg;
}

struct bufferevent *
evws_connection_get_bufferevent(struct evws_connection *evws)
{
	return evws->bufev;
}
