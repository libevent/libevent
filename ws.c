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

struct evws_connection {
	TAILQ_ENTRY(evws_connection) next;

	struct bufferevent *bufev;

	void (*cb)(struct evws_connection *, char *, size_t, void *);
	void *cb_arg;

	void (*closecb)(struct evws_connection *, void *);
	void *cbclose_arg;

	unsigned char *recv_data;
	size_t recv_len;
	size_t recv_cap;

	/* for server connections, the http server they are connected with */
	struct evhttp *http_server;

	bool closed;
};

#define WS_RECV_BUFFER_SIZE 4096

enum WebSocketFrameType {
	ERROR_FRAME = 0xFF00,
	INCOMPLETE_FRAME = 0xFE00,

	OPENING_FRAME = 0x3300,
	CLOSING_FRAME = 0x3400,

	INCOMPLETE_TEXT_FRAME = 0x01,
	INCOMPLETE_BINARY_FRAME = 0x02,

	TEXT_FRAME = 0x81,
	BINARY_FRAME = 0x82,

	PING_FRAME = 0x19,
	PONG_FRAME = 0x1A
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

	if (evws->recv_data)
		free(evws->recv_data);

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

	snprintf(
		buf, sizeof(buf), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws_key);

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
	bufferevent_setcb(evws->bufev, NULL, close_after_write_cb, close_event_cb, evws);
}

static void
evws_force_disconnect_(struct evws_connection *evws)
{
	evws_close(evws, WS_CR_NONE);
}

static enum WebSocketFrameType
ws_get_frame(unsigned char *in_buffer, int in_length, unsigned char *out_buffer,
	int out_size, int *out_length)
{
	unsigned char msg_opcode;
	unsigned char msg_fin;
	unsigned char msg_masked;
	int payload_length;
	int pos;
	int length_field;
	unsigned int mask;

	if (in_length < 3) {
		return INCOMPLETE_FRAME;
	}

	msg_opcode = in_buffer[0] & 0x0F;
	msg_fin = (in_buffer[0] >> 7) & 0x01;
	msg_masked = (in_buffer[1] >> 7) & 0x01;

	payload_length = 0;
	pos = 2;
	length_field = in_buffer[1] & (~0x80);
	mask = 0;

	if (length_field <= 125) {
		payload_length = length_field;
	} else if (length_field == 126) { /* msglen is 16bit */
		payload_length = ntohs(*(uint16_t *)(in_buffer + 2));
		pos += 2;
	} else if (length_field == 127) { /* msglen is 64bit */
		payload_length = ntohs(*(uint64_t *)(in_buffer + 2));
		pos += 8;
	}
	if (in_length < payload_length + pos) {
		return INCOMPLETE_FRAME;
	}

	if (msg_masked) {
		unsigned char *c;

		mask = *((unsigned int *)(in_buffer + pos));
		pos += 4;

		/* unmask data */
		c = in_buffer + pos;
		for (int i = 0; i < payload_length; i++) {
			c[i] = c[i] ^ ((unsigned char *)(&mask))[i % 4];
		}
	}

	assert(payload_length <= out_size);

	memcpy((void *)out_buffer, (void *)(in_buffer + pos), payload_length);
	out_buffer[payload_length] = 0;
	*out_length = payload_length;

	switch (msg_opcode) {
	case 0x0:
		return msg_fin ? TEXT_FRAME : INCOMPLETE_TEXT_FRAME;
	case 0x1:
		return msg_fin ? TEXT_FRAME : INCOMPLETE_TEXT_FRAME;
	case 0x2:
		return msg_fin ? BINARY_FRAME : INCOMPLETE_BINARY_FRAME;
	case 0x9:
		return PING_FRAME;
	case 0xA:
		return PONG_FRAME;
	default:
		return ERROR_FRAME;
	}
}


static void
ws_evhttp_read_cb(struct bufferevent *bufev, void *arg)
{
	struct evws_connection *evws = arg;
	unsigned char msg_buf[WS_RECV_BUFFER_SIZE] = {0};
	enum WebSocketFrameType type;

	struct evbuffer *input = bufferevent_get_input(evws->bufev);
	int len = evbuffer_get_length(input);

	if (evws->recv_cap < evws->recv_len + len) {
		evws->recv_cap = evws->recv_len + len;
		evws->recv_data = realloc(evws->recv_data, evws->recv_cap);
	}
	evbuffer_remove(input, evws->recv_data + evws->recv_len, len);
	evws->recv_len += len;

	if (evws->recv_len > WS_RECV_BUFFER_SIZE) {
		event_warn("%s: exceed the max recv buffer size %ld\n", __func__,
			evws->recv_len);
		evws_force_disconnect_(evws);
		return;
	}

	type = ws_get_frame(
		evws->recv_data, evws->recv_len, msg_buf, sizeof(msg_buf), &len);

	if (type == TEXT_FRAME) {
		if (evws->cb)
			evws->cb(evws, (char *)msg_buf, len, evws->cb_arg);
		evws->recv_len = 0;
	} else if (type == INCOMPLETE_TEXT_FRAME || type == INCOMPLETE_FRAME) {
		/* incomplete frame received, wait for next chunk */
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
evws_new_session(struct evhttp_request *req,
	void (*cb)(struct evws_connection *, char *, size_t, void *), void *arg)
{
	struct evws_connection *evws = NULL;
	struct evkeyvalq *headers;
	const char *upgrade, *connection, *ws_key, *ws_protocol;
	struct evkeyvalq *output;
	struct evhttp_connection *evcon;

	headers = evhttp_request_get_input_headers(req);
	upgrade = evhttp_find_header(headers, "Upgrade");
	if (upgrade == NULL || strcmp(upgrade, "websocket"))
		goto error;

	connection = evhttp_find_header(headers, "Connection");
	if (connection == NULL || strcmp(connection, "Upgrade"))
		goto error;

	ws_key = evhttp_find_header(headers, "Sec-WebSocket-Key");
	if (ws_key == NULL)
		goto error;

	output = evhttp_request_get_output_headers(req);
	evhttp_add_header(output, "Upgrade", "websocket");
	evhttp_add_header(output, "Connection", "Upgrade");

	evhttp_add_header(output, "Sec-WebSocket-Accept",
		ws_gen_accept_key(ws_key, (char[32]){0}));

	ws_protocol = evhttp_find_header(headers, "Sec-WebSocket-Protocol");
	if (ws_protocol != NULL)
		evhttp_add_header(output, "Sec-WebSocket-Protocol", ws_protocol);

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

static int
ws_make_frame(enum WebSocketFrameType frame_type, unsigned char *msg,
	int msg_length, unsigned char *buffer, int buffer_size)
{
	int pos = 0;
	int size = msg_length;
	buffer[pos++] = (unsigned char)frame_type; /* text frame */

	if (size <= 125) {
		buffer[pos++] = size;
	} else if (size <= 65535) {
		buffer[pos++] = 126;				/* 16 bit length */
		buffer[pos++] = (size >> 8) & 0xFF; /* rightmost first */
		buffer[pos++] = size & 0xFF;
	} else {				 /* >2^16-1 */
		buffer[pos++] = 127; /* 64 bit length */

		pos += 8;
	}
	memcpy((void *)(buffer + pos), msg, size);
	return (size + pos);
}


void
evws_send(struct evws_connection *evws, const char *packet_str, size_t str_len)
{
	unsigned char frame[WS_RECV_BUFFER_SIZE] = {0};
	struct evbuffer *output;
	int len;

	len = ws_make_frame(
		TEXT_FRAME, (unsigned char *)packet_str, str_len, frame, sizeof(frame));
	if (len <= 0) {
		event_warn("%s: make websocket frame failed", __func__);
		return;
	}
	output = bufferevent_get_output(evws->bufev);
	evbuffer_add(output, frame, len);
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
