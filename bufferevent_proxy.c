/*
 * Copyright (c) 2009-2012 Niels Provos, Nick Mathewson
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


#include "event2/event-config.h"
#include "evconfig-private.h"

#include <sys/types.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "event2/util.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/event.h"
#include "defer-internal.h"
#include "bufferevent-internal.h"
#include "mm-internal.h"
#include "util-internal.h"

enum bufferevent_proxy_type {
	BUFFEREVENT_PROXY_NONE,
	BUFFEREVENT_PROXY_HTTPS,
	BUFFEREVENT_PROXY_SOCKS5
};

static int
request_socks5_target(struct bufferevent *bev)
{
	uint32_t lenght = 0;
	uint32_t itr = 0;
	unsigned char msg[512] = {0};
	uint8_t is_domain = 0, ret = 0;
	struct sockaddr_in addr; // just support ipv4, ipv6 next...
	int dn_size = 0;

	do {
		if (!bev->proxy_target_address)
			break;
		if (!evutil_inet_pton(
				AF_INET, bev->proxy_target_address, &addr.sin_addr))
			is_domain = 1;
		dn_size = strlen(bev->proxy_target_address);
		// max 255, ref:https://www.rfc-editor.org/rfc/rfc2821
		if (dn_size > 255)
			break;
		msg[0] = 0x05;
		msg[1] = 0x01;
		msg[2] = 0x00;
		if (is_domain) {
			msg[3] = 0x03;
			msg[4] = (unsigned char)dn_size;
			for (itr = 0; itr != msg[4]; ++itr)
				msg[itr + 5] = bev->proxy_target_address[itr];
			*(unsigned short *)(msg + 5 + dn_size) =
				htons(bev->proxy_target_port);
			lenght = 5 + dn_size + 2;
		} else {
			msg[3] = 0x01;
			memcpy((unsigned char *)msg + 4, (unsigned char *)&addr.sin_addr,
				sizeof(addr.sin_addr));
			*(unsigned short *)(msg + 8) = htons(bev->proxy_target_port);
			lenght = 10;
		}
		ret = 1;
	} while (0);
	if (ret)
		bufferevent_write(bev, msg, lenght);
	return 0;
}

static int
bufferevent_proxy_request_httpconnect(struct bufferevent *bev)
{
	char buf_conn[512] = "";
	int ret = -1;

	snprintf(buf_conn, sizeof(buf_conn),
		"CONNECT %s:%d HTTP/1.0\r\nHost: "
		"%s:%d\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n",
		bev->proxy_target_address, bev->proxy_target_port, bev->proxy_address,
		bev->proxy_port);
	bufferevent_write(bev, buf_conn, strlen(buf_conn));
	ret = 0;
	return ret;
}

static void
restore_request_callback(struct bufferevent *bev)
{
	if (bev->proxy_ssltunnel) {
		struct bufferevent *bevOrig = bev->cbarg;
		bev->readcb = NULL; // reset bridge bev
		bufferevent_disable(bev, EV_READ | EV_TIMEOUT | EV_CLOSED);
		// var modify singal, do_handshake(bev_ssl) while run...
		bevOrig->proxycb = NULL;
	} else {
		bev->readcb = bev->proxy_orig_readcb;
		bev->errorcb = bev->proxy_orig_errorcb;
		bev->errorcb(bev, BEV_EVENT_CONNECTED, bev->cbarg); // trig orig
	}
}

static int
read_socks5_reponse(struct bufferevent *bev, uint8_t *data, int size)
{
	int ret = -1;
	unsigned char method = data[1];
	do {
		if (2 == size && !memcmp(data, "\x05\x00", 2)) {
			// socks5 noauth step1;
			// Accepted Auth Method: 0x0 (No authentication)
			if (request_socks5_target(bev))
				break;
			ret = 0;
		} else if (size >= 10 && size <= 22 && !memcmp(data, "\x05\x00", 2)) {
			// socks5 noauth step2;
			// Version: 5
			// Results(V5): Succeeded (0)
			// Reserved: 0
			// Address Type: IPv4 (1)
			// Remote Address: 0.0.0.0
			// Port: 0
			restore_request_callback(bev);
			ret = 0;
			break;
		} else if (method == 0x01)
			break;
		else if (method == 0x02) {
			// not support auth with name-password
			break;
		} else if (method >= 0x03 && method <= 0x7F)
			break;
		else if (method >= 0x80 && method <= 0xFE)
			break;
		else
			break;
	} while (0);
	return ret;
}

static void
bufferevent_proxy_read_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *input;
	size_t len;
	unsigned char *read_data = NULL;

	do {
		input = bufferevent_get_input(bev);
		len = evbuffer_get_length(input);
		read_data = evbuffer_pullup(input, len);
		if (BUFFEREVENT_PROXY_SOCKS5 == bev->proxy_type) {
			if (len < 2 || 0x5 != read_data[0])
				break;
			if (read_socks5_reponse(bev, read_data, len))
				break;
		} else if (BUFFEREVENT_PROXY_HTTPS == bev->proxy_type) {
			if (strncmp((const char *)read_data, "HTTP/", 5))
				break;
			if (!strstr((const char *)read_data, "HTTP/1.1 200 ") &&
				!strstr((const char *)read_data, "HTTP/1.0 200 "))
				break;
			restore_request_callback(bev);
		}
		evbuffer_drain(input, len);
	} while (0);
}

static void
bufferevent_proxy_errnocb(struct bufferevent *bufev, short what, void *arg)
{
	// todo
	if (what & BEV_EVENT_EOF) {
	} else if (what & BEV_EVENT_TIMEOUT) {
	} else if (what & BEV_EVENT_ERROR) {
	} else if (what & BEV_EVENT_CONNECTED) {
	} else {
	}
}

static void
bufferevent_proxy_prehandshake_cb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *bufev = NULL;
	if (!strcmp(bev->be_ops->type, "ssl")) {
		bufev = bufferevent_socket_new(
			bev->ev_base, bufferevent_getfd(bev), BEV_OPT_CLOSE_ON_FREE);
		if (!bufev)
			return;
		bufev->proxy_type = bev->proxy_type;
		if (!(bufev->proxy_target_address =
					mm_strdup(bev->proxy_target_address)))
			return;
		bufev->proxy_target_port = bev->proxy_target_port;
		bufev->readcb = bufferevent_proxy_read_cb;
		bufev->cbarg = bev; // orig bev
		bufev->proxy_ssltunnel = 1;
	} else {
		bufev = bev;
		bufev->proxy_orig_errorcb = bufev->errorcb;
		bufev->errorcb = bufferevent_proxy_errnocb;
		bufev->proxy_orig_readcb = bufev->readcb;
		bufev->readcb = bufferevent_proxy_read_cb;
		bufev->proxy_ssltunnel = 0;
	}
	bufferevent_enable(bufev, EV_READ | EV_TIMEOUT | EV_CLOSED);
	if (1 == bufev->proxy_type) {
		if (bufferevent_proxy_request_httpconnect(bufev))
			return;
	} else if (2 == bufev->proxy_type) {
		bufferevent_write(bufev, "\x05\x01\x00", 3);
	}
}

int
bufferevent_set_proxy(struct bufferevent *bev, ev_uint8_t proxy_type,
	const char *proxy_host, ev_uint16_t proxy_port, const char *auth_user,
	const char *auth_pwd)
{
	int ret = -1;

	do {
		// auth_user\auth_pwd ignore now
		if (1 != proxy_type && 2 != proxy_type) {
			event_errx(1, "proxy type check failed");
			break;
		}
		if (!proxy_host || strlen(proxy_host) > 255) {
			event_errx(1, "proxy host check failed");
			break;
		}
		if (!auth_user || strlen(auth_user) > 255 || !auth_pwd ||
			strlen(auth_pwd) > 255) {
			event_errx(1, "proxy user/password check failed");
			break;
		}
		if (bev->proxy_address) {
			mm_free(bev->proxy_address);
			bev->proxy_address = NULL;
		}
		if (!(bev->proxy_address = mm_strdup(proxy_host)))
			break;
		bev->proxy_port = proxy_port;
		bev->proxy_type = proxy_type;
		bev->proxycb = bufferevent_proxy_prehandshake_cb;

		ret = 0;
	} while (0);
	return ret;
}