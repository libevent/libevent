/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
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


/* Mbed-TLS 3.x does not currently expose a function to retrieve
   the bio parameters from the SSL object. When the above issue has been
   fixed, remove the MBEDTLS_ALLOW_PRIVATE_ACCESS define and use the
   appropriate getter function in bufferevent_mbedtls_socket_new rather than
   accessing the struct fields directly. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls-compat.h"
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

#include "event2/util.h"
#include "util-internal.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/bufferevent_ssl.h"

#include "ssl-compat.h"
#include "mm-internal.h"

struct mbedtls_context {
	mbedtls_dyncontext *ssl;
	mbedtls_net_context net;
};
static void *
mbedtls_context_init(void *ssl)
{
	struct mbedtls_context *ctx = mm_malloc(sizeof(*ctx));
	if (ctx) {
		ctx->ssl = ssl;
		ctx->net.fd = -1;
	}
	return ctx;
}
static void
mbedtls_context_free(void *ssl, int flags)
{
	struct mbedtls_context *ctx = ssl;
	if (flags & BEV_OPT_CLOSE_ON_FREE)
		bufferevent_mbedtls_dyncontext_free(ctx->ssl);
	mm_free(ctx);
}
static int
mbedtls_context_renegotiate(void *ssl)
{
#ifdef MBEDTLS_SSL_RENEGOTIATION
	struct mbedtls_context *ctx = ssl;
	return mbedtls_ssl_renegotiate(ctx->ssl);
#else
	return MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE;
#endif
}
static int
mbedtls_context_write(void *ssl, const unsigned char *buf, size_t len)
{
	struct mbedtls_context *ctx = ssl;
	return mbedtls_ssl_write(ctx->ssl, buf, len);
}
static int
mbedtls_context_read(void *ssl, unsigned char *buf, size_t len)
{
	struct mbedtls_context *ctx = ssl;
	return mbedtls_ssl_read(ctx->ssl, buf, len);
}
static size_t
mbedtls_context_pending(void *ssl)
{
	struct mbedtls_context *ctx = ssl;
	return mbedtls_ssl_get_bytes_avail(ctx->ssl);
}
static int
mbedtls_context_handshake(void *ssl)
{
	struct mbedtls_context *ctx = ssl;
	return mbedtls_ssl_handshake(ctx->ssl);
}
static int
mbedtls_get_error(void *ssl, int ret)
{
	return ret;
}
static void
mbedtls_clear_error(void)
{
}
static int
mbedtls_clear(void *ssl)
{
	return 1;
}
static void
mbedtls_set_ssl_noops(void *ssl)
{
}
static int
mbedtls_handshake_is_ok(int err)
{
	/* What mbedtls_ssl_handshake() return on success */
	return err == 0;
}
static int
mbedtls_is_want_read(int err)
{
	return err == MBEDTLS_ERR_SSL_WANT_READ;
}
static int
mbedtls_is_want_write(int err)
{
	return err == MBEDTLS_ERR_SSL_WANT_WRITE;
}

static evutil_socket_t
be_mbedtls_get_fd(void *ssl)
{
	struct bufferevent_ssl *bev = ssl;
	struct mbedtls_context *ctx = bev->ssl;
	return ctx->net.fd;
}

static int be_mbedtls_bio_set_fd(
	struct bufferevent_ssl *bev_ssl, evutil_socket_t fd);

#if 0
static void
print_err(int val)
{
	char buf[1024];
	mbedtls_strerror(val, buf, sizeof(buf));
	printf("Error was %d:%s\n", val, buf);
}
#else
static void
print_err(int val)
{
}
#endif

/* Called to extract data from the BIO. */
static int
bio_bufferevent_read(void *ctx, unsigned char *out, size_t outlen)
{
	struct bufferevent *bufev = (struct bufferevent *)ctx;
	int r = 0;
	struct evbuffer *input;

	if (!out)
		return 0;
	if (!bufev)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	input = bufferevent_get_input(bufev);
	if (evbuffer_get_length(input) == 0) {
		/* If there's no data to read, say so. */
		return MBEDTLS_ERR_SSL_WANT_READ;
	} else {
		r = evbuffer_remove(input, out, outlen);
	}

	return r;
}

/* Called to write data into the BIO */
static int
bio_bufferevent_write(void *ctx, const unsigned char *in, size_t inlen)
{
	struct bufferevent *bufev = (struct bufferevent *)ctx;
	struct evbuffer *output;
	size_t outlen;

	if (!bufev)
		return MBEDTLS_ERR_NET_INVALID_CONTEXT;

	output = bufferevent_get_output(bufev);
	outlen = evbuffer_get_length(output);

	/* Copy only as much data onto the output buffer as can fit under the
	 * high-water mark. */
	if (bufev->wm_write.high && bufev->wm_write.high <= (outlen + inlen)) {
		if (bufev->wm_write.high <= outlen) {
			/* If no data can fit, we'll need to retry later. */
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
		inlen = bufev->wm_write.high - outlen;
	}

	EVUTIL_ASSERT(inlen > 0);
	evbuffer_add(output, in, inlen);
	return inlen;
}

static void
conn_closed(struct bufferevent_ssl *bev_ssl, int when, int errcode, int ret)
{
	int event = BEV_EVENT_ERROR;
	char buf[100];

	if (when & BEV_EVENT_READING && ret == 0) {
		if (bev_ssl->flags & BUFFEREVENT_SSL_DIRTY_SHUTDOWN)
			event = BEV_EVENT_EOF;
	} else {
		mbedtls_strerror(errcode, buf, sizeof(buf));
		switch (errcode) {
		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			event = BEV_EVENT_EOF;
			break;
		case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
			event_warnx("BUG: Unsupported feature %d: %s", errcode, buf);
			break;
		default:
			/* should be impossible; treat as normal error. */
			event_warnx(
				"BUG: Unexpected mbedtls error code %d: %s", errcode, buf);
			break;
		}

		bufferevent_ssl_put_error(bev_ssl, errcode);
	}

	bufferevent_ssl_stop_reading(bev_ssl);
	bufferevent_ssl_stop_writing(bev_ssl);

	bufferevent_run_eventcb_(&bev_ssl->bev.bev, when | event, 0);
}

static int
be_mbedtls_bio_set_fd(struct bufferevent_ssl *bev_ssl, evutil_socket_t fd)
{
	struct mbedtls_context *ctx = bev_ssl->ssl;
	if (!bev_ssl->underlying) {
		ctx->net.fd = fd;
		mbedtls_ssl_set_bio(
			ctx->ssl, &ctx->net, mbedtls_net_send, mbedtls_net_recv, NULL);
	} else {
		mbedtls_ssl_set_bio(ctx->ssl, bev_ssl->underlying,
			bio_bufferevent_write, bio_bufferevent_read, NULL);
	}
	return 0;
}

int
bufferevent_mbedtls_get_allow_dirty_shutdown(struct bufferevent *bev)
{
	return bufferevent_ssl_get_allow_dirty_shutdown(bev);
}

void
bufferevent_mbedtls_set_allow_dirty_shutdown(
	struct bufferevent *bev, int allow_dirty_shutdown)
{
	bufferevent_ssl_set_allow_dirty_shutdown(bev, allow_dirty_shutdown);
}

mbedtls_ssl_context *
bufferevent_mbedtls_get_ssl(struct bufferevent *bufev)
{
	struct mbedtls_context *ctx = NULL;
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bufev);
	if (!bev_ssl)
		return NULL;
	ctx = bev_ssl->ssl;
	return ctx->ssl;
}

int
bufferevent_mbedtls_renegotiate(struct bufferevent *bufev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bufev);
	if (!bev_ssl)
		return -1;
	return bufferevent_ssl_renegotiate_impl(bufev);
}

unsigned long
bufferevent_get_mbedtls_error(struct bufferevent *bufev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bufev);
	if (!bev_ssl)
		return 0;
	return bufferevent_get_ssl_error(bufev);
}

static struct le_ssl_ops le_mbedtls_ops = {
	mbedtls_context_init,
	mbedtls_context_free,
	(void (*)(void *))bufferevent_mbedtls_dyncontext_free,
	mbedtls_context_renegotiate,
	mbedtls_context_write,
	mbedtls_context_read,
	mbedtls_context_pending,
	mbedtls_context_handshake,
	mbedtls_get_error,
	mbedtls_clear_error,
	mbedtls_clear,
	mbedtls_set_ssl_noops,
	mbedtls_set_ssl_noops,
	mbedtls_handshake_is_ok,
	mbedtls_is_want_read,
	mbedtls_is_want_write,
	be_mbedtls_get_fd,
	be_mbedtls_bio_set_fd,
	(void (*)(struct bufferevent_ssl *))mbedtls_set_ssl_noops,
	(void (*)(struct bufferevent_ssl *))mbedtls_set_ssl_noops,
	conn_closed,
	print_err,
};

struct bufferevent *
bufferevent_mbedtls_filter_new(struct event_base *base,
	struct bufferevent *underlying, mbedtls_ssl_context *ssl,
	enum bufferevent_ssl_state state, int options)
{
	struct bufferevent *bev;

	if (!underlying)
		goto err;

	bev = bufferevent_ssl_new_impl(
		base, underlying, -1, ssl, state, options, &le_mbedtls_ops);

	if (bev) {
		be_mbedtls_bio_set_fd(bufferevent_ssl_upcast(bev), -1);
	}

	return bev;

err:
	if (options & BEV_OPT_CLOSE_ON_FREE)
		bufferevent_mbedtls_dyncontext_free(ssl);
	return NULL;
}

struct bufferevent *
bufferevent_mbedtls_socket_new(struct event_base *base, evutil_socket_t fd,
	mbedtls_ssl_context *ssl, enum bufferevent_ssl_state state, int options)
{
	long have_fd = -1;
	struct bufferevent *bev;

	if (ssl->p_bio) {
		/* The SSL is already configured with bio. */
		if (ssl->f_send == mbedtls_net_send &&
			ssl->f_recv == mbedtls_net_recv) {
			have_fd = ((mbedtls_net_context *)ssl->p_bio)->fd;
		} else if (ssl->f_send == bio_bufferevent_write &&
				   ssl->f_recv == bio_bufferevent_read) {
			have_fd = bufferevent_getfd(ssl->p_bio);
		} else {
			/* We don't known the fd. */
			have_fd = LONG_MAX;
		}
	}

	if (have_fd >= 0) {
		if (fd < 0) {
			/* We should learn the fd from the SSL. */
			fd = (evutil_socket_t)have_fd;
		} else if (have_fd == (long)fd) {
			/* We already know the fd from the SSL; do nothing */
		} else {
			/* We specified an fd different from that of the SSL.
			   This is probably an error on our part.  Fail. */
			goto err;
		}
	} else {
		if (fd >= 0) {
			/* ... and we have an fd we want to use. */
		} else {
			/* Leave the fd unset. */
		}
	}

	bev = bufferevent_ssl_new_impl(
		base, NULL, fd, ssl, state, options, &le_mbedtls_ops);

	if (bev) {
		be_mbedtls_bio_set_fd(bufferevent_ssl_upcast(bev), fd);
	}

	return bev;
err:
	return NULL;
}

mbedtls_dyncontext *
bufferevent_mbedtls_dyncontext_new(struct mbedtls_ssl_config *conf)
{
	mbedtls_dyncontext *ctx = mm_calloc(1, sizeof(*ctx));
	mbedtls_ssl_init(ctx);
	mbedtls_ssl_setup(ctx, conf);
	return ctx;
}

void
bufferevent_mbedtls_dyncontext_free(mbedtls_dyncontext *ctx)
{
	mbedtls_ssl_free(ctx);
	mm_free(ctx);
}
