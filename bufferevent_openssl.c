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

#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "openssl-compat.h"

#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/buffer.h"

#include "ssl-compat.h"

/*
 * Define an OpenSSL bio that targets a bufferevent.
 */

/* --------------------
   A BIO is an OpenSSL abstraction that handles reading and writing data.  The
   library will happily speak SSL over anything that implements a BIO
   interface.

   Here we define a BIO implementation that directs its output to a
   bufferevent.  We'll want to use this only when none of OpenSSL's built-in
   IO mechanisms work for us.
   -------------------- */

/* every BIO type needs its own integer type value. */
#define BIO_TYPE_LIBEVENT 57
/* ???? Arguably, we should set BIO_TYPE_FILTER or BIO_TYPE_SOURCE_SINK on
 * this. */

#if 0
static void
print_err(int val)
{
	int err;
	printf("Error was %d\n", val);

	while ((err = ERR_get_error())) {
		const char *msg = (const char*)ERR_reason_error_string(err);
		const char *lib = (const char*)ERR_lib_error_string(err);
		const char *func = (const char*)ERR_func_error_string(err);

		printf("%s in %s %s\n", msg, lib, func);
	}
}
#else
static void
print_err(int val)
{
}
#endif

/* Called to initialize a new BIO */
static int
bio_bufferevent_new(BIO *b)
{
	BIO_set_init(b, 0);
	BIO_set_data(b, NULL); /* We'll be putting the bufferevent in this field.*/
	return 1;
}

/* Called to uninitialize the BIO. */
static int
bio_bufferevent_free(BIO *b)
{
	if (!b)
		return 0;
	if (BIO_get_shutdown(b)) {
		if (BIO_get_init(b) && BIO_get_data(b))
			bufferevent_free(BIO_get_data(b));
		BIO_free(b);
	}
	return 1;
}

/* Called to extract data from the BIO. */
static int
bio_bufferevent_read(BIO *b, char *out, int outlen)
{
	int r = 0;
	struct evbuffer *input;

	BIO_clear_retry_flags(b);

	if (!out)
		return 0;
	if (!BIO_get_data(b))
		return -1;

	input = bufferevent_get_input(BIO_get_data(b));
	if (evbuffer_get_length(input) == 0) {
		/* If there's no data to read, say so. */
		BIO_set_retry_read(b);
		return -1;
	} else {
		r = evbuffer_remove(input, out, outlen);
	}

	return r;
}

/* Called to write data into the BIO */
static int
bio_bufferevent_write(BIO *b, const char *in, int inlen)
{
	struct bufferevent *bufev = BIO_get_data(b);
	struct evbuffer *output;
	size_t outlen;

	BIO_clear_retry_flags(b);

	if (!BIO_get_data(b))
		return -1;

	output = bufferevent_get_output(bufev);
	outlen = evbuffer_get_length(output);

	/* Copy only as much data onto the output buffer as can fit under the
	 * high-water mark. */
	if (bufev->wm_write.high && bufev->wm_write.high <= (outlen + inlen)) {
		if (bufev->wm_write.high <= outlen) {
			/* If no data can fit, we'll need to retry later. */
			BIO_set_retry_write(b);
			return -1;
		}
		inlen = bufev->wm_write.high - outlen;
	}

	EVUTIL_ASSERT(inlen > 0);
	evbuffer_add(output, in, inlen);
	return inlen;
}

/* Called to handle various requests */
static long
bio_bufferevent_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	struct bufferevent *bufev = BIO_get_data(b);
	long ret = 1;

	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
		ret = BIO_get_shutdown(b);
		break;
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(b, (int)num);
		break;
	case BIO_CTRL_PENDING:
		ret = evbuffer_get_length(bufferevent_get_input(bufev)) != 0;
		break;
	case BIO_CTRL_WPENDING:
		ret = evbuffer_get_length(bufferevent_get_output(bufev)) != 0;
		break;
	/* XXXX These two are given a special-case treatment because
	 * of cargo-cultism.  I should come up with a better reason. */
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret = 1;
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}

/* Called to write a string to the BIO */
static int
bio_bufferevent_puts(BIO *b, const char *s)
{
	return bio_bufferevent_write(b, s, strlen(s));
}

/* Method table for the bufferevent BIO */
static BIO_METHOD *methods_bufferevent;

/* Return the method table for the bufferevents BIO */
static BIO_METHOD *
BIO_s_bufferevent(void)
{
	if (methods_bufferevent == NULL) {
		methods_bufferevent = BIO_meth_new(BIO_TYPE_LIBEVENT, "bufferevent");
		if (methods_bufferevent == NULL)
			return NULL;
		BIO_meth_set_write(methods_bufferevent, bio_bufferevent_write);
		BIO_meth_set_read(methods_bufferevent, bio_bufferevent_read);
		BIO_meth_set_puts(methods_bufferevent, bio_bufferevent_puts);
		BIO_meth_set_ctrl(methods_bufferevent, bio_bufferevent_ctrl);
		BIO_meth_set_create(methods_bufferevent, bio_bufferevent_new);
		BIO_meth_set_destroy(methods_bufferevent, bio_bufferevent_free);
	}
	return methods_bufferevent;
}

/* Create a new BIO to wrap communication around a bufferevent.  If close_flag
 * is true, the bufferevent will be freed when the BIO is closed. */
static BIO *
BIO_new_bufferevent(struct bufferevent *bufferevent)
{
	BIO *result;
	if (!bufferevent)
		return NULL;
	if (!(result = BIO_new(BIO_s_bufferevent())))
		return NULL;
	BIO_set_init(result, 1);
	BIO_set_data(result, bufferevent);
	/* We don't tell the BIO to close the bufferevent; we do it ourselves on
	 * be_openssl_destruct() */
	BIO_set_shutdown(result, 0);
	return result;
}

static void
conn_closed(struct bufferevent_ssl *bev_ssl, int when, int errcode, int ret)
{
	int event = BEV_EVENT_ERROR;
	int dirty_shutdown = 0;
	unsigned long err;

	switch (errcode) {
	case SSL_ERROR_ZERO_RETURN:
		/* Possibly a clean shutdown. */
		if (SSL_get_shutdown(bev_ssl->ssl) & SSL_RECEIVED_SHUTDOWN)
			event = BEV_EVENT_EOF;
		else
			dirty_shutdown = 1;
		break;
	case SSL_ERROR_SYSCALL:
		/* IO error; possibly a dirty shutdown. */
		if ((ret == 0 || ret == -1) && ERR_peek_error() == 0)
			dirty_shutdown = 1;
		bufferevent_ssl_put_error(bev_ssl, errcode);
		break;
	case SSL_ERROR_SSL:
		/* Protocol error; possibly a dirty shutdown. */
		if (ret == 0 && SSL_is_init_finished(bev_ssl->ssl) == 0)
			dirty_shutdown = 1;
		bufferevent_ssl_put_error(bev_ssl, errcode);
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		/* XXXX handle this. */
		bufferevent_ssl_put_error(bev_ssl, errcode);
		break;
	case SSL_ERROR_NONE:
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	default:
		/* should be impossible; treat as normal error. */
		event_warnx("BUG: Unexpected OpenSSL error code %d", errcode);
		break;
	}

	while ((err = ERR_get_error())) {
		bufferevent_ssl_put_error(bev_ssl, err);
	}

	if (dirty_shutdown && bev_ssl->flags & BUFFEREVENT_SSL_DIRTY_SHUTDOWN)
		event = BEV_EVENT_EOF;

	bufferevent_ssl_stop_reading(bev_ssl);
	bufferevent_ssl_stop_writing(bev_ssl);

	/* when is BEV_EVENT_{READING|WRITING} */
	event = when | event;
	bufferevent_run_eventcb_(&bev_ssl->bev.bev, event, 0);
}

static void
init_bio_counts(struct bufferevent_ssl *bev_ssl)
{
	BIO *rbio, *wbio;

	wbio = SSL_get_wbio(bev_ssl->ssl);
	bev_ssl->counts.n_written = wbio ? BIO_number_written(wbio) : 0;
	rbio = SSL_get_rbio(bev_ssl->ssl);
	bev_ssl->counts.n_read = rbio ? BIO_number_read(rbio) : 0;
}

static inline void
decrement_buckets(struct bufferevent_ssl *bev_ssl)
{
	unsigned long num_w = BIO_number_written(SSL_get_wbio(bev_ssl->ssl));
	unsigned long num_r = BIO_number_read(SSL_get_rbio(bev_ssl->ssl));
	/* These next two subtractions can wrap around. That's okay. */
	unsigned long w = num_w - bev_ssl->counts.n_written;
	unsigned long r = num_r - bev_ssl->counts.n_read;
	if (w)
		bufferevent_decrement_write_buckets_(&bev_ssl->bev, w);
	if (r)
		bufferevent_decrement_read_buckets_(&bev_ssl->bev, r);
	bev_ssl->counts.n_written = num_w;
	bev_ssl->counts.n_read = num_r;
}

static void *
SSL_init(void *ssl)
{
	/* Don't explode if we decide to realloc a chunk we're writing from in
	 * the output buffer. */
	SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	return ssl;
}

static void
SSL_context_free(void *ssl, int flags)
{
	if (flags & BEV_OPT_CLOSE_ON_FREE)
		SSL_free(ssl);
}

static int
SSL_handshake_is_ok(int err)
{
	/* What SSL_do_handshake() return on success */
	return err == 1;
}

static int
SSL_is_want_read(int err)
{
	return err == SSL_ERROR_WANT_READ;
}

static int
SSL_is_want_write(int err)
{
	return err == SSL_ERROR_WANT_WRITE;
}

static int
openssl_read(void *ssl, unsigned char *buf, size_t len)
{
	return SSL_read(ssl, buf, len);
}

static int
openssl_write(void *ssl, const unsigned char *buf, size_t len)
{
	return SSL_write(ssl, buf, len);
}

static evutil_socket_t
be_openssl_get_fd(struct bufferevent_ssl *bev_ssl)
{
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	BIO *bio = SSL_get_wbio(bev_ssl->ssl);
	if (bio)
		fd = BIO_get_fd(bio, NULL);
	return fd;
}

static int
be_openssl_bio_set_fd(struct bufferevent_ssl *bev_ssl, evutil_socket_t fd)
{
	if (!bev_ssl->underlying) {
		BIO *bio;
		bio = BIO_new_socket((int)fd, 0);
		SSL_set_bio(bev_ssl->ssl, bio, bio);
	} else {
		BIO *bio;
		if (!(bio = BIO_new_bufferevent(bev_ssl->underlying)))
			return -1;
		SSL_set_bio(bev_ssl->ssl, bio, bio);
	}
	return 0;
}

static size_t SSL_pending_wrap(void *ssl)
{
	return SSL_pending(ssl);
}

static struct le_ssl_ops le_openssl_ops = {
	SSL_init,
	SSL_context_free,
	(void (*)(void *))SSL_free,
	(int (*)(void *))SSL_renegotiate,
	openssl_write,
	openssl_read,
	SSL_pending_wrap,
	(int (*)(void *))SSL_do_handshake,
	(int (*)(void *, int))SSL_get_error,
	ERR_clear_error,
	(int (*)(void *))SSL_clear,
	(void (*)(void *))SSL_set_connect_state,
	(void (*)(void *))SSL_set_accept_state,
	SSL_handshake_is_ok,
	SSL_is_want_read,
	SSL_is_want_write,
	(int (*)(void *))be_openssl_get_fd,
	be_openssl_bio_set_fd,
	init_bio_counts,
	decrement_buckets,
	conn_closed,
	print_err,
};

struct bufferevent *
bufferevent_openssl_filter_new(struct event_base *base,
    struct bufferevent *underlying,
    SSL *ssl,
    enum bufferevent_ssl_state state,
    int options)
{
	BIO *bio;
	struct bufferevent *bev;

	if (!underlying)
		goto err;
	if (!(bio = BIO_new_bufferevent(underlying)))
		goto err;

	SSL_set_bio(ssl, bio, bio);

	bev = bufferevent_ssl_new_impl(
		base, underlying, -1, ssl, state, options, &le_openssl_ops);
	return bev;

err:
	if (options & BEV_OPT_CLOSE_ON_FREE)
		SSL_free(ssl);
	return NULL;
}

struct bufferevent *
bufferevent_openssl_socket_new(struct event_base *base,
    evutil_socket_t fd,
    SSL *ssl,
    enum bufferevent_ssl_state state,
    int options)
{
	/* Does the SSL already have an fd? */
	BIO *bio = SSL_get_wbio(ssl);
	long have_fd = -1;

	if (bio)
		have_fd = BIO_get_fd(bio, NULL);

	if (have_fd >= 0) {
		/* The SSL is already configured with an fd. */
		if (fd < 0) {
			/* We should learn the fd from the SSL. */
			fd = (evutil_socket_t) have_fd;
		} else if (have_fd == (long)fd) {
			/* We already know the fd from the SSL; do nothing */
		} else {
			/* We specified an fd different from that of the SSL.
			   This is probably an error on our part.  Fail. */
			goto err;
		}
		(void)BIO_set_close(bio, 0);
	} else {
		/* The SSL isn't configured with a BIO with an fd. */
		if (fd >= 0) {
			/* ... and we have an fd we want to use. */
			bio = BIO_new_socket((int)fd, 0);
			SSL_set_bio(ssl, bio, bio);
		} else {
			/* Leave the fd unset. */
		}
	}

	return bufferevent_ssl_new_impl(
		base, NULL, fd, ssl, state, options, &le_openssl_ops);

err:
	if (options & BEV_OPT_CLOSE_ON_FREE)
		SSL_free(ssl);
	return NULL;
}

int
bufferevent_ssl_renegotiate(struct bufferevent *bev)
{
	return bufferevent_ssl_renegotiate_impl(bev);
}

SSL *
bufferevent_openssl_get_ssl(struct bufferevent *bufev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bufev);
	if (!bev_ssl)
		return NULL;
	return bev_ssl->ssl;
}

int
bufferevent_openssl_get_allow_dirty_shutdown(struct bufferevent *bev)
{
	return bufferevent_ssl_get_allow_dirty_shutdown(bev);
}

void
bufferevent_openssl_set_allow_dirty_shutdown(
	struct bufferevent *bev, int allow_dirty_shutdown)
{
	bufferevent_ssl_set_allow_dirty_shutdown(bev, allow_dirty_shutdown);
}

unsigned long
bufferevent_get_openssl_error(struct bufferevent *bufev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bufev);
	if (!bev_ssl)
		return 0;
	return bufferevent_get_ssl_error(bufev);
}
