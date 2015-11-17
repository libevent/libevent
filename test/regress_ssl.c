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

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef _WIN32
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "event2/util.h"
#include "event2/event.h"
#include "event2/bufferevent_ssl.h"
#include "event2/bufferevent_struct.h"
#include "event2/buffer.h"
#include "event2/listener.h"

#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <string.h>
#include <unistd.h>

/* A short pre-generated key, to save the cost of doing an RSA key generation
 * step during the unit tests.  It's only 512 bits long, and it is published
 * in this file, so you would have to be very foolish to consider using it in
 * your own code. */
static const char KEY[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBAKibTEzXjj+sqpipePX1lEk5BNFuL/dDBbw8QCXgaJWikOiKHeJq\n"
    "3FQ0OmCnmpkdsPFE4x3ojYmmdgE2i0dJwq0CAwEAAQJAZ08gpUS+qE1IClps/2gG\n"
    "AAer6Bc31K2AaiIQvCSQcH440cp062QtWMC3V5sEoWmdLsbAHFH26/9ZHn5zAflp\n"
    "gQIhANWOx/UYeR8HD0WREU5kcuSzgzNLwUErHLzxP7U6aojpAiEAyh2H35CjN/P7\n"
    "NhcZ4QYw3PeUWpqgJnaE/4i80BSYkSUCIQDLHFhLYLJZ80HwHTADif/ISn9/Ow6b\n"
    "p6BWh3DbMar/eQIgBPS6azH5vpp983KXkNv9AL4VZi9ac/b+BeINdzC6GP0CIDmB\n"
    "U6GFEQTZ3IfuiVabG5pummdC4DNbcdI+WKrSFNmQ\n"
    "-----END RSA PRIVATE KEY-----\n";

EVP_PKEY *
ssl_getkey(void)
{
	EVP_PKEY *key;
	BIO *bio;

	/* new read-only BIO backed by KEY. */
	bio = BIO_new_mem_buf((char*)KEY, -1);
	tt_assert(bio);

	key = PEM_read_bio_PrivateKey(bio,NULL,NULL,NULL);
	BIO_free(bio);
	tt_assert(key);

	return key;
end:
	return NULL;
}

X509 *
ssl_getcert(void)
{
	/* Dummy code to make a quick-and-dirty valid certificate with
	   OpenSSL.  Don't copy this code into your own program! It does a
	   number of things in a stupid and insecure way. */
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	EVP_PKEY *key = ssl_getkey();
	int nid;
	time_t now = time(NULL);

	tt_assert(key);

	x509 = X509_new();
	tt_assert(x509);
	tt_assert(0 != X509_set_version(x509, 2));
	tt_assert(0 != ASN1_INTEGER_set(X509_get_serialNumber(x509),
		(long)now));

	name = X509_NAME_new();
	tt_assert(name);
	nid = OBJ_txt2nid("commonName");
	tt_assert(NID_undef != nid);
	tt_assert(0 != X509_NAME_add_entry_by_NID(
		    name, nid, MBSTRING_ASC, (unsigned char*)"example.com",
		    -1, -1, 0));

	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);

	X509_time_adj(X509_get_notBefore(x509), 0, &now);
	now += 3600;
	X509_time_adj(X509_get_notAfter(x509), 0, &now);
	X509_set_pubkey(x509, key);
	tt_assert(0 != X509_sign(x509, key, EVP_sha1()));

	return x509;
end:
	X509_free(x509);
	return NULL;
}

static int disable_tls_11_and_12 = 0;
static SSL_CTX *the_ssl_ctx = NULL;

SSL_CTX *
get_ssl_ctx(void)
{
	if (the_ssl_ctx)
		return the_ssl_ctx;
	the_ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!the_ssl_ctx)
		return NULL;
	if (disable_tls_11_and_12) {
#ifdef SSL_OP_NO_TLSv1_2
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_1
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif
	}
	return the_ssl_ctx;
}

void
init_ssl(void)
{
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	if (SSLeay() != OPENSSL_VERSION_NUMBER) {
		TT_DECLARE("WARN", ("Version mismatch for openssl: compiled with %lx but running with %lx", (unsigned long)OPENSSL_VERSION_NUMBER, (unsigned long) SSLeay()));
	}
}

/* ====================
   Here's a simple test: we read a number from the input, increment it, and
   reply, until we get to 1001.
*/

static int test_is_done = 0;
static int n_connected = 0;
static int got_close = 0;
static int got_error = 0;
static int got_timeout = 0;
static int renegotiate_at = -1;
static int stop_when_connected = 0;
static int pending_connect_events = 0;
static struct event_base *exit_base = NULL;

enum regress_openssl_type
{
	REGRESS_OPENSSL_SOCKETPAIR = 1,
	REGRESS_OPENSSL_FILTER = 2,
	REGRESS_OPENSSL_RENEGOTIATE = 4,
	REGRESS_OPENSSL_OPEN = 8,
	REGRESS_OPENSSL_DIRTY_SHUTDOWN = 16,
	REGRESS_OPENSSL_FD = 32,

	REGRESS_OPENSSL_CLIENT = 64,
	REGRESS_OPENSSL_SERVER = 128,

	REGRESS_OPENSSL_FREED = 256,
	REGRESS_OPENSSL_TIMEOUT = 512,
	REGRESS_OPENSSL_SLEEP = 1024,
};

static void
bufferevent_openssl_check_fd(struct bufferevent *bev, int filter)
{
	if (filter) {
		tt_int_op(bufferevent_getfd(bev), ==, -1);
		tt_int_op(bufferevent_setfd(bev, -1), ==, -1);
	} else {
		tt_int_op(bufferevent_getfd(bev), !=, -1);
		tt_int_op(bufferevent_setfd(bev, -1), ==, 0);
	}
	tt_int_op(bufferevent_getfd(bev), ==, -1);

end:
	;
}
static void
bufferevent_openssl_check_freed(struct bufferevent *bev)
{
	tt_int_op(event_pending(&bev->ev_read, EVLIST_ALL, NULL), ==, 0);
	tt_int_op(event_pending(&bev->ev_write, EVLIST_ALL, NULL), ==, 0);

end:
	;
}

static void
respond_to_number(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_input(bev);
	char *line;
	int n;

	enum regress_openssl_type type;
	type = (enum regress_openssl_type)ctx;

	line = evbuffer_readln(b, NULL, EVBUFFER_EOL_LF);
	if (! line)
		return;
	n = atoi(line);
	if (n <= 0)
		TT_FAIL(("Bad number: %s", line));
	free(line);
	TT_BLATHER(("The number was %d", n));
	if (n == 1001) {
		++test_is_done;
		bufferevent_free(bev); /* Should trigger close on other side. */
		return;
	}
	if ((type & REGRESS_OPENSSL_CLIENT) && n == renegotiate_at) {
		SSL_renegotiate(bufferevent_openssl_get_ssl(bev));
	}
	++n;
	evbuffer_add_printf(bufferevent_get_output(bev),
	    "%d\n", n);
	TT_BLATHER(("Done reading; now writing."));
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_disable(bev, EV_READ);
}

static void
done_writing_cb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);
	if (evbuffer_get_length(b))
		return;
	TT_BLATHER(("Done writing."));
	bufferevent_disable(bev, EV_WRITE);
	bufferevent_enable(bev, EV_READ);
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	enum regress_openssl_type type;
	type = (enum regress_openssl_type)ctx;

	TT_BLATHER(("Got event %d", (int)what));
	if (what & BEV_EVENT_CONNECTED) {
		SSL *ssl;
		X509 *peer_cert;
		++n_connected;
		ssl = bufferevent_openssl_get_ssl(bev);
		tt_assert(ssl);
		peer_cert = SSL_get_peer_certificate(ssl);
		if (type & REGRESS_OPENSSL_SERVER) {
			tt_assert(peer_cert == NULL);
		} else {
			tt_assert(peer_cert != NULL);
		}
		if (stop_when_connected) {
			if (--pending_connect_events == 0)
				event_base_loopexit(exit_base, NULL);
		}
	} else if (what & BEV_EVENT_EOF) {
		TT_BLATHER(("Got a good EOF"));
		++got_close;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_openssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_openssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_ERROR) {
		TT_BLATHER(("Got an error."));
		++got_error;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_openssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_openssl_check_freed(bev);
		}
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_TIMEOUT) {
		TT_BLATHER(("Got timeout."));
		++got_timeout;
		if (type & REGRESS_OPENSSL_FD) {
			bufferevent_openssl_check_fd(bev, type & REGRESS_OPENSSL_FILTER);
		}
		if (type & REGRESS_OPENSSL_FREED) {
			bufferevent_openssl_check_freed(bev);
		}
		bufferevent_free(bev);
	}
end:
	;
}

static void
open_ssl_bufevs(struct bufferevent **bev1_out, struct bufferevent **bev2_out,
    struct event_base *base, int is_open, int flags, SSL *ssl1, SSL *ssl2,
    evutil_socket_t *fd_pair, struct bufferevent **underlying_pair,
    enum regress_openssl_type type)
{
	int state1 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_CONNECTING;
	int state2 = is_open ? BUFFEREVENT_SSL_OPEN :BUFFEREVENT_SSL_ACCEPTING;
	int dirty_shutdown = type & REGRESS_OPENSSL_DIRTY_SHUTDOWN;
	if (fd_pair) {
		*bev1_out = bufferevent_openssl_socket_new(
			base, fd_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_openssl_socket_new(
			base, fd_pair[1], ssl2, state2, flags);
	} else {
		*bev1_out = bufferevent_openssl_filter_new(
			base, underlying_pair[0], ssl1, state1, flags);
		*bev2_out = bufferevent_openssl_filter_new(
			base, underlying_pair[1], ssl2, state2, flags);

	}
	bufferevent_setcb(*bev1_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_CLIENT | (long)type));
	bufferevent_setcb(*bev2_out, respond_to_number, done_writing_cb,
	    eventcb, (void*)(REGRESS_OPENSSL_SERVER | (long)type));

	bufferevent_openssl_set_allow_dirty_shutdown(*bev1_out, dirty_shutdown);
	bufferevent_openssl_set_allow_dirty_shutdown(*bev2_out, dirty_shutdown);
}

static void
regress_bufferevent_openssl(void *arg)
{
	struct basic_test_data *data = arg;

	struct bufferevent *bev1, *bev2;
	SSL *ssl1, *ssl2;
	X509 *cert = ssl_getcert();
	EVP_PKEY *key = ssl_getkey();
	int flags = BEV_OPT_DEFER_CALLBACKS;
	struct bufferevent *bev_ll[2] = { NULL, NULL };
	evutil_socket_t *fd_pair = NULL;

	enum regress_openssl_type type;
	type = (enum regress_openssl_type)data->setup_data;

	tt_assert(cert);
	tt_assert(key);

	init_ssl();

	if (type & REGRESS_OPENSSL_RENEGOTIATE) {
		if (SSLeay() >= 0x10001000 &&
		    SSLeay() <  0x1000104f) {
			/* 1.0.1 up to 1.0.1c has a bug where TLS1.1 and 1.2
			 * can't renegotiate with themselves. Disable. */
			disable_tls_11_and_12 = 1;
		}
		renegotiate_at = 600;
	}

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());

	SSL_use_certificate(ssl2, cert);
	SSL_use_PrivateKey(ssl2, key);

	if (!(type & REGRESS_OPENSSL_OPEN))
		flags |= BEV_OPT_CLOSE_ON_FREE;

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_assert(type & REGRESS_OPENSSL_SOCKETPAIR);
		fd_pair = data->pair;
	} else {
		bev_ll[0] = bufferevent_socket_new(data->base, data->pair[0],
		    BEV_OPT_CLOSE_ON_FREE);
		bev_ll[1] = bufferevent_socket_new(data->base, data->pair[1],
		    BEV_OPT_CLOSE_ON_FREE);
	}

	open_ssl_bufevs(&bev1, &bev2, data->base, 0, flags, ssl1, ssl2,
	    fd_pair, bev_ll, type);

	if (!(type & REGRESS_OPENSSL_FILTER)) {
		tt_int_op(bufferevent_getfd(bev1), ==, data->pair[0]);
	} else {
		tt_ptr_op(bufferevent_get_underlying(bev1), ==, bev_ll[0]);
	}

	if (type & REGRESS_OPENSSL_OPEN) {
		pending_connect_events = 2;
		stop_when_connected = 1;
		exit_base = data->base;
		event_base_dispatch(data->base);
		/* Okay, now the renegotiation is done.  Make new
		 * bufferevents to test opening in BUFFEREVENT_SSL_OPEN */
		flags |= BEV_OPT_CLOSE_ON_FREE;
		bufferevent_free(bev1);
		bufferevent_free(bev2);
		bev1 = bev2 = NULL;
		open_ssl_bufevs(&bev1, &bev2, data->base, 1, flags, ssl1, ssl2,
		    fd_pair, bev_ll, type);
	}

	if (!(type & REGRESS_OPENSSL_TIMEOUT)) {
		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_enable(bev2, EV_READ|EV_WRITE);

		evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 1);
		tt_assert(n_connected == 2);

		/* We don't handle shutdown properly yet */
		if (type & REGRESS_OPENSSL_DIRTY_SHUTDOWN) {
			tt_int_op(got_close, ==, 1);
			tt_int_op(got_error, ==, 0);
		} else {
			tt_int_op(got_error, ==, 1);
		}
		tt_int_op(got_timeout, ==, 0);
	} else {
		struct timeval t = { 2, 0 };

		bufferevent_enable(bev1, EV_READ|EV_WRITE);
		bufferevent_disable(bev2, EV_READ|EV_WRITE);

		bufferevent_set_timeouts(bev1, &t, &t);

		evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

		event_base_dispatch(data->base);

		tt_assert(test_is_done == 0);
		tt_assert(n_connected == 0);

		tt_int_op(got_close, ==, 0);
		tt_int_op(got_error, ==, 0);
		tt_int_op(got_timeout, ==, 1);
	}
end:
	return;
}

static void
acceptcb_deferred(evutil_socket_t fd, short events, void *arg)
{
	struct bufferevent *bev = arg;
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}
static void
acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	struct basic_test_data *data = arg;
	struct bufferevent *bev;
	enum regress_openssl_type type;
	SSL *ssl = SSL_new(get_ssl_ctx());

	type = (enum regress_openssl_type)data->setup_data;

	SSL_use_certificate(ssl, ssl_getcert());
	SSL_use_PrivateKey(ssl, ssl_getkey());

	bev = bufferevent_openssl_socket_new(
		data->base,
		fd,
		ssl,
		BUFFEREVENT_SSL_ACCEPTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);

	bufferevent_setcb(bev, respond_to_number, NULL, eventcb,
	    (void*)(REGRESS_OPENSSL_SERVER));

	if (type & REGRESS_OPENSSL_SLEEP) {
		struct timeval when = { 1, 0 };
		event_base_once(data->base, -1, EV_TIMEOUT,
		    acceptcb_deferred, bev, &when);
		bufferevent_disable(bev, EV_READ|EV_WRITE);
	} else {
		bufferevent_enable(bev, EV_READ|EV_WRITE);
	}

	/* Only accept once, then disable ourself. */
	evconnlistener_disable(listener);
}

struct rwcount
{
	int fd;
	size_t read;
	size_t write;
};
static int
bio_rwcount_new(BIO *b)
{
	b->init = 0;
	b->num = -1;
	b->ptr = NULL;
	b->flags = 0;
	return 1;
}
static int
bio_rwcount_free(BIO *b)
{
	if (!b)
		return 0;
	if (b->shutdown) {
		b->init = 0;
		b->flags = 0;
		b->ptr = NULL;
	}
	return 1;
}
static int
bio_rwcount_read(BIO *b, char *out, int outlen)
{
	struct rwcount *rw = b->ptr;
	ssize_t ret = read(rw->fd, out, outlen);
	++rw->read;
	if (ret == -1 && errno == EAGAIN) {
		BIO_set_retry_read(b);
	}
	return ret;
}
static int
bio_rwcount_write(BIO *b, const char *in, int inlen)
{

	struct rwcount *rw = b->ptr;
	ssize_t ret = write(rw->fd, in, inlen);
	++rw->write;
	if (ret == -1 && errno == EAGAIN) {
		BIO_set_retry_write(b);
	}
	return ret;
}
static long
bio_rwcount_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	long ret = 0;
	switch (cmd) {
	case BIO_CTRL_GET_CLOSE:
		ret = b->shutdown;
		break;
	case BIO_CTRL_SET_CLOSE:
		b->shutdown = (int)num;
		break;
	case BIO_CTRL_PENDING:
		ret = 0;
		break;
	case BIO_CTRL_WPENDING:
		ret = 0;
		break;
	case BIO_CTRL_DUP:
	case BIO_CTRL_FLUSH:
		ret = 1;
		break;
	}
	return ret;
}
static int
bio_rwcount_puts(BIO *b, const char *s)
{
	return bio_rwcount_write(b, s, strlen(s));
}
#define BIO_TYPE_LIBEVENT_RWCOUNT 0xff1
static BIO_METHOD methods_rwcount = {
	BIO_TYPE_LIBEVENT_RWCOUNT, "rwcount",
	bio_rwcount_write,
	bio_rwcount_read,
	bio_rwcount_puts,
	NULL /* bio_rwcount_gets */,
	bio_rwcount_ctrl,
	bio_rwcount_new,
	bio_rwcount_free,
	NULL /* callback_ctrl */,
};
static BIO_METHOD *
BIO_s_rwcount(void)
{
	return &methods_rwcount;
}
static BIO *
BIO_new_rwcount(int close_flag)
{
	BIO *result;
	if (!(result = BIO_new(BIO_s_rwcount())))
		return NULL;
	result->init = 1;
	result->ptr = NULL;
	result->shutdown = !!close_flag;
	return result;
}

static void
regress_bufferevent_openssl_connect(void *arg)
{
	struct basic_test_data *data = arg;

	struct event_base *base = data->base;

	struct evconnlistener *listener;
	struct bufferevent *bev;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen;
	SSL *ssl;
	BIO *bio;
	struct rwcount rw = { -1, 0, 0 };
	enum regress_openssl_type type;

	type = (enum regress_openssl_type)data->setup_data;

	init_ssl();

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);

	memset(&ss, 0, sizeof(ss));
	slen = sizeof(ss);

	listener = evconnlistener_new_bind(base, acceptcb, data,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);
	tt_assert(evconnlistener_get_fd(listener) >= 0);

	ssl = SSL_new(get_ssl_ctx());
	tt_assert(ssl);

	bev = bufferevent_openssl_socket_new(
		data->base, -1, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bev);

	bufferevent_setcb(bev, respond_to_number, NULL, eventcb,
	    (void*)(REGRESS_OPENSSL_CLIENT));

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);
	tt_assert(slen == sizeof(struct sockaddr_in));
	tt_int_op(((struct sockaddr*)&ss)->sa_family, ==, AF_INET);

	tt_assert(0 ==
	    bufferevent_socket_connect(bev, (struct sockaddr*)&ss, slen));
	/* Possible only when we have fd, since be_openssl can and will overwrite
	 * bio otherwise before */
	if (type & REGRESS_OPENSSL_SLEEP) {
		rw.fd = bufferevent_getfd(bev);
		bio = BIO_new_rwcount(0);
		tt_assert(bio);
		bio->ptr = &rw;
		SSL_set_bio(ssl, bio, bio);
	}
	evbuffer_add_printf(bufferevent_get_output(bev), "1\n");
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	event_base_dispatch(base);

	tt_int_op(rw.read, <=, 100);
	tt_int_op(rw.write, <=, 100);
end:
	;
}

struct testcase_t ssl_testcases[] = {
#define T(a) ((void *)(a))
	{ "bufferevent_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup, T(REGRESS_OPENSSL_SOCKETPAIR) },
	{ "bufferevent_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup, T(REGRESS_OPENSSL_FILTER) },
	{ "bufferevent_renegotiate_socketpair", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE) },
	{ "bufferevent_renegotiate_filter", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE) },
	{ "bufferevent_socketpair_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN) },
	{ "bufferevent_filter_startopen", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN) },

	{ "bufferevent_socketpair_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_dirty_shutdown", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_renegotiate_socketpair_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_renegotiate_filter_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_RENEGOTIATE | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_socketpair_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },
	{ "bufferevent_filter_startopen_dirty_shutdown",
	  regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_OPEN | REGRESS_OPENSSL_DIRTY_SHUTDOWN) },

	{ "bufferevent_socketpair_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FD) },
	{ "bufferevent_socketpair_freed", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED) },
	{ "bufferevent_socketpair_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },
	{ "bufferevent_filter_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_FILTER | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },

	{ "bufferevent_socketpair_timeout", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT) },
	{ "bufferevent_socketpair_timeout_freed_fd", regress_bufferevent_openssl,
	  TT_ISOLATED, &basic_setup,
	  T(REGRESS_OPENSSL_SOCKETPAIR | REGRESS_OPENSSL_TIMEOUT | REGRESS_OPENSSL_FREED | REGRESS_OPENSSL_FD) },

	{ "bufferevent_connect", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL },
	{ "bufferevent_connect_sleep", regress_bufferevent_openssl_connect,
	  TT_FORK|TT_NEED_BASE, &basic_setup, T(REGRESS_OPENSSL_SLEEP) },

#undef T

	END_OF_TESTCASES,
};
