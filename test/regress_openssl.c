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
#include "event2/util.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include "openssl-compat.h"
#include "regress.h"
#include "tinytest.h"
#define TESTCASES_NAME openssl_testcases
static void *ssl_test_setup(const struct testcase_t *testcase);
static int ssl_test_cleanup(const struct testcase_t *testcase, void *ptr);
static const struct testcase_setup_t ssl_setup = {
	ssl_test_setup, ssl_test_cleanup};

static X509 *the_cert;
EVP_PKEY *the_key;

#define SSL_IS_CLIENT
#define SSL_IS_SERVER

#define bufferevent_ssl_get_ssl bufferevent_openssl_get_ssl
#define bufferevent_ssl_set_allow_dirty_shutdown \
	bufferevent_openssl_set_allow_dirty_shutdown
#define bufferevent_ssl_socket_new bufferevent_openssl_socket_new
#define bufferevent_ssl_filter_new bufferevent_openssl_filter_new

struct rwcount;
static void BIO_setup(SSL *ssl, struct rwcount *rw);
#include "regress_ssl.c"

EVP_PKEY *
ssl_getkey(void)
{
	EVP_PKEY *key;
	BIO *bio;

	/* new read-only BIO backed by KEY. */
	bio = BIO_new_mem_buf((char *)KEY, -1);
	tt_assert(bio);

	key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);
	tt_assert(key);

	return key;
end:
	return NULL;
}

X509 *
ssl_getcert(EVP_PKEY *key)
{
	/* Dummy code to make a quick-and-dirty valid certificate with
	   OpenSSL.  Don't copy this code into your own program! It does a
	   number of things in a stupid and insecure way. */
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	int nid;
	time_t now = time(NULL);

	tt_assert(key);

	x509 = X509_new();
	tt_assert(x509);
	tt_assert(0 != X509_set_version(x509, 2));
	tt_assert(0 != ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)now));

	name = X509_NAME_new();
	tt_assert(name);
	nid = OBJ_txt2nid("commonName");
	tt_assert(NID_undef != nid);
	tt_assert(0 != X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
					   (unsigned char *)"example.com", -1, -1, 0));

	X509_set_subject_name(x509, name);
	X509_set_issuer_name(x509, name);
	X509_NAME_free(name);

	X509_time_adj(X509_getm_notBefore(x509), 0, &now);
	now += 3600;
	X509_time_adj(X509_getm_notAfter(x509), 0, &now);
	X509_set_pubkey(x509, key);
	tt_assert(0 != X509_sign(x509, key, EVP_sha256()));

	return x509;
end:
	X509_free(x509);
	X509_NAME_free(name);
	return NULL;
}

static SSL_CTX *the_ssl_ctx = NULL;

SSL_CTX *
get_ssl_ctx(void)
{
	if (the_ssl_ctx)
		return the_ssl_ctx;
	the_ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!the_ssl_ctx)
		return NULL;

#ifdef SSL_OP_ALLOW_CLIENT_RENEGOTIATION
	/*
	 * OpenSSL 3 disables client renegotiation by default. Enable it if
	 * the option is defined.
	 */
	SSL_CTX_set_options(the_ssl_ctx, SSL_OP_ALLOW_CLIENT_RENEGOTIATION);
#endif

	if (disable_tls_11_and_12) {
#ifdef SSL_OP_NO_TLSv1_2
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_2);
#endif
#ifdef SSL_OP_NO_TLSv1_1
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_1);
#endif
	}
	if (disable_tls_13) {
#ifdef SSL_OP_NO_TLSv1_3
		SSL_CTX_set_options(the_ssl_ctx, SSL_OP_NO_TLSv1_3);
#endif
	}
	return the_ssl_ctx;
}

void
init_ssl(void)
{
	static int initialized;
	if (initialized)
		return;
	initialized = 1;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) &&      \
		LIBRESSL_VERSION_NUMBER < 0x20700000L)
	/* NOTE: you should destroy every global objects to avoid leaks, see lsan.supp */
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	if (SSLeay() != OPENSSL_VERSION_NUMBER) {
		TT_DECLARE("WARN", ("Version mismatch for openssl: compiled with %lx "
							"but running with %lx",
							   (unsigned long)OPENSSL_VERSION_NUMBER,
							   (unsigned long)SSLeay()));
	}
#endif
}

static void *
ssl_test_setup(const struct testcase_t *testcase)
{
	init_ssl();

	the_key = ssl_getkey();
	EVUTIL_ASSERT(the_key);

	the_cert = ssl_getcert(the_key);
	EVUTIL_ASSERT(the_cert);

	disable_tls_11_and_12 = disable_tls_13 = 0;

	return basic_test_setup(testcase);
}
static int
ssl_test_cleanup(const struct testcase_t *testcase, void *ptr)
{
	int ret = basic_test_cleanup(testcase, ptr);
	if (!ret) {
		return ret;
	}

	test_is_done = 0;
	n_connected = 0;
	got_close = 0;
	got_error = 0;
	got_timeout = 0;
	renegotiate_at = -1;
	stop_when_connected = 0;
	pending_connect_events = 0;
	exit_base = NULL;

	X509_free(the_cert);
	EVP_PKEY_free(the_key);

	SSL_CTX_free(the_ssl_ctx);
	the_ssl_ctx = NULL;

	return 1;
}

static int
bio_rwcount_new(BIO *b)
{
	BIO_set_init(b, 0);
	BIO_set_data(b, NULL);
	return 1;
}
static int
bio_rwcount_free(BIO *b)
{
	TT_BLATHER(("bio_rwcount_free: %p", b));
	if (!b)
		return 0;
	if (BIO_get_shutdown(b)) {
		BIO_set_init(b, 0);
		BIO_set_data(b, NULL);
	}
	return 1;
}
static int
bio_rwcount_read(BIO *b, char *out, int outlen)
{
	struct rwcount *rw = BIO_get_data(b);
	ev_ssize_t ret = recv(rw->fd, out, outlen, 0);
	++rw->read;
	if (ret == -1 && EVUTIL_ERR_RW_RETRIABLE(EVUTIL_SOCKET_ERROR())) {
		BIO_set_retry_read(b);
	}
	return ret;
}
static int
bio_rwcount_write(BIO *b, const char *in, int inlen)
{
	struct rwcount *rw = BIO_get_data(b);
	ev_ssize_t ret = send(rw->fd, in, inlen, 0);
	++rw->write;
	if (ret == -1 && EVUTIL_ERR_RW_RETRIABLE(EVUTIL_SOCKET_ERROR())) {
		BIO_set_retry_write(b);
	}
	return ret;
}
static long
bio_rwcount_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	struct rwcount *rw = BIO_get_data(b);
	long ret = 0;
	switch (cmd) {
	case BIO_C_GET_FD:
		ret = rw->fd;
		break;
	case BIO_CTRL_GET_CLOSE:
		ret = BIO_get_shutdown(b);
		break;
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(b, (int)num);
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
static BIO_METHOD *methods_rwcount;

static BIO_METHOD *
BIO_s_rwcount(void)
{
	if (methods_rwcount == NULL) {
		methods_rwcount = BIO_meth_new(BIO_TYPE_LIBEVENT_RWCOUNT, "rwcount");
		if (methods_rwcount == NULL)
			return NULL;
		BIO_meth_set_write(methods_rwcount, bio_rwcount_write);
		BIO_meth_set_read(methods_rwcount, bio_rwcount_read);
		BIO_meth_set_puts(methods_rwcount, bio_rwcount_puts);
		BIO_meth_set_ctrl(methods_rwcount, bio_rwcount_ctrl);
		BIO_meth_set_create(methods_rwcount, bio_rwcount_new);
		BIO_meth_set_destroy(methods_rwcount, bio_rwcount_free);
	}
	return methods_rwcount;
}
static BIO *
BIO_new_rwcount(int close_flag)
{
	BIO *result;
	if (!(result = BIO_new(BIO_s_rwcount())))
		return NULL;
	BIO_set_init(result, 1);
	BIO_set_data(result, NULL);
	BIO_set_shutdown(result, !!close_flag);
	return result;
}
static void
BIO_setup(SSL *ssl, struct rwcount *rw)
{
	BIO *bio;
	bio = BIO_new_rwcount(0);
	tt_assert(bio);
	BIO_set_data(bio, rw);
	SSL_set_bio(ssl, bio, bio);
end:
	return;
}
