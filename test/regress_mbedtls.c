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
/** For event_debug() usage/coverage */
#define EVENT_VISIBILITY_WANT_DLLIMPORT

#include "event2/util.h"
#include <mbedtls/version.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include "regress.h"
#include "tinytest.h"

#define TESTCASES_NAME mbedtls_testcases

#ifdef OPENSSL_VERSION_NUMBER
#undef OPENSSL_VERSION_NUMBER
#endif
#define OPENSSL_VERSION_NUMBER 0
#define SSL_IS_CLIENT MBEDTLS_SSL_IS_CLIENT
#define SSL_IS_SERVER MBEDTLS_SSL_IS_SERVER

#define get_ssl_ctx get_mbedtls_config

/* FIXME: clean this up, add some prefix, i.e. le_ssl_ */
#define SSL_renegotiate mbedtls_ssl_renegotiate
#undef SSL_get_peer_certificate
#define SSL_get_peer_certificate mbedtls_ssl_get_peer_cert
#define SSL_get1_peer_certificate mbedtls_ssl_get_peer_cert
#define SSL_new bufferevent_mbedtls_dyncontext_new
#define SSL_use_certificate(a, b) \
	do {                          \
	} while (0);
#define SSL_use_PrivateKey(a, b) \
	do {                         \
	} while (0);
#define X509_free(x) \
	do {             \
	} while (0);

#define X509 const mbedtls_x509_crt
#define SSL mbedtls_ssl_context

#define bufferevent_ssl_get_ssl bufferevent_mbedtls_get_ssl
#define bufferevent_ssl_set_allow_dirty_shutdown \
	bufferevent_mbedtls_set_allow_dirty_shutdown
#define bufferevent_ssl_socket_new bufferevent_mbedtls_socket_new
#define bufferevent_ssl_filter_new bufferevent_mbedtls_filter_new

struct rwcount;
static void BIO_setup(SSL *ssl, struct rwcount *rw);
static void *mbedtls_test_setup(const struct testcase_t *testcase);
static int mbedtls_test_cleanup(const struct testcase_t *testcase, void *ptr);
const struct testcase_setup_t mbedtls_setup = {
	mbedtls_test_setup, mbedtls_test_cleanup};
#define ssl_setup mbedtls_setup
#include "regress_ssl.c"
static mbedtls_ssl_config *the_mbedtls_conf[2] = {NULL, NULL};
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt *the_cert;
static mbedtls_pk_context *the_key;

static void
mbedtls_debug(
	void *userdata, int level, const char *file, int line, const char *str)
{
	int loglen = strlen(str);
	if (str[loglen - 1] == '\n')
		loglen--;
	event_debug(("[mbedtls][%s][%d][%s][%d]%.*s", (char *)userdata, level, file,
		line, loglen, str));
}

static int
mbedtls_rng(void* ctx, unsigned char* buffer, size_t len)
{
	int rc;

	(void)ctx;

	rc = evutil_secure_rng_init();
	if (rc != 0)
		return rc;
	evutil_secure_rng_get_bytes(buffer, len);
	return 0;
}

static mbedtls_pk_context *
mbedtls_getkey(void)
{
	int ret = 0;
	mbedtls_pk_context *pk = malloc(sizeof(mbedtls_pk_context));
	tt_assert(pk);
	mbedtls_pk_init(pk);
	ret = mbedtls_pk_parse_key(pk,
		(const unsigned char *)KEY, sizeof(KEY),
		NULL, 0
#if MBEDTLS_VERSION_MAJOR >= 3
		, mbedtls_rng, NULL
#endif
		);
	tt_assert(ret == 0);
	return pk;
end:
	if (pk) {
		mbedtls_pk_free(pk);
		free(pk);
	}
	return NULL;
}

static void
create_tm_from_unix_epoch(struct tm *cur_p, const time_t t)
{
#ifdef _WIN32
	struct tm *tmp = gmtime(&t);
	if (!tmp) {
		fprintf(stderr, "gmtime: %s (%i)", strerror(errno), (int)t);
		exit(1);
	}
	*cur_p = *tmp;
#else
	gmtime_r(&t, cur_p);
#endif
}

static mbedtls_x509_crt *
mbedtls_getcert(mbedtls_pk_context *pk)
{
	const char *name = "commonName=example.com";
	time_t now = time(NULL);
	char now_string[32] = "";
	char not_before[32] = "";
	char not_after[32] = "";
	unsigned char certbuf[8192];
	struct tm tm;
	mbedtls_x509_crt *crt = NULL;
	int ret = 0;

	mbedtls_mpi serial;
	mbedtls_x509write_cert write_cert;

	snprintf(now_string, sizeof(now_string), "%lld", (long long)now);

	create_tm_from_unix_epoch(&tm, now);
	strftime(not_before, sizeof(not_before), "%Y%m%d%H%M%S", &tm);
	now += 3600;
	create_tm_from_unix_epoch(&tm, now);
	strftime(not_after, sizeof(not_after), "%Y%m%d%H%M%S", &tm);

	mbedtls_x509write_crt_init(&write_cert);
	mbedtls_x509write_crt_set_version(&write_cert, 2);

	mbedtls_mpi_init(&serial);
	ret = mbedtls_mpi_read_string(&serial, 10, now_string);
	tt_assert(ret == 0);
	ret = mbedtls_x509write_crt_set_serial(&write_cert, &serial);
	tt_assert(ret == 0);
	mbedtls_mpi_free(&serial);

	ret = mbedtls_x509write_crt_set_subject_name(&write_cert, name);
	tt_assert(ret == 0);
	ret = mbedtls_x509write_crt_set_issuer_name(&write_cert, name);
	tt_assert(ret == 0);

	mbedtls_x509write_crt_set_md_alg(&write_cert, MBEDTLS_MD_SHA256);

	ret =
		mbedtls_x509write_crt_set_validity(&write_cert, not_before, not_after);
	tt_assert(ret == 0);
	mbedtls_x509write_crt_set_issuer_key(&write_cert, pk);
	mbedtls_x509write_crt_set_subject_key(&write_cert, pk);

	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)name, strlen(name));
	tt_assert(ret == 0);
	ret = mbedtls_x509write_crt_pem(&write_cert, certbuf, sizeof(certbuf),
		mbedtls_ctr_drbg_random, &ctr_drbg);
	tt_assert(ret == 0);
	mbedtls_x509write_crt_free(&write_cert);

	crt = malloc(sizeof(mbedtls_x509_crt));
	tt_assert(crt);
	mbedtls_x509_crt_init(crt);
	ret = mbedtls_x509_crt_parse(crt, certbuf, strlen((char *)certbuf) + 1);
	tt_assert(ret == 0);
	return crt;
end:
	if (crt) {
		mbedtls_x509_crt_free(crt);
		free(crt);
	}
	return NULL;
}

mbedtls_ssl_config *
get_mbedtls_config(int endpoint)
{
	if (the_mbedtls_conf[endpoint])
		return the_mbedtls_conf[endpoint];
	the_mbedtls_conf[endpoint] = malloc(sizeof(mbedtls_ssl_config));
	if (!the_mbedtls_conf[endpoint])
		return NULL;
	mbedtls_ssl_config_init(the_mbedtls_conf[endpoint]);
	mbedtls_ssl_conf_renegotiation(
		the_mbedtls_conf[endpoint], MBEDTLS_SSL_RENEGOTIATION_ENABLED);
	mbedtls_ssl_conf_dbg(the_mbedtls_conf[endpoint], mbedtls_debug,
		(void *)(endpoint == MBEDTLS_SSL_IS_SERVER ? "server" : "client"));
	mbedtls_ssl_config_defaults(the_mbedtls_conf[endpoint], endpoint,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(
		the_mbedtls_conf[endpoint], mbedtls_ctr_drbg_random, &ctr_drbg);
#if MBEDTLS_VERSION_MAJOR < 3
	/* Mbed-TLS 3 doesn't support anything below TLS v1.2 */
	if (disable_tls_11_and_12) {
		mbedtls_ssl_conf_max_version(the_mbedtls_conf[endpoint],
			MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
	}
#endif
	if (endpoint == MBEDTLS_SSL_IS_SERVER) {
		mbedtls_ssl_conf_own_cert(
			the_mbedtls_conf[endpoint], the_cert, the_key);
	} else { /* MBEDTLS_SSL_IS_CLIENT */
		mbedtls_ssl_conf_ca_chain(the_mbedtls_conf[endpoint], the_cert, NULL);
	}
	return the_mbedtls_conf[endpoint];
}

static void
init_mbedtls(void)
{
	mbedtls_debug_set_threshold(5);
}

static void *
mbedtls_test_setup(const struct testcase_t *testcase)
{
	init_mbedtls();

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char *)"libevent", sizeof("libevent"));

	the_key = mbedtls_getkey();
	EVUTIL_ASSERT(the_key);

	the_cert = mbedtls_getcert(the_key);
	EVUTIL_ASSERT(the_cert);

	disable_tls_11_and_12 = 0;

	return basic_test_setup(testcase);
}
static int
mbedtls_test_cleanup(const struct testcase_t *testcase, void *ptr)
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

	mbedtls_x509_crt_free(the_cert);
	free(the_cert);
	mbedtls_pk_free(the_key);
	free(the_key);

	if (the_mbedtls_conf[0]) {
		mbedtls_ssl_config_free(the_mbedtls_conf[0]);
		free(the_mbedtls_conf[0]);
		the_mbedtls_conf[0] = NULL;
	}
	if (the_mbedtls_conf[1]) {
		mbedtls_ssl_config_free(the_mbedtls_conf[1]);
		free(the_mbedtls_conf[1]);
		the_mbedtls_conf[1] = NULL;
	}

	return 1;
}

static int
bio_rwcount_read(void *ctx, unsigned char *out, size_t outlen)
{
	struct rwcount *rw = ctx;
	ev_ssize_t ret = recv(rw->fd, out, outlen, 0);
	++rw->read;
	if (ret == -1 && EVUTIL_ERR_RW_RETRIABLE(EVUTIL_SOCKET_ERROR())) {
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	return ret;
}
static int
bio_rwcount_write(void *ctx, const unsigned char *in, size_t inlen)
{
	struct rwcount *rw = ctx;
	ev_ssize_t ret = send(rw->fd, in, inlen, 0);
	++rw->write;
	if (ret == -1 && EVUTIL_ERR_RW_RETRIABLE(EVUTIL_SOCKET_ERROR())) {
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}
	return ret;
}
static void
BIO_setup(SSL *ssl, struct rwcount *rw)
{
	mbedtls_ssl_set_bio(ssl, rw, bio_rwcount_write, bio_rwcount_read,
		NULL);
}
