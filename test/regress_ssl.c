/*
 * Copyright (c) 2009 Niels Provos and Nick Mathewson
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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#include <event2/util.h>
#include <event2/event.h>
#include <event2/bufferevent_ssl.h>
#include <event2/buffer.h>

#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <string.h>

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

static EVP_PKEY *
getkey(void)
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

static X509 *
getcert(void)
{
	/* Dummy code to make a quick-and-dirty valid certificate with
	   OpenSSL.  Don't copy this code into your own program! It does a
	   number of things in a stupid and insecure way. */
	X509 *x509 = NULL;
	X509_NAME *name = NULL;
	EVP_PKEY *key = getkey();
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
	tt_assert(NID_undef != (nid = OBJ_txt2nid("commonName")));
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

static SSL_CTX *
get_ssl_ctx(void)
{
	static SSL_CTX *the_ssl_ctx = NULL;
	if (the_ssl_ctx)
		return the_ssl_ctx;
	return (the_ssl_ctx = SSL_CTX_new(SSLv23_method()));
}

static void
init_ssl(void)
{
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

/* ====================
   Here's a simple test: we read a number from the input, increment it, and
   reply, until we get to 1001.
*/

static int test_is_done = 0;
static int n_connected = 0;
static int got_close = 0;
static int got_error = 0;

static void
respond_to_number(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_input(bev);
	char *line;
	int n;
	line = evbuffer_readln(b, NULL, EVBUFFER_EOL_LF);
	if (! line)
		return;
	n = atoi(line);
	if (n <= 0)
		TT_FAIL(("Bad number: %s", line));
	TT_BLATHER(("The number was %d", n));
	if (n == 1001) {
		++test_is_done;
		bufferevent_free(bev); /* Should trigger close on other side. */
		return;
	}
	++n;
	evbuffer_add_printf(bufferevent_get_output(bev),
	    "%d\n", n);
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	TT_BLATHER(("Got event %d", (int)what));
	if (what & BEV_EVENT_CONNECTED)
		++n_connected;
	else if (what & BEV_EVENT_EOF) {
		TT_BLATHER(("Got a good EOF"));
		++got_close;
		bufferevent_free(bev);
	} else if (what & BEV_EVENT_ERROR) {
		TT_BLATHER(("Got an error."));
		++got_error;
		bufferevent_free(bev);
	}
}

static void
regress_bufferevent_openssl(void *arg)
{
	struct basic_test_data *data = arg;

	struct bufferevent *bev1, *bev2;
	SSL *ssl1, *ssl2;
	X509 *cert = getcert();
	EVP_PKEY *key = getkey();
	tt_assert(cert);
	tt_assert(key);

	init_ssl();

	ssl1 = SSL_new(get_ssl_ctx());
	ssl2 = SSL_new(get_ssl_ctx());

	SSL_use_certificate(ssl2, cert);
	SSL_use_PrivateKey(ssl2, key);

	if (strstr((char*)data->setup_data, "socketpair")) {
		bev1 = bufferevent_openssl_socket_new(
			data->base,
			data->pair[0],
			ssl1,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		bev2 = bufferevent_openssl_socket_new(
			data->base,
			data->pair[1],
			ssl2,
			BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	} else if (strstr((char*)data->setup_data, "filter")) {
		struct bufferevent *bev_ll1, *bev_ll2;
		bev_ll1 = bufferevent_socket_new(data->base, data->pair[0],
		    BEV_OPT_CLOSE_ON_FREE);
		bev_ll2 = bufferevent_socket_new(data->base, data->pair[1],
		    BEV_OPT_CLOSE_ON_FREE);
		tt_assert(bev_ll1);
		tt_assert(bev_ll2);
		bev1 = bufferevent_openssl_filter_new(
			data->base,
			bev_ll1,
			ssl1,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		bev2 = bufferevent_openssl_filter_new(
			data->base,
			bev_ll2,
			ssl2,
			BUFFEREVENT_SSL_ACCEPTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	} else {
		TT_DIE(("Bad setup data %s", (char*)data->setup_data));
	}

	bufferevent_enable(bev1, EV_READ|EV_WRITE);
	bufferevent_enable(bev2, EV_READ|EV_WRITE);

	bufferevent_setcb(bev1, respond_to_number, NULL, eventcb, NULL);
	bufferevent_setcb(bev2, respond_to_number, NULL, eventcb, NULL);

	evbuffer_add_printf(bufferevent_get_output(bev1), "1\n");

	event_base_dispatch(data->base);

	tt_assert(test_is_done == 1);
	tt_assert(n_connected == 2);
	/* We don't handle shutdown properly yet.
	   tt_int_op(got_close, ==, 1);
	   tt_int_op(got_error, ==, 0);
	*/
end:
	return;
}

struct testcase_t ssl_testcases[] = {

	{ "bufferevent_socketpair", regress_bufferevent_openssl, TT_ISOLATED,
	  &basic_setup, (void*)"socketpair" },
	{ "bufferevent_filter", regress_bufferevent_openssl,
	  TT_ISOLATED,
	  &basic_setup, (void*)"filter" },

        END_OF_TESTCASES,
};
