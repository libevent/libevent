/*
 *  SSL client demonstration program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include "mbedtls/config.h"
#include "mbedtls/platform.h"

#include "mbedtls-compat.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <string.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/util.h>

#define SERVER_PORT "443"
#define SERVER_NAME "amazon.com"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 1

static void
my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void)level);

	mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}

static void
writecb(struct bufferevent *bev, void *arg)
{
	fprintf(stderr, "writecb\n");
}

static void
readcb(struct bufferevent *bev, void *arg)
{
	char buf[1000];
	size_t r = 0;
	int i;
	for (i = 0; i < 10; ++i) {
		r = bufferevent_read(bev, buf, 800);
		fprintf(stderr, "readcb %zu\n\n", r);
		if (r > 1) {
			fwrite(buf, 1, r, stdout);
			fwrite("\n", 1, r, stdout);
			fflush(stdout);
		}
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *arg)
{
	fprintf(stderr, "\n---------------eventcb %d\n", what);
	if (what & BEV_EVENT_CONNECTED) {
		const char headers[] = "GET / HTTP/1.1\r\n"
							   "HOST: " SERVER_NAME "\r\n"
							   "User-Agent: curl/7.65.1\r\n"
							   "Connection: Keep-Alive\r\n"
							   "\r\n";
		bufferevent_write(
			bev, headers, sizeof(headers) - 1); // without ending '\0'
		// bufferevent_disable(bev, EV_WRITE);
		fprintf(stderr, "write request completely\n");
	} else if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		fprintf(stderr, "closed\n");
		bufferevent_free(bev);
	}
}


int
main(void)
{
	int ret;
	mbedtls_net_context server_fd;
	const char *pers = "ssl_client1";

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cacert;

	struct event_base *evbase;
	struct evdns_base *evdns;
	struct bufferevent *bev;
	struct bufferevent *bevf;

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
#endif


#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

	/*
	 * 0. Initialize the RNG and the session data
	 */
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	mbedtls_printf("\n  . Seeding the random number generator...");
	fflush(stdout);

	mbedtls_entropy_init(&entropy);
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
			 (const unsigned char *)pers, strlen(pers))) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 0. Initialize certificates
	 */
	mbedtls_printf("  . Loading the CA root certificate ...");
	fflush(stdout);

	ret = mbedtls_x509_crt_parse(&cacert,
		(const unsigned char *)mbedtls_test_cas_pem, mbedtls_test_cas_pem_len);
	if (ret < 0) {
		mbedtls_printf(
			" failed\n  !  mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
		goto exit;
	}

	mbedtls_printf(" ok (%d skipped)\n", ret);

	/*
	 * 1. Start the connection
	 */
	mbedtls_printf("  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
	fflush(stdout);

	if ((ret = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT,
			 MBEDTLS_NET_PROTO_TCP)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/*
	 * 2. Setup stuff
	 */
	mbedtls_printf("  . Setting up the SSL/TLS structure...");
	fflush(stdout);

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
			 MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		mbedtls_printf(
			" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		goto exit;
	}

	mbedtls_printf(" ok\n");

	/* OPTIONAL is not optimal for security,
	 * but makes interop easier in this simplified example */
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME)) != 0) {
		mbedtls_printf(
			" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		goto exit;
	}
	fflush(stdout);

	event_enable_debug_mode();
	evbase = event_base_new();
	evdns = evdns_base_new(evbase, 1);
	evdns_base_set_option(evdns, "randomize-case:", "0");

	evutil_make_socket_nonblocking(server_fd.fd);

	bev = bufferevent_socket_new(evbase, server_fd.fd, BEV_OPT_CLOSE_ON_FREE);
	bevf = bufferevent_mbedtls_filter_new(
		evbase, bev, &ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
	bev = bevf;
	bufferevent_setcb(bev, readcb, writecb, eventcb, NULL);

	bufferevent_enable(bev, EV_READ);


	event_base_loop(evbase, 0);
	event_base_free(evbase);


exit:

#ifdef MBEDTLS_ERROR_C
	if (ret != 0) {
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, 100);
		mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
	}
#endif

	mbedtls_net_free(&server_fd);

	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
	mbedtls_printf("  + Press Enter to exit this program.\n");
	fflush(stdout);
	getchar();
#endif

	return (ret);
}
