/*
  This is an simple example of https/(http) client access Internet over https or
  socks5 proxy
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#ifdef USE_MBEDTLS
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifdef USE_MBEDTLS
#else
#include "openssl_hostname_validation.h"
#endif

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	char buffer[4096] = "";
	int nread = 0;
	struct event_base *base = NULL;
	if (!req) {
		fprintf(stderr, "[-] Http reponse failed\n");
		return;
	}
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
				buffer, sizeof(buffer))) > 0) {
		printf("%s", (char *)buffer);
		memset(buffer, 0, sizeof(buffer));
	}
	base = evhttp_connection_get_base(arg);
	event_base_loopbreak(base);
	return;
}

static int
format_proxystring(struct bufferevent *bev, const char *proxystr)
{
	int ret = -1;
	struct evhttp_uri *uri = NULL;
	const char *scheme = NULL, *host = NULL;
	ev_uint8_t proxy_type = 0;
	int proxy_port = 0;

	do {
		if (!(uri = evhttp_uri_parse(proxystr)))
			break;
		if (!(scheme = evhttp_uri_get_scheme(uri)))
			break;
		if (!(host = evhttp_uri_get_host(uri)))
			break;
		if (!strcasecmp(scheme, "https"))
			proxy_type = 1;
		else if (!strcasecmp(scheme, "socks5"))
			proxy_type = 2;
		else
			break;
		proxy_port = evhttp_uri_get_port(uri);
		if (proxy_port == -1)
			proxy_port = (strcasecmp(scheme, "https") == 0) ? 443 : 1080;
		if (bufferevent_set_proxy(bev, proxy_type, host, proxy_port, "", ""))
			break;
		ret = 0;
	} while (0);
	if (uri)
		evhttp_uri_free(uri);
	return ret;
}

int
main(int argc, char **argv)
{
	int r, is_ssl = 0, http_port = 80;
	struct event_base *base = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev = NULL;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	struct evkeyvalq *headerOutput;
	int ret = 0;
	char szHttpWebsite[256] = "www.bing.com", *proxy_string = NULL;

	do {
		printf("Https client demo via proxy\n");
		if (3 != argc) {
			printf("\nUsage:\n");
			printf("argv1-sslcheck(0|1), argv2-proxystring(\"\"|\"proxystring\")\n");
			printf("\nExample:\n");
			printf("%s 0 \"socks5://192.168.1.1:1080\"\n", argv[0]);
			printf("%s 1 \"socks5://192.168.1.1:1080\"\n", argv[0]);
			printf("%s 0 \"https://192.168.1.1:443\"\n", argv[0]);
			printf("%s 1 \"https://192.168.1.1:443\"\n", argv[0]);
			break;
		}
		if (!strcmp(argv[1], "1"))
			is_ssl = 1;
		proxy_string = argv[2];
		if (!(base = event_base_new()))
			break;
		if (is_ssl) {
			ssl_ctx = SSL_CTX_new(SSLv23_method());
			if (!ssl_ctx)
				break;
			ssl = SSL_new(ssl_ctx);
			if (ssl == NULL)
				break;
			strcpy(szHttpWebsite, "github.com");
			http_port = 443;
			bev = bufferevent_openssl_socket_new(base, -1, ssl,
				BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
		} else
			bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
		if (strlen(proxy_string)) {
			// proxy_string, example: "socks5://192.168.136.1:1080"/
			// "https://192.168.136.1:443"
			if (format_proxystring(bev, proxy_string))
				break;
		}
		if (bev == NULL)
			break;
		evcon = evhttp_connection_base_bufferevent_new(
			base, NULL, bev, szHttpWebsite, http_port);
		if (evcon == NULL)
			break;
		req = evhttp_request_new(http_request_done, evcon);
		if (req == NULL)
			break;
		headerOutput = evhttp_request_get_output_headers(req);
		evhttp_add_header(headerOutput, "Host", szHttpWebsite);
		evhttp_add_header(headerOutput, "Connection", "Keep-Alive");

		r = evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/");
		if (r != 0) {
			fprintf(stderr, "evhttp_make_request() failed\n");
			break;
		}
		event_base_dispatch(base);
		ret = 1;
		break;
	} while (0);

	if (evcon)
		evhttp_connection_free(evcon);
	if (base)
		event_base_free(base);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	return ret;
}