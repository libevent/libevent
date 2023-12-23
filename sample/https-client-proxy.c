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
	char buffer[4096];
	int nread = 0;
	if (!req) {
		fprintf(stderr, "Http reponse failed\n");
		return;
	}
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
				buffer, sizeof(buffer))) > 0) {
		printf("%s", (char *)buffer);
		memset(buffer, 0, sizeof(buffer));
	}
	return;
}

int
main(int argc, char **argv)
{
	int r;
	struct event_base *base = NULL;
	struct evhttp_uri *http_uri = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	struct evkeyvalq *headerOutput;
	int ret = 0;

	do {
		printf("http client proxy begin\n");
		ssl_ctx = SSL_CTX_new(SSLv23_method());
		if (!ssl_ctx)
			break;
		base = event_base_new();
		if (!base)
			break;
			
		ssl = SSL_new(ssl_ctx);
		if (ssl == NULL)
			break;
		bev = bufferevent_openssl_socket_new(
			base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
		if (bev == NULL)
			break;
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
		evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev, "www.bing.com", 443);
		if (evcon == NULL)
			break;
		if (evhttp_connection_set_proxy(evcon,"https://192.168.88.209:8888") < 0)
		    break;
		// if (evhttp_connection_set_proxy(evcon,"socks5://192.168.88.1:1920") < 0)
		//     break;
		req = evhttp_request_new(http_request_done, bev);
		if (req == NULL)
			break;
		headerOutput = evhttp_request_get_output_headers(req);
		evhttp_add_header(headerOutput, "Host", "www.bing.com");
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
	if (http_uri)
		evhttp_uri_free(http_uri);
	if (base)
		event_base_free(base);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	return ret;
}