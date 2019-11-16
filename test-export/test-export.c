#include <event2/event.h>
#if defined(EVENT_EXPORT_TEST_COMPONENT_EXTRA)
#include "event2/http.h"
#include "event2/rpc.h"
#include <event2/dns.h>
#elif defined(EVENT_EXPORT_TEST_COMPONENT_PTHREADS)
#include <event2/thread.h>
#elif defined(EVENT_EXPORT_TEST_COMPONENT_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <event2/bufferevent_ssl.h>
#endif

#if defined(EVENT_EXPORT_TEST_COMPONENT_EXTRA)
static int
test()
{
	struct event_base *base = NULL;
	struct evhttp *http = NULL;
	struct evdns_base *dns_base = NULL;
	struct evrpc_base *rpc_base = NULL;

	base = event_base_new();
	if (base) {
		http = evhttp_new(base);
		dns_base = evdns_base_new(base,
			EVDNS_BASE_DISABLE_WHEN_INACTIVE);
	}
	if (http)
		rpc_base = evrpc_init(http);

	if (base)
		event_base_free(base);
	if (http)
		evhttp_free(http);
	if (rpc_base)
		evrpc_free(rpc_base);
	if (dns_base)
		evdns_base_free(dns_base, 0);

	return 0;
}
#elif defined(EVENT_EXPORT_TEST_COMPONENT_PTHREADS)
static int
test()
{
	return evthread_use_pthreads();
}
#elif defined(EVENT_EXPORT_TEST_COMPONENT_OPENSSL)
static int
test()
{
	struct event_base *base = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	int r = 1;

	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	base = event_base_new();
	if (!base) {
		goto error;
	}

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		goto error;
	}
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		goto error;
	}
	bev = bufferevent_openssl_socket_new(base, -1, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	if (bev == NULL) {
		goto error;
	}
	r = 0;
error:
	if (base)
		event_base_free(base);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	if (ssl)
		SSL_free(ssl);
	return r;
}
#else
static int
test()
{
	struct event_base *base = NULL;

	base = event_base_new();
	if (base)
		event_base_free(base);

	return 0;
}
#endif

int
main(int argc, char const *argv[])
{
	int r = 0;
#ifdef _WIN32
	{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
	}
#endif
	r = test();
#ifdef _WIN32
	WSACleanup();
#endif
	return r;
}
