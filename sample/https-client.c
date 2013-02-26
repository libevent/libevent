/*
  This is an example of how to hook up evhttp with bufferevent_ssl

  It just GETs an https URL given on the command-line and prints the response
  body to stdout.

  Actually, it also accepts plain http URLs to make it easy to compare http vs
  https code paths.

  Loosely based on le-proxy.c.
 */

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
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
#include <event2/http_struct.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static struct event_base *base;

static void
http_request_done(struct evhttp_request *req, void *ctx)
{
	char buffer[256];
	int nread;

	if (req == NULL) {
		/* If req is NULL, it means an error occurred, but
		 * sadly we are mostly left guessing what the error
		 * might have been.  We'll do our best... */
		struct bufferevent *bev = (struct bufferevent *) ctx;
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();
		fprintf(stderr, "some request failed - no idea which one though!\n");
		/* Print out the OpenSSL error queue that libevent
		 * squirreled away for us, if any. */
		while ((oslerr = bufferevent_get_openssl_error(bev))) {
			ERR_error_string_n(oslerr, buffer, sizeof(buffer));
			fprintf(stderr, "%s\n", buffer);
			printed_err = 1;
		}
		/* If the OpenSSL error queue was empty, maybe it was a
		 * socket error; let's try printing that. */
		if (! printed_err)
			fprintf(stderr, "socket error = %s (%d)\n",
				evutil_socket_error_to_string(errcode),
				errcode);
		return;
	}

	fprintf(stderr, "Response line: %d %s\n",
		req->response_code, req->response_code_line);

	while ((nread = evbuffer_remove(req->input_buffer, buffer, sizeof(buffer)))
	       > 0) {
		/* These are just arbitrary chunks of 256 bytes.
		 * They are not lines, so we can't treat them as such. */
		fwrite(buffer, nread, 1, stdout);
	}
}

static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fputs("   https-client <https-url>\n", stderr);
	fputs("Example:\n", stderr);
	fputs("   https-client https://ip.appspot.com/\n", stderr);

	exit(1);
}

static void
die(const char *msg)
{
	fputs(msg, stderr);
	exit(1);
}

static void
die_openssl(const char *func)
{
	fprintf (stderr, "%s failed:\n", func);

	/* This is the OpenSSL function that prints the contents of the
	 * error stack to the specified file handle. */
	ERR_print_errors_fp (stderr);

	exit(1);
}

int
main(int argc, char **argv)
{
	int r;

	struct evhttp_uri *http_uri;
	const char *url, *scheme, *host, *path, *query;
	char uri[256];
	int port;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	struct bufferevent *bev;
	struct evhttp_connection *evcon;
	struct evhttp_request *req;

	if (argc != 2)
		syntax();

	url = argv[1];
	http_uri = evhttp_uri_parse(url);
	if (http_uri == NULL) {
		die("malformed url");
	}

	scheme = evhttp_uri_get_scheme(http_uri);
	if (scheme == NULL || (strcasecmp(scheme, "https") != 0 &&
	                       strcasecmp(scheme, "http") != 0)) {
		die("url must be http or https");
	}

	host = evhttp_uri_get_host(http_uri);
	if (host == NULL) {
		die("url must have a host");
	}

	port = evhttp_uri_get_port(http_uri);
	if (port == -1) {
		port = (strcasecmp(scheme, "http") == 0) ? 80 : 443;
	}

	path = evhttp_uri_get_path(http_uri);
	if (path == NULL) {
		path = "/";
	}

	query = evhttp_uri_get_query(http_uri);
	if (query == NULL) {
		snprintf(uri, sizeof(uri) - 1, "%s", path);
	} else {
		snprintf(uri, sizeof(uri) - 1, "%s?%s", path, query);
	}
	uri[sizeof(uri) - 1] = '\0';

	// Initialize OpenSSL
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* This isn't strictly necessary... OpenSSL performs RAND_poll
	 * automatically on first use of random number generator. */
	r = RAND_poll();
	if (r == 0) {
		die_openssl("RAND_poll");
	}

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx)
		die_openssl("SSL_CTX_new");

	// Create event base
	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}

	// Create OpenSSL bufferevent and stack evhttp on top of it
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		die_openssl("SSL_new()");
	}

	if (strcasecmp(scheme, "http") == 0) {
		bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	} else {
		bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	}

	if (bev == NULL) {
		fprintf(stderr, "bufferevent_openssl_socket_new() failed\n");
		return 1;
	}

	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	// For simplicity, we let DNS resolution block. Everything else should be
	// asynchronous though.
	evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
		host, port);
	if (evcon == NULL) {
		fprintf(stderr, "evhttp_connection_base_bufferevent_new() failed\n");
		return 1;
	}

	// Fire off the request
	req = evhttp_request_new(http_request_done, bev);
	if (req == NULL) {
		fprintf(stderr, "evhttp_request_new() failed\n");
		return 1;
	}

	evhttp_add_header(req->output_headers, "Host", host);
	evhttp_add_header(req->output_headers, "Connection", "close");

	r = evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
	if (r != 0) {
		fprintf(stderr, "evhttp_make_request() failed\n");
		return 1;
	}

	event_base_dispatch(base);

	evhttp_connection_free(evcon);
	event_base_free(base);

	return 0;
}
