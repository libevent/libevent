/**
 * This is an analog of nc/ncat/telnet that uses libevent's bufferevents
 *
 * TODO:
 * - optional SSL
 */

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event-config.h>
#include "../util-internal.h"

#include <event2/bufferevent_ssl.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include "openssl-compat.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <getopt.h>
#include <io.h>
#include <fcntl.h>
#else /* _WIN32 */
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#endif /* !_WIN32 */
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#ifdef __GNUC__
#define CHECK_FMT(a,b) __attribute__((format(printf, a, b)))
#else
#define CHECK_FMT(a,b)
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

static int verbose;

struct addr
{
	int port;
	char *address;
};
struct options
{
	struct addr src;
	struct addr dst;

	int max_read;
	struct {
		int read; /* seconds */
		int write; /* seconds */
	} timeout;

	struct {
		int listen:1;
		int keep:1;
		int ssl:1;
	} extra;
};
struct ssl_context
{
	SSL_CTX *ctx;
	EVP_PKEY *pkey;
	X509 *cert;
};
struct context
{
	struct options *opts;
	struct ssl_context ssl;

	struct bufferevent *in;
	struct bufferevent *out;

	FILE *fout;
};

static void info(const char *fmt, ...) CHECK_FMT(1,2);
static void error(const char *fmt, ...) CHECK_FMT(1,2);

static void info(const char *fmt, ...)
{
	va_list ap;
	if (!verbose)
		return;
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}
static void error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void be_free(struct bufferevent **bevp)
{
	evutil_socket_t fd;
	struct bufferevent *bev = *bevp;

	if (!bev)
		return;

	fd = bufferevent_getfd(bev);
	info("Freeing bufferevent with fd=%d\n", fd);

	bufferevent_free(bev);
	*bevp = NULL;
}
static struct bufferevent *
be_new(struct context *ctx, struct event_base *base, evutil_socket_t fd)
{
	SSL *ssl = NULL;
	struct bufferevent *bev = NULL;
	int flags = BEV_OPT_CLOSE_ON_FREE;
	enum bufferevent_ssl_state state = BUFFEREVENT_SSL_CONNECTING;

	if (fd != -1)
		state = BUFFEREVENT_SSL_ACCEPTING;

	if (ctx->opts->extra.ssl) {
		ssl = SSL_new(ctx->ssl.ctx);
		if (!ssl)
			goto err;
		if (SSL_use_certificate(ssl, ctx->ssl.cert) != 1)
			goto err;
		if (SSL_use_PrivateKey(ssl, ctx->ssl.pkey) != 1)
			goto err;
		bev = bufferevent_openssl_socket_new(base, fd, ssl, state, flags);
	} else {
		bev = bufferevent_socket_new(base, fd, flags);
	}
	if (ctx->opts->max_read != -1) {
		if (bufferevent_set_max_single_read(bev, ctx->opts->max_read))
			goto err;
	}
	return bev;
err:
	if (ssl)
		SSL_free(ssl);
	return NULL;
}
static int be_set_timeout(struct bufferevent *bev, const struct options *o)
{
	struct timeval tv_read = { o->timeout.read, 0 };
	struct timeval tv_write = { o->timeout.write, 0 };
	info("Set timeout to (read=%i, write=%i)\n", o->timeout.read, o->timeout.write);
	return bufferevent_set_timeouts(bev, &tv_read, &tv_write);
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
static inline void ssl_init(void)
{
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}
#else /* OPENSSL_VERSION_NUMBER */
static inline void ssl_init(void) {}
#endif /* OPENSSL_VERSION_NUMBER */

static void ssl_ctx_free(struct ssl_context *ssl)
{
	SSL_CTX_free(ssl->ctx);
	EVP_PKEY_free(ssl->pkey);
	X509_free(ssl->cert);
}
static int ssl_load_key(struct ssl_context *ssl)
{
	int err = 1;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
	ssl->pkey = EVP_RSA_gen(4096);
	err = ssl->pkey == NULL;
#else
	BIGNUM *bn;
	RSA *key;

	ssl->pkey = EVP_PKEY_new();

	bn = BN_new();
	if (BN_set_word(bn, RSA_F4) != 1)
		goto err;
	/** Will be freed with ctx.pkey */
	key = RSA_new();
	if (RSA_generate_key_ex(key, 2048, bn, NULL) != 1)
		goto err;
	if (EVP_PKEY_assign_RSA(ssl->pkey, key) != 1)
		goto err;
	err = 0;
err:
	BN_free(bn);
#endif
	return err;
}
static int ssl_load_cert(struct ssl_context *ssl)
{
	X509_NAME *name;

	ssl->cert = X509_new();

	ASN1_INTEGER_set(X509_get_serialNumber(ssl->cert), 1);

	X509_gmtime_adj(X509_getm_notBefore(ssl->cert), 0);
	/** 1 year lifetime */
	X509_gmtime_adj(X509_getm_notAfter(ssl->cert),
		(long)time(NULL) + 365 * 86400);

	X509_set_pubkey(ssl->cert, ssl->pkey);

	name = X509_get_subject_name(ssl->cert);
	X509_NAME_add_entry_by_txt(
		name, "C", MBSTRING_ASC, (unsigned char *)"--", -1, -1, 0);
	X509_NAME_add_entry_by_txt(
		name, "O", MBSTRING_ASC, (unsigned char *)"<NULL>", -1, -1, 0);
	X509_NAME_add_entry_by_txt(
		name, "CN", MBSTRING_ASC, (unsigned char *)"*", -1, -1, 0);
	X509_set_issuer_name(ssl->cert, name);

	X509_sign(ssl->cert, ssl->pkey, EVP_sha1());

	return 0;
}
static int ssl_ctx_init(struct ssl_context *ssl)
{
	const SSL_METHOD *method;

	ssl_init();

	method = TLS_method();
	if (!method)
		goto err;
	ssl->ctx = SSL_CTX_new(method);

	if (ssl_load_key(ssl))
		goto err;
	if (ssl_load_cert(ssl))
		goto err;

	return 0;

err:
	ssl_ctx_free(ssl);
	return 1;
}

static void print_usage(FILE *out, const char *name)
{
	fprintf(out, "Syntax: %s [ OPTS ] [hostname] [port]\n", name);
	fprintf(out,
		"\n"
		"ncat like utility\n"
		"\n"
		"  -p   Specify source port to use\n"
		"  -s   Specify source address to use (*does* affect -l, unlike ncat)\n"
		"  -l   Bind and listen for incoming connections\n"
		"  -k   Accept multiple connections in listen mode\n"
		"  -S   Connect or listen with SSL\n"
		"  -t   read timeout\n"
		"  -T   write timeout\n"
		"\n"
		"  -v   Increase verbosity\n"
		"  -h   Print usage\n"
	);
}
static struct options parse_opts(int argc, char **argv)
{
	struct options o;
	int opt;

	memset(&o, 0, sizeof(o));
	o.src.port = o.dst.port = 10024;
	o.max_read = -1;

	while ((opt = getopt(argc, argv, "p:s:R:t:" "lkSvh")) != -1) {
		switch (opt) {
			case 'p': o.src.port    = atoi(optarg); break;
			case 's': o.src.address = strdup("127.1"); break;
			case 'R': o.max_read    = atoi(optarg); break;

			case 't': o.timeout.read  = atoi(optarg); break;
			case 'T': o.timeout.write = atoi(optarg); break;

			case 'l': o.extra.listen = 1; break;
			case 'k': o.extra.keep   = 1; break;
			case 'S': o.extra.ssl    = 1; break;

			/**
			 * TODO: implement other bits:
			 * - filters
			 * - pair
			 * - watermarks
			 * - ratelimits
			 */

			case 'v': ++verbose; break;
			case 'h':
				print_usage(stdout, argv[0]);
				exit(EXIT_SUCCESS);
			default:
				fprintf(stderr, "Unknown option -%c\n", opt); break;
				exit(EXIT_FAILURE);
		}
	}

	if ((argc-optind) > 1) {
		o.dst.address = strdup(argv[optind]);
		++optind;
	}
	if ((argc-optind) > 1) {
		o.dst.port = atoi(optarg);
		++optind;
	}
	if ((argc-optind) > 1) {
		print_usage(stderr, argv[0]);
		exit(1);
	}

	if (!o.src.address)
		o.src.address = strdup("127.1");
	if (!o.dst.address)
		o.dst.address = strdup("127.1");

	return o;
}

#ifndef EVENT__HAVE_STRSIGNAL
static inline const char* strsignal(evutil_socket_t sig) { return "Signal"; }
#endif
static void do_term(evutil_socket_t sig, short events, void *arg)
{
	struct event_base *base = arg;
	event_base_loopexit(base, NULL);
	fprintf(stderr, "%s(" EV_SOCK_FMT "), Terminating\n",
		strsignal(sig), EV_SOCK_ARG(sig));
}

static ev_socklen_t
make_address(struct sockaddr_storage *ss, const char *address, ev_uint16_t port)
{
	struct evutil_addrinfo *ai = NULL;
	struct evutil_addrinfo hints;
	char strport[NI_MAXSERV];
	int ai_result;
	ev_socklen_t ret = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = EVUTIL_AI_PASSIVE|EVUTIL_AI_ADDRCONFIG;
	evutil_snprintf(strport, sizeof(strport), "%d", port);
	if ((ai_result = evutil_getaddrinfo(address, strport, &hints, &ai)) != 0) {
		return 0;
	}
	if (!ai)
		return 0;
	if (ai->ai_addrlen > sizeof(*ss)) {
		evutil_freeaddrinfo(ai);
		return 0;
	}

	memcpy(ss, ai->ai_addr, ai->ai_addrlen);
	/** Hm.. I do not like this cast. */
	ret = (ev_socklen_t)ai->ai_addrlen;
	evutil_freeaddrinfo(ai);
	return ret;
}

static void be_ssl_errors(struct bufferevent *bev)
{
	int err;
	while ((err = bufferevent_get_openssl_error(bev))) {
		const char *msg = ERR_reason_error_string(err);
		const char *lib = ERR_lib_error_string(err);
#if OPENSSL_VERSION_NUMBER >= 0x30000000
		error("ssl/err=%d/%s in %s\n", err, msg, lib);
#else
		const char *func = ERR_func_error_string(err);
		error("ssl/err=%d/%s in %s %s\n", err, msg, lib, func);
#endif
	}
}
static int event_cb_(struct bufferevent *bev, short what, int ssl, int stop)
{
	struct event_base *base = bufferevent_get_base(bev);
	evutil_socket_t fd = bufferevent_getfd(bev);

	if (what & BEV_EVENT_CONNECTED) {
		info("Connected\n");
		return 0;
	}
	if (ssl && what & BEV_EVENT_ERROR) {
		be_ssl_errors(bev);
	}

	if (stop)
		event_base_loopexit(base, NULL);

	error("Got 0x%x event on fd=%d. Terminating connection\n", what, fd);
	be_free(&bev);
	return 1;
}

static void read_cb(struct bufferevent *bev, void *arg)
{
	struct context *ctx = arg;
	struct evbuffer *in = bufferevent_get_input(bev);
	evbuffer_write(in, fileno(ctx->fout));
}
static void write_cb(struct bufferevent *bev, void *arg)
{
	struct context *ctx = arg;
	bufferevent_write_buffer(bev, bufferevent_get_input(ctx->in));
}
static void server_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct context *ctx = arg;
	EVUTIL_ASSERT(bev == ctx->out);
	if (!event_cb_(bev, what, ctx->opts->extra.ssl, !ctx->opts->extra.keep))
		return;
	ctx->out = NULL;
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
	struct sockaddr *sa, int socklen, void *arg)
{
	char buffer[128];
	struct context *ctx = arg;
	struct bufferevent *bev = NULL;
	struct event_base *base = evconnlistener_get_base(listener);

	if (!ctx->opts->extra.keep)
		evconnlistener_disable(listener);

	info("Accepting %s (fd=%d)\n",
		evutil_format_sockaddr_port_(sa, buffer, sizeof(buffer)-1), fd);

	bev = be_new(ctx, base, fd);
	if (!bev) {
		error("Cannot make bufferevent for fd=%d\n", fd);
		goto err;
	}

	bufferevent_setcb(bev, read_cb, write_cb, server_event_cb, ctx);
	if (bufferevent_enable(bev, EV_READ|EV_WRITE)) {
		error("Cannot monitor EV_READ|EV_WRITE for server\n");
		goto err;
	}
	if (be_set_timeout(bev, ctx->opts)) {
		info("Cannot set timeout for server\n");
		goto err;
	}

	/** TODO: support multiple bevs */
	EVUTIL_ASSERT(!ctx->out);
	ctx->out = bev;

	if (bufferevent_enable(ctx->in, EV_READ)) {
		error("Cannot monitor EV_READ on input\n");
		goto err;
	}

	return;

err:
	be_free(&bev);
}

static void client_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct context *ctx = arg;
	if (!event_cb_(bev, what, ctx->opts->extra.ssl, 1))
		return;
	ctx->out = NULL;
}

static void in_event_cb(struct bufferevent *bev, short what, void *arg)
{
	struct context *ctx = arg;
	if (!event_cb_(bev, what, ctx->opts->extra.ssl, 1))
		return;

	ctx->in = NULL;
	be_free(&ctx->out);
}

static void trigger_bev_write_cb(struct bufferevent *bev, void *arg)
{
	struct context *ctx = arg;
	if (!ctx->out)
		return;
	bufferevent_trigger(ctx->out, EV_WRITE, 0);
}

int main(int argc, char **argv)
{
	struct event_base *base = NULL;
	struct event *term = NULL;
	struct evconnlistener *listener = NULL;
	struct bufferevent *bev = NULL;
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	ev_socklen_t ss_len;
	char buffer[128];

	struct context ctx;
	struct options o = parse_opts(argc, argv);
	int err = EXIT_SUCCESS;

	memset(&ctx, 0, sizeof(ctx));
	ctx.opts = &o;

	if (verbose || getenv("EVENT_DEBUG_LOGGING_ALL"))
		event_enable_debug_logging(EVENT_DBG_ALL);

	base = event_base_new();
	if (!base)
		goto err;

	term = evsignal_new(base, SIGINT, do_term, base);
	if (!term)
		goto err;
	if (event_add(term, NULL))
		goto err;

#ifdef _WIN32
	{
		WORD wVersionRequested;
		WSADATA wsaData;
		wVersionRequested = MAKEWORD(2, 2);
		WSAStartup(wVersionRequested, &wsaData);
	}
#else
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		goto err;
#endif

	if (o.extra.ssl && ssl_ctx_init(&ctx.ssl))
		goto err;

	if (o.extra.listen) {
		int flags = 0;
		flags |= LEV_OPT_CLOSE_ON_FREE;
		flags |= LEV_OPT_CLOSE_ON_EXEC;
		flags |= LEV_OPT_REUSEABLE;

		ss_len = make_address(&ss, o.src.address, o.src.port);
		if (!ss_len) {
			error("Cannot make address from %s:%d\n",
				o.src.address, o.src.port);
			goto err;
		}
		info("Listening on %s\n",
			evutil_format_sockaddr_port_(sa, buffer, sizeof(buffer)-1));
		listener = evconnlistener_new_bind(base, accept_cb, &ctx, flags, -1, sa, ss_len);
		if (!listener) {
			error("Cannot listen\n");
			goto err;
		}
	} else {
		ss_len = make_address(&ss, o.dst.address, o.dst.port);
		if (!ss_len) {
			error("Cannot make address from %s:%d\n",
				o.src.address, o.src.port);
			goto err;
		}
		info("Connecting to %s\n",
			evutil_format_sockaddr_port_(sa, buffer, sizeof(buffer)-1));

		bev = be_new(&ctx, base, -1);
		if (!bev) {
			error("Cannot make bufferevent\n");
			goto err;
		}

		bufferevent_setcb(bev, read_cb, write_cb, client_event_cb, &ctx);
		if (bufferevent_enable(bev, EV_READ|EV_WRITE)) {
			error("Cannot monitor EV_READ|EV_WRITE for client\n");
			goto err;
		}
		if (be_set_timeout(bev, &o)) {
			info("Cannot set timeout for client\n");
			goto err;
		}

		if (bufferevent_socket_connect(bev, sa, ss_len)) {
			info("Connection failed\n");
			goto err;
		}
	}

	ctx.out = bev;
	ctx.fout = stdout;

	ctx.in = bufferevent_socket_new(base, STDIN_FILENO, 0);
	if (o.max_read != -1) {
		if (bufferevent_set_max_single_read(ctx.in, o.max_read))
			goto err;
	}
	if (!ctx.in) {
		error("Cannot create input bufferevent\n");
		goto err;
	}
	bufferevent_setcb(ctx.in, trigger_bev_write_cb, NULL, in_event_cb, &ctx);
	if (ctx.out && bufferevent_enable(ctx.in, EV_READ)) {
		error("Cannot monitor EV_READ on input\n");
		goto err;
	}
	bufferevent_disable(ctx.in, EV_WRITE);

	if (!event_base_dispatch(base))
		goto out;

err:
	if (!err)
		err = EXIT_FAILURE;

out:
	if (term)
		event_free(term);
	be_free(&ctx.in);
	be_free(&ctx.out);
	if (listener)
		evconnlistener_free(listener);
	if (base)
		event_base_free(base);

	free(o.src.address);
	free(o.dst.address);

	ssl_ctx_free(&ctx.ssl);

#ifdef _WIN32
	WSACleanup();
#endif

	return err;
}
