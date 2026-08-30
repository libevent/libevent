/*
 * Copyright 2024 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name of the author may not be used to endorse or promote products
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

/*
 * Throughput micro-benchmark for socket bufferevents. Each "pair" streams a
 * payload from a producer bufferevent to a consumer bufferevent over a
 * socketpair, --rounds times; the run reports elapsed time, aggregate
 * throughput, and per-round latency. The consumer drains each payload and
 * then triggers the next one by writing to the producer's output, so the
 * data flows one way (producer -> consumer) and the producer never needs to
 * read. --pairs runs many connections concurrently to measure behaviour
 * under load.
 *
 * With --ssl each pair is wrapped in TLS via bufferevent_openssl_socket_new
 * so plaintext and TLS bufferevent throughput can be compared on the same
 * workload. The TLS figure includes the (amortized) handshake, not raw
 * cipher throughput.
 */

#include "event2/event-config.h"

#include <sys/types.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else /* _WIN32 */
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>

#ifdef EVENT__HAVE_OPENSSL
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <event2/bufferevent_ssl.h>
#include "openssl-compat.h"

static SSL_CTX *ssl_ctx;

/* Generate an ephemeral RSA key for the self-signed benchmark certificate.
 * Uses EVP_PKEY_keygen (portable since OpenSSL 1.0.0 and on LibreSSL) rather
 * than the 3.0-only EVP_RSA_gen. This is a one-time setup cost, outside the
 * timed loop, so it does not affect the measured throughput; and it avoids
 * baking a private key into the source. */
static EVP_PKEY *
make_key(void)
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

	if (ctx == NULL)
		return NULL;
	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(ctx, &key) <= 0)
		key = NULL;
	EVP_PKEY_CTX_free(ctx);
	return key;
}

static X509 *
make_cert(EVP_PKEY *key)
{
	X509 *cert = X509_new();
	X509_NAME *name;
	time_t now = time(NULL);

	if (cert == NULL)
		return NULL;
	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(cert), (long)now);
	name = X509_NAME_new();
	if (name == NULL)
		goto err;
	X509_NAME_add_entry_by_NID(name, OBJ_txt2nid("commonName"),
	    MBSTRING_ASC, (unsigned char *)"bench", -1, -1, 0);
	X509_set_subject_name(cert, name);
	X509_set_issuer_name(cert, name);
	X509_NAME_free(name);
	X509_time_adj(X509_getm_notBefore(cert), 0, &now);
	now += 3600;
	X509_time_adj(X509_getm_notAfter(cert), 0, &now);
	X509_set_pubkey(cert, key);
	if (!X509_sign(cert, key, EVP_sha256()))
		goto err;
	return cert;
err:
	X509_free(cert);
	return NULL;
}

/* Build a single SSL_CTX (the bufferevent's accept/connect state picks the
 * role). Self-contained, so the benchmark needs no certificate files.
 * Returns 0 on success, -1 on failure (with everything freed). */
static int
ssl_setup(void)
{
	EVP_PKEY *key = make_key();
	X509 *cert = NULL;

	if (key == NULL)
		goto err;
	cert = make_cert(key);
	if (cert == NULL)
		goto err;
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (ssl_ctx == NULL)
		goto err;
	if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1 ||
	    SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1)
		goto err;
	X509_free(cert);
	EVP_PKEY_free(key);
	return 0;
err:
	X509_free(cert);
	EVP_PKEY_free(key);
	return -1;
}

static void
ssl_cleanup(void)
{
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
}

static struct bufferevent *
ssl_wrap(struct event_base *base, evutil_socket_t fd, int server)
{
	SSL *ssl = SSL_new(ssl_ctx);
	if (ssl == NULL)
		return NULL;
	return bufferevent_openssl_socket_new(base, fd, ssl,
	    server ? BUFFEREVENT_SSL_ACCEPTING : BUFFEREVENT_SSL_CONNECTING,
	    BEV_OPT_CLOSE_ON_FREE);
}
#endif /* EVENT__HAVE_OPENSSL */

struct bench_state;

struct bench_pair {
	struct bufferevent *producer;
	struct bufferevent *consumer;
	size_t received_this_round;
	int rounds_left;
	struct bench_state *owner;
};

struct bench_state {
	struct event_base *base;
	size_t payload_len;
	int npairs;
	int pairs_finished;
	struct bench_pair *pairs;
	char *payload;
};

static void
consumer_read_cb(struct bufferevent *bev, void *arg)
{
	struct bench_pair *p = arg;
	struct bench_state *s = p->owner;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t n = evbuffer_get_length(in);

	if (n == 0)
		return;
	evbuffer_drain(in, n);
	p->received_this_round += n;
	if (p->received_this_round < s->payload_len)
		return;

	p->received_this_round = 0;
	if (--p->rounds_left == 0) {
		if (++s->pairs_finished == s->npairs)
			event_base_loopbreak(s->base);
		return;
	}
	/* Drive the next round: the producer sends another payload. */
	bufferevent_write(p->producer, s->payload, s->payload_len);
}

static void
event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct bench_pair *p = arg;
	struct bench_state *s = p->owner;
	(void)bev;
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		fprintf(stderr, "bench: connection event 0x%x\n", events);
		event_base_loopbreak(s->base);
	}
}

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "usage: %s [--ssl] [--bytes N] [--rounds R] [--pairs P]\n"
	    "  --ssl             wrap each pair in TLS (needs OpenSSL)\n"
	    "  --bytes N         payload bytes per round (default 65536)\n"
	    "  --rounds R        round trips per pair (default 10000)\n"
	    "  --pairs P         number of concurrent socket pairs (default 1)\n",
	    prog);
}

int
main(int argc, char **argv)
{
	int use_ssl = 0;
	size_t payload_len = 65536;
	size_t k;
	int rounds = 10000;
	int npairs = 1;
	int i, j;
	evutil_socket_t sv[2];
	struct bench_pair *p;
	struct event_base *base = NULL;
	char *payload = NULL;
	struct bench_state state;
	struct timeval tv_start, tv_end, tv_diff;
	double elapsed, total_bytes;

	memset(&state, 0, sizeof(state));

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--ssl")) {
			use_ssl = 1;
		} else if (!strcmp(argv[i], "--bytes") && i + 1 < argc) {
			payload_len = (size_t)strtoull(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
			rounds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--pairs") && i + 1 < argc) {
			npairs = atoi(argv[++i]);
		} else {
			usage(argv[0]);
			return 2;
		}
	}
	if (payload_len == 0 || rounds <= 0 || npairs <= 0) {
		usage(argv[0]);
		return 2;
	}

	if (use_ssl) {
#ifdef EVENT__HAVE_OPENSSL
		if (ssl_setup() < 0) {
			fprintf(stderr, "bench: TLS setup failed\n");
			goto fail;
		}
#else
		fprintf(stderr,
		    "bench: built without OpenSSL; --ssl unavailable\n");
		return 2;
#endif
	}

	base = event_base_new();
	if (base == NULL) {
		fprintf(stderr, "bench: event_base_new failed\n");
		goto fail;
	}

	payload = malloc(payload_len);
	if (payload == NULL) {
		fprintf(stderr, "bench: malloc payload\n");
		goto fail;
	}
	for (k = 0; k < payload_len; ++k)
		payload[k] = (char)(k & 0xff);

	state.base = base;
	state.payload_len = payload_len;
	state.npairs = npairs;
	state.payload = payload;
	state.pairs = calloc(npairs, sizeof(*state.pairs));
	if (state.pairs == NULL) {
		fprintf(stderr, "bench: calloc pairs\n");
		goto fail;
	}

	for (j = 0; j < npairs; ++j) {
		sv[0] = sv[1] = -1;
		p = &state.pairs[j];

		if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
			perror("bench: socketpair");
			goto fail;
		}
		if (evutil_make_socket_nonblocking(sv[0]) < 0 ||
		    evutil_make_socket_nonblocking(sv[1]) < 0) {
			fprintf(stderr, "bench: make_nonblocking failed\n");
			evutil_closesocket(sv[0]);
			evutil_closesocket(sv[1]);
			goto fail;
		}

		p->owner = &state;
		p->rounds_left = rounds;
		if (use_ssl) {
#ifdef EVENT__HAVE_OPENSSL
			p->producer = ssl_wrap(base, sv[0], 0);
			p->consumer = ssl_wrap(base, sv[1], 1);
#endif
		} else {
			p->producer = bufferevent_socket_new(base, sv[0],
			    BEV_OPT_CLOSE_ON_FREE);
			p->consumer = bufferevent_socket_new(base, sv[1],
			    BEV_OPT_CLOSE_ON_FREE);
		}
		/* Each fd that was handed to a bufferevent is now owned by it
		 * (BEV_OPT_CLOSE_ON_FREE); clear our copy so the error path
		 * does not close it a second time. */
		if (p->producer != NULL)
			sv[0] = -1;
		if (p->consumer != NULL)
			sv[1] = -1;
		if (p->producer == NULL || p->consumer == NULL) {
			fprintf(stderr, "bench: bufferevent create failed\n");
			if (sv[0] >= 0)
				evutil_closesocket(sv[0]);
			if (sv[1] >= 0)
				evutil_closesocket(sv[1]);
			goto fail;
		}

		bufferevent_setcb(p->consumer, consumer_read_cb, NULL,
		    event_cb, p);
		bufferevent_setcb(p->producer, NULL, NULL, event_cb, p);
		if (bufferevent_enable(p->consumer, EV_READ) < 0 ||
		    bufferevent_enable(p->producer, EV_WRITE) < 0) {
			fprintf(stderr, "bench: bufferevent_enable failed\n");
			goto fail;
		}
		if (bufferevent_write(p->producer, payload, payload_len) < 0) {
			fprintf(stderr, "bench: initial write failed\n");
			goto fail;
		}
	}

	printf("bench_bufferevent: mode=%s payload=%lu rounds=%d pairs=%d\n",
	    use_ssl ? "tls" : "plain", (unsigned long)payload_len, rounds,
	    npairs);

	evutil_gettimeofday(&tv_start, NULL);
	if (event_base_dispatch(base) < 0) {
		fprintf(stderr, "bench: dispatch failed\n");
		goto fail;
	}
	evutil_gettimeofday(&tv_end, NULL);

	if (state.pairs_finished != npairs) {
		fprintf(stderr, "bench: short run, %d/%d pairs finished\n",
		    state.pairs_finished, npairs);
		goto fail;
	}

	evutil_timersub(&tv_end, &tv_start, &tv_diff);
	elapsed = tv_diff.tv_sec + tv_diff.tv_usec * 1e-6;
	total_bytes = (double)payload_len * (double)rounds * (double)npairs;
	printf("elapsed: %.3f s\n", elapsed);
	printf("throughput: %.2f MiB/s\n",
	    total_bytes / elapsed / (1024.0 * 1024.0));
	printf("per-round: %.3f us\n",
	    elapsed * 1e6 / ((double)rounds * (double)npairs));

	for (j = 0; j < npairs; ++j) {
		if (state.pairs[j].producer)
			bufferevent_free(state.pairs[j].producer);
		if (state.pairs[j].consumer)
			bufferevent_free(state.pairs[j].consumer);
	}
	free(state.pairs);
	event_base_free(base);
	free(payload);
#ifdef EVENT__HAVE_OPENSSL
	ssl_cleanup();
#endif
	return 0;

fail:
	if (state.pairs) {
		for (j = 0; j < npairs; ++j) {
			if (state.pairs[j].producer)
				bufferevent_free(state.pairs[j].producer);
			if (state.pairs[j].consumer)
				bufferevent_free(state.pairs[j].consumer);
		}
		free(state.pairs);
	}
	if (base)
		event_base_free(base);
	free(payload);
#ifdef EVENT__HAVE_OPENSSL
	ssl_cleanup();
#endif
	return 1;
}
