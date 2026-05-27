/*
 * Throughput micro-benchmark for socket bufferevents, with an opt-in
 * EVENT_BASE_FLAG_IO_URING toggle so the io_uring fast path can be
 * compared head-to-head with the synchronous read/write path on the
 * same workload and hardware.
 *
 * Two bufferevents on a unix socketpair exchange a payload R times
 * in a producer -> consumer round trip; the run prints elapsed time
 * and aggregate throughput.
 *
 * Copyright (c) 2026 Libevent contributors
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

#include "event2/event-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/util.h"

struct bench_state {
	struct event_base *base;
	size_t payload_len;
	int rounds_left;
	int rounds_total;
	size_t received_this_round;
	struct bufferevent *producer;
	struct bufferevent *consumer;
	char *payload;
};

static double
now_seconds(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static void
consumer_read_cb(struct bufferevent *bev, void *arg)
{
	struct bench_state *s = arg;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t n = evbuffer_get_length(in);

	if (n == 0)
		return;
	evbuffer_drain(in, n);
	s->received_this_round += n;
	if (s->received_this_round < s->payload_len)
		return;

	s->received_this_round = 0;
	if (--s->rounds_left == 0) {
		event_base_loopbreak(s->base);
		return;
	}
	bufferevent_write(s->producer, s->payload, s->payload_len);
}

static void
event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct bench_state *s = arg;
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
	    "usage: %s [--uring] [--bytes N] [--rounds R]\n"
	    "  --uring           enable EVENT_BASE_FLAG_IO_URING (default off)\n"
	    "  --bytes N         payload bytes per round (default 65536)\n"
	    "  --rounds R        number of producer/consumer round trips (default 10000)\n",
	    prog);
}

int
main(int argc, char **argv)
{
	int use_uring = 0;
	size_t payload_len = 65536;
	int rounds = 10000;
	int i;
	int sv[2] = { -1, -1 };
	struct event_config *cfg = NULL;
	struct event_base *base = NULL;
	struct bufferevent *producer = NULL, *consumer = NULL;
	char *payload = NULL;
	struct bench_state state;
	double t0, t1, elapsed;
	double total_bytes;

	for (i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--uring")) {
			use_uring = 1;
		} else if (!strcmp(argv[i], "--bytes") && i + 1 < argc) {
			payload_len = (size_t)strtoull(argv[++i], NULL, 0);
		} else if (!strcmp(argv[i], "--rounds") && i + 1 < argc) {
			rounds = atoi(argv[++i]);
		} else {
			usage(argv[0]);
			return 2;
		}
	}
	if (payload_len == 0 || rounds <= 0) {
		usage(argv[0]);
		return 2;
	}

	cfg = event_config_new();
	if (cfg == NULL) {
		fprintf(stderr, "bench: event_config_new failed\n");
		return 1;
	}
	if (use_uring &&
	    event_config_set_flag(cfg, EVENT_BASE_FLAG_IO_URING) < 0) {
		fprintf(stderr, "bench: event_config_set_flag failed\n");
		goto fail;
	}
	base = event_base_new_with_config(cfg);
	event_config_free(cfg);
	cfg = NULL;
	if (base == NULL) {
		fprintf(stderr, "bench: event_base_new_with_config failed\n");
		return 1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		perror("bench: socketpair");
		goto fail;
	}
	if (evutil_make_socket_nonblocking(sv[0]) < 0 ||
	    evutil_make_socket_nonblocking(sv[1]) < 0) {
		fprintf(stderr, "bench: make_nonblocking failed\n");
		goto fail;
	}

	payload = malloc(payload_len);
	if (payload == NULL) {
		fprintf(stderr, "bench: malloc payload\n");
		goto fail;
	}
	for (size_t k = 0; k < payload_len; ++k)
		payload[k] = (char)(k & 0xff);

	producer = bufferevent_socket_new(base, sv[0], BEV_OPT_CLOSE_ON_FREE);
	consumer = bufferevent_socket_new(base, sv[1], BEV_OPT_CLOSE_ON_FREE);
	if (producer == NULL || consumer == NULL) {
		fprintf(stderr, "bench: bufferevent_socket_new failed\n");
		goto fail;
	}
	sv[0] = sv[1] = -1; /* owned by the bufferevents now */

	memset(&state, 0, sizeof(state));
	state.base = base;
	state.payload_len = payload_len;
	state.rounds_left = rounds;
	state.rounds_total = rounds;
	state.payload = payload;
	state.producer = producer;
	state.consumer = consumer;

	bufferevent_setcb(consumer, consumer_read_cb, NULL, event_cb, &state);
	bufferevent_setcb(producer, NULL, NULL, event_cb, &state);
	if (bufferevent_enable(consumer, EV_READ) < 0 ||
	    bufferevent_enable(producer, EV_WRITE) < 0) {
		fprintf(stderr, "bench: bufferevent_enable failed\n");
		goto fail;
	}

	/* Kick off the first round. */
	if (bufferevent_write(producer, payload, payload_len) < 0) {
		fprintf(stderr, "bench: initial write failed\n");
		goto fail;
	}

	printf("bench_bufferevent_io: mode=%s payload=%zu rounds=%d\n",
	    use_uring ? "io_uring" : "syscall", payload_len, rounds);

	t0 = now_seconds();
	if (event_base_dispatch(base) < 0) {
		fprintf(stderr, "bench: dispatch failed\n");
		goto fail;
	}
	t1 = now_seconds();

	if (state.rounds_left != 0) {
		fprintf(stderr, "bench: short run, %d rounds remaining\n",
		    state.rounds_left);
		goto fail;
	}

	elapsed = t1 - t0;
	total_bytes = (double)payload_len * (double)rounds;
	printf("elapsed: %.3f s\n", elapsed);
	printf("throughput: %.2f MiB/s (%.0f bytes/s)\n",
	    total_bytes / elapsed / (1024.0 * 1024.0),
	    total_bytes / elapsed);
	printf("per-round: %.3f us\n", elapsed * 1e6 / (double)rounds);

	bufferevent_free(producer);
	bufferevent_free(consumer);
	event_base_free(base);
	free(payload);
	return 0;

fail:
	if (producer)
		bufferevent_free(producer);
	if (consumer)
		bufferevent_free(consumer);
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	if (cfg)
		event_config_free(cfg);
	if (base)
		event_base_free(base);
	free(payload);
	return 1;
}
