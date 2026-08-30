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
 * Microbenchmark for the per-iteration overhead of a non-blocking event
 * loop with no pending timeouts -- the "busy poll" pattern. Each iteration
 * runs event_base_loop(base, EVLOOP_NONBLOCK) with an empty timer heap, so
 * it isolates the loop's own bookkeeping (time caching, backend dispatch)
 * from any event work. A single persistent, never-readable pipe event keeps
 * the loop alive without ever firing.
 *
 * Reports nanoseconds per loop iteration.
 */

#include "event2/event-config.h"

#include <sys/types.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <getopt.h>
#else /* _WIN32 */
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <event.h>
#include <evutil.h>

static void
nop_cb(evutil_socket_t fd, short which, void *arg)
{
	/* never invoked: the fd is never readable */
}

int
main(int argc, char **argv)
{
	struct event_config *cfg;
	struct event_base *base;
	struct event *keepalive;
	evutil_socket_t pair[2];
	struct timeval start, end;
	long i, count = 2000000;
	double total_us, ns_per_iter;
	int c;

	while ((c = getopt(argc, argv, "n:")) != -1) {
		switch (c) {
		case 'n':
			count = atol(optarg);
			break;
		default:
			fprintf(stderr, "Illegal argument \"%c\"\n", c);
			exit(1);
		}
	}

	cfg = event_config_new();
	/* PRECISE_TIMER exercises the timerfd path on kernels without
	 * epoll_pwait2(); harmless elsewhere. */
	event_config_set_flag(cfg, EVENT_BASE_FLAG_PRECISE_TIMER);
	base = event_base_new_with_config(cfg);
	if (base == NULL) {
		fprintf(stderr, "event_base_new_with_config failed\n");
		exit(1);
	}

	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		perror("evutil_socketpair");
		exit(1);
	}

	keepalive = event_new(base, pair[0], EV_READ | EV_PERSIST, nop_cb, NULL);
	if (keepalive == NULL || event_add(keepalive, NULL) == -1) {
		fprintf(stderr, "could not add keepalive event\n");
		exit(1);
	}

	evutil_gettimeofday(&start, NULL);
	for (i = 0; i < count; i++)
		event_base_loop(base, EVLOOP_NONBLOCK);
	evutil_gettimeofday(&end, NULL);

	evutil_timersub(&end, &start, &end);
	total_us = end.tv_sec * 1000000.0 + end.tv_usec;
	ns_per_iter = total_us * 1000.0 / (double)count;

	fprintf(stdout, "%.2f ns/iter (%ld iterations, %.0f ms total)\n",
		ns_per_iter, count, total_us / 1000.0);

	event_free(keepalive);
	event_base_free(base);
	event_config_free(cfg);
	evutil_closesocket(pair[0]);
	evutil_closesocket(pair[1]);
	return 0;
}
