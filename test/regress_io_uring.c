/*
 * Regression tests for the EVENT_BASE_FLAG_IO_URING fast path.
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

#include <stdlib.h>
#include <string.h>

#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/util.h"

#include "event-internal.h"

#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#ifndef EVENT__HAVE_LIBURING

/* When liburing isn't built in, expose an empty test table so the registry
 * in regress_main.c can still reference io_uring_testcases unconditionally
 * if desired. The actual group registration in regress_main.c is gated on
 * EVENT__HAVE_LIBURING so this stub is normally unreachable. */
struct testcase_t io_uring_testcases[] = {
	END_OF_TESTCASES
};

#else /* EVENT__HAVE_LIBURING */

/* Helper: create a base with EVENT_BASE_FLAG_IO_URING. `extra_flags`
 * lets callers add e.g. EVENT_BASE_FLAG_IGNORE_ENV. */
static struct event_base *
make_uring_base(int extra_flags)
{
	struct event_config *cfg = event_config_new();
	struct event_base *base;

	if (cfg == NULL)
		return NULL;
	if (event_config_set_flag(cfg, EVENT_BASE_FLAG_IO_URING | extra_flags) < 0) {
		event_config_free(cfg);
		return NULL;
	}
	base = event_base_new_with_config(cfg);
	event_config_free(cfg);
	return base;
}

/* Skip the test (rather than fail) when the host kernel rejects io_uring.
 * io_uring is a Linux >= 5.1 feature; some CI runners and containers
 * disable it via seccomp or sysctl. */
#define SKIP_IF_NO_URING(base) do { \
	if ((base)->io_uring == NULL) { \
		tt_skip(); \
	} \
} while (0)

static void
test_io_uring_base_init(void *arg)
{
	struct event_base *base = NULL;

	(void)arg;
	base = make_uring_base(0);
	tt_assert(base != NULL);
	SKIP_IF_NO_URING(base);

end:
	if (base)
		event_base_free(base);
}

static void
test_io_uring_disabled_by_env(void *arg)
{
	struct event_base *base = NULL;

	(void)arg;
	/* EVENT_NOIO_URING in the environment should silently disable the
	 * ring; the base must still come up and base->io_uring must be
	 * NULL so the bufferevent fast path doesn't engage. */
	tt_assert(setenv("EVENT_NOIO_URING", "yes", 1) == 0);
	base = make_uring_base(0);
	tt_assert(base != NULL);
	tt_assert(base->io_uring == NULL);

end:
	unsetenv("EVENT_NOIO_URING");
	if (base)
		event_base_free(base);
}

static void
test_io_uring_ignore_env(void *arg)
{
	struct event_base *base = NULL;

	(void)arg;
	/* With EVENT_BASE_FLAG_IGNORE_ENV the env var must be ignored and
	 * the ring must still come up. */
	tt_assert(setenv("EVENT_NOIO_URING", "yes", 1) == 0);
	base = make_uring_base(EVENT_BASE_FLAG_IGNORE_ENV);
	tt_assert(base != NULL);
	SKIP_IF_NO_URING(base);

end:
	unsetenv("EVENT_NOIO_URING");
	if (base)
		event_base_free(base);
}

/* Bufferevent round-trip: payload travels writer -> reader through io_uring
 * readv/writev. Verifies that the async path moves bytes correctly and that
 * the user callbacks fire from the CQE drain. */
struct roundtrip_state {
	struct event_base *base;
	const char *payload;
	size_t payload_len;
	char *received;
	size_t received_len;
	size_t received_cap;
	int write_done;
};

static void
roundtrip_read_cb(struct bufferevent *bev, void *arg)
{
	struct roundtrip_state *s = arg;
	struct evbuffer *in = bufferevent_get_input(bev);
	size_t want = evbuffer_get_length(in);
	size_t cap = s->received_cap - s->received_len;
	size_t take = want < cap ? want : cap;

	if (take > 0) {
		evbuffer_remove(in, s->received + s->received_len, take);
		s->received_len += take;
	}
	if (s->received_len >= s->payload_len)
		event_base_loopbreak(s->base);
}

static void
roundtrip_write_cb(struct bufferevent *bev, void *arg)
{
	struct roundtrip_state *s = arg;
	(void)bev;
	s->write_done = 1;
}

static void
roundtrip_event_cb(struct bufferevent *bev, short events, void *arg)
{
	struct roundtrip_state *s = arg;
	(void)bev;
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF))
		event_base_loopbreak(s->base);
}

/* Shared body so the small and large payload tests reuse the same
 * machinery; the only difference is payload size. */
static void
roundtrip_with_payload(size_t payload_len)
{
	struct event_base *base = NULL;
	struct bufferevent *reader = NULL, *writer = NULL;
	evutil_socket_t sv[2] = { -1, -1 };
	char *payload = NULL, *received = NULL;
	struct roundtrip_state state;
	struct timeval cap = { 2, 0 };
	size_t i;

	memset(&state, 0, sizeof(state));

	base = make_uring_base(0);
	tt_assert(base != NULL);
	SKIP_IF_NO_URING(base);

	tt_assert(evutil_socketpair(AF_UNIX,
	    SOCK_STREAM | EVUTIL_SOCK_NONBLOCK, 0, sv) == 0);

	payload = malloc(payload_len);
	received = malloc(payload_len);
	tt_assert(payload != NULL);
	tt_assert(received != NULL);
	for (i = 0; i < payload_len; ++i)
		payload[i] = (char)(i & 0xff);

	state.base = base;
	state.payload = payload;
	state.payload_len = payload_len;
	state.received = received;
	state.received_cap = payload_len;

	reader = bufferevent_socket_new(base, sv[0], BEV_OPT_CLOSE_ON_FREE);
	writer = bufferevent_socket_new(base, sv[1], BEV_OPT_CLOSE_ON_FREE);
	tt_assert(reader != NULL);
	tt_assert(writer != NULL);
	sv[0] = sv[1] = -1; /* now owned by the bufferevents */

	bufferevent_setcb(reader, roundtrip_read_cb, NULL,
	    roundtrip_event_cb, &state);
	bufferevent_setcb(writer, NULL, roundtrip_write_cb,
	    roundtrip_event_cb, &state);

	tt_assert(bufferevent_enable(reader, EV_READ) == 0);
	tt_assert(bufferevent_enable(writer, EV_WRITE) == 0);

	tt_assert(bufferevent_write(writer, payload, payload_len) == 0);

	/* Watchdog so a regression can't hang the suite. */
	event_base_loopexit(base, &cap);

	event_base_dispatch(base);

	tt_int_op(state.received_len, ==, payload_len);
	tt_int_op(memcmp(state.received, payload, payload_len), ==, 0);

end:
	if (reader)
		bufferevent_free(reader);
	if (writer)
		bufferevent_free(writer);
	if (sv[0] >= 0)
		evutil_closesocket(sv[0]);
	if (sv[1] >= 0)
		evutil_closesocket(sv[1]);
	free(payload);
	free(received);
	if (base)
		event_base_free(base);
}

static void
test_io_uring_roundtrip_small(void *arg)
{
	(void)arg;
	roundtrip_with_payload(16);
}

static void
test_io_uring_roundtrip_large(void *arg)
{
	(void)arg;
	/* 64 KiB exercises multiple CQEs and likely multiple iovecs across
	 * the evbuffer reservation/peek paths. */
	roundtrip_with_payload(64 * 1024);
}

/* Tests run without basic_setup since each test creates its own base with
 * the io_uring flag set. */
struct testcase_t io_uring_testcases[] = {
	{ "base_init", test_io_uring_base_init, TT_FORK, NULL, NULL },
	{ "disabled_by_env", test_io_uring_disabled_by_env, TT_FORK,
	  NULL, NULL },
	{ "ignore_env", test_io_uring_ignore_env, TT_FORK, NULL, NULL },
	{ "roundtrip_small", test_io_uring_roundtrip_small, TT_FORK,
	  NULL, NULL },
	{ "roundtrip_large", test_io_uring_roundtrip_large, TT_FORK,
	  NULL, NULL },
	END_OF_TESTCASES
};

#endif /* EVENT__HAVE_LIBURING */
