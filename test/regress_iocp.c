/*
 * Copyright (c) 2009 Niels Provos and Nick Mathewson
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

#include <stdlib.h>
#include <event2/event.h>
#include <event2/thread.h>

#include "tinytest.h"
#include "tinytest_macros.h"

#include "iocp-internal.h"
#include "evthread-internal.h"

#define MAX_CALLS 16
struct dummy_overlapped {
	struct event_overlapped eo;
	void *lock;
	int call_count;
	uintptr_t keys[MAX_CALLS];
	ssize_t sizes[MAX_CALLS];
};

static void
dummy_cb(struct event_overlapped *o, uintptr_t key, ssize_t n)
{
	struct dummy_overlapped *d_o =
	    EVUTIL_UPCAST(o, struct dummy_overlapped, eo);

	EVLOCK_LOCK(d_o->lock, EVTHREAD_WRITE);
	if (d_o->call_count < MAX_CALLS) {
		d_o->keys[d_o->call_count] = key;
		d_o->sizes[d_o->call_count] = n;
	}
	d_o->call_count++;
	EVLOCK_UNLOCK(d_o->lock, EVTHREAD_WRITE);
}

static int
pair_is_in(struct dummy_overlapped *o, uintptr_t key, ssize_t n)
{
	int i;
	int result = 0;
	EVLOCK_LOCK(o->lock, EVTHREAD_WRITE);
	for (i=0; i < o->call_count; ++i) {
		if (o->keys[i] == key && o->sizes[i] == n) {
			result = 1;
			break;
		}
	}
	EVLOCK_UNLOCK(o->lock, EVTHREAD_WRITE);
	return result;
}

static void
test_iocp_port(void *loop)
{
	struct event_iocp_port *port = NULL;
	struct dummy_overlapped o1, o2;

#ifdef WIN32
	evthread_use_windows_threads();
#endif
	memset(&o1, 0, sizeof(o1));
	memset(&o2, 0, sizeof(o2));

	EVTHREAD_ALLOC_LOCK(o1.lock);
	EVTHREAD_ALLOC_LOCK(o2.lock);

	tt_assert(o1.lock);
	tt_assert(o2.lock);

	event_overlapped_init(&o1.eo, dummy_cb);
	event_overlapped_init(&o2.eo, dummy_cb);

	port = event_iocp_port_launch();
	tt_assert(port);

	tt_assert(!event_iocp_activate_overlapped(port, &o1.eo, 10, 105));
	tt_assert(!event_iocp_activate_overlapped(port, &o2.eo, 25, 205));

#ifdef WIN32
	/* FIXME Be smarter. */
	Sleep(1000);
#endif

	tt_want(!event_iocp_shutdown(port, 2000));

	tt_int_op(o1.call_count, ==, 1);
	tt_int_op(o2.call_count, ==, 1);
	tt_want(pair_is_in(&o1, 10, 105));
	tt_want(pair_is_in(&o2, 25, 205));

end:
	/* FIXME free the locks. */
	;
}

struct testcase_t iocp_testcases[] = {
	{ "iocp_port", test_iocp_port, TT_FORK, NULL, NULL },
	END_OF_TESTCASES
};
