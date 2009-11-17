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
#include <string.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#undef WIN32_LEAN_AND_MEAN

#include "iocp-internal.h"
#include "evthread-internal.h"

/* FIXME remove these ones */
#include <sys/queue.h>
#include "event2/event_struct.h"
#include "event-internal.h"

#define MAX_CALLS 16
struct dummy_overlapped {
	struct event_overlapped eo;
	void *lock;
	int call_count;
	uintptr_t keys[MAX_CALLS];
	ev_ssize_t sizes[MAX_CALLS];
};

static void
dummy_cb(struct event_overlapped *o, uintptr_t key, ev_ssize_t n, int ok)
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
pair_is_in(struct dummy_overlapped *o, uintptr_t key, ev_ssize_t n)
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
test_iocp_port(void *ptr)
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

	tt_assert(!event_iocp_activate_overlapped(port, &o1.eo, 10, 100));
	tt_assert(!event_iocp_activate_overlapped(port, &o2.eo, 20, 200));

	tt_assert(!event_iocp_activate_overlapped(port, &o1.eo, 11, 101));
	tt_assert(!event_iocp_activate_overlapped(port, &o2.eo, 21, 201));

	tt_assert(!event_iocp_activate_overlapped(port, &o1.eo, 12, 102));
	tt_assert(!event_iocp_activate_overlapped(port, &o2.eo, 22, 202));

	tt_assert(!event_iocp_activate_overlapped(port, &o1.eo, 13, 103));
	tt_assert(!event_iocp_activate_overlapped(port, &o2.eo, 23, 203));

#ifdef WIN32
	/* FIXME Be smarter. */
	Sleep(1000);
#endif

	tt_want(!event_iocp_shutdown(port, 2000));

	tt_int_op(o1.call_count, ==, 4);
	tt_int_op(o2.call_count, ==, 4);

	tt_want(pair_is_in(&o1, 10, 100));
	tt_want(pair_is_in(&o1, 11, 101));
	tt_want(pair_is_in(&o1, 12, 102));
	tt_want(pair_is_in(&o1, 13, 103));

	tt_want(pair_is_in(&o2, 20, 200));
	tt_want(pair_is_in(&o2, 21, 201));
	tt_want(pair_is_in(&o2, 22, 202));
	tt_want(pair_is_in(&o2, 23, 203));

end:
	/* FIXME free the locks. */
	;
}

static struct evbuffer *rbuf = NULL, *wbuf = NULL;

static void
read_complete(struct event_overlapped *eo, uintptr_t key,
    ev_ssize_t nbytes, int ok)
{
	tt_assert(ok);
	evbuffer_commit_read(rbuf, nbytes);
end:
	;
}

static void
write_complete(struct event_overlapped *eo, uintptr_t key,
    ev_ssize_t nbytes, int ok)
{
	tt_assert(ok);
	evbuffer_commit_write(wbuf, nbytes);
end:
	;
}

static void
test_iocp_evbuffer(void *ptr)
{
	struct event_overlapped rol, wol;
	struct basic_test_data *data = ptr;
	struct event_iocp_port *port = NULL;
	char junk[1024];
	int i;

	event_overlapped_init(&rol, read_complete);
	event_overlapped_init(&wol, write_complete);

#ifdef WIN32
	evthread_use_windows_threads();
#endif

	for (i = 0; i < sizeof(junk); ++i)
		junk[i] = (char)(i);

	rbuf = evbuffer_overlapped_new(data->pair[0]);
	wbuf = evbuffer_overlapped_new(data->pair[1]);
	evbuffer_enable_locking(rbuf, NULL);
	evbuffer_enable_locking(wbuf, NULL);

	port = event_iocp_port_launch();
	tt_assert(port);
	tt_assert(rbuf);
	tt_assert(wbuf);

	tt_assert(!event_iocp_port_associate(port, data->pair[0], 100));
	tt_assert(!event_iocp_port_associate(port, data->pair[1], 100));

	for (i=0;i<10;++i)
		evbuffer_add(wbuf, junk, sizeof(junk));

	tt_assert(!evbuffer_get_length(rbuf));
	tt_assert(!evbuffer_launch_write(wbuf, 512, &wol));
	tt_assert(!evbuffer_launch_read(rbuf, 2048, &rol));

#ifdef WIN32
	/* FIXME this is stupid. */
	Sleep(1000);
#endif

	tt_int_op(evbuffer_get_length(rbuf),==,512);

	/* FIXME Actually test some stuff here. */

	tt_want(!event_iocp_shutdown(port, 2000));
end:
	evbuffer_free(rbuf);
	evbuffer_free(wbuf);
}

static void
test_iocp_bufferevent_async(void *ptr)
{
	struct basic_test_data *data = ptr;
	struct event_iocp_port *port = NULL;
	struct bufferevent *bea1=NULL, *bea2=NULL;
	char buf[128];
	size_t n;
	struct timeval one_sec = {1,0};


#ifdef WIN32
	evthread_use_windows_threads();
#endif

	event_base_start_iocp(data->base);
	port = event_base_get_iocp(data->base);
	tt_assert(port);

	bea1 = bufferevent_async_new(data->base, data->pair[0],
	    BEV_OPT_DEFER_CALLBACKS);
	bea2 = bufferevent_async_new(data->base, data->pair[1],
	    BEV_OPT_DEFER_CALLBACKS);
	tt_assert(bea1);
	tt_assert(bea2);

	/*FIXME set some callbacks */
	bufferevent_enable(bea1, EV_WRITE);
	bufferevent_enable(bea2, EV_READ);

	bufferevent_write(bea1, "Hello world", strlen("Hello world")+1);

	event_base_loopexit(data->base, &one_sec);
	event_base_dispatch(data->base);

	n = bufferevent_read(bea2, buf, sizeof(buf)-1);
	buf[n]='\0';
	tt_str_op(buf, ==, "Hello world");

	tt_want(!event_iocp_shutdown(port, 2000));
end:
	/* FIXME: free stuff. */;
}


struct testcase_t iocp_testcases[] = {
	{ "port", test_iocp_port, TT_FORK, NULL, NULL },
	{ "evbuffer", test_iocp_evbuffer, TT_FORK|TT_NEED_SOCKETPAIR,
	  &basic_setup, NULL },
	{ "bufferevent_async", test_iocp_bufferevent_async,
	  TT_FORK|TT_NEED_SOCKETPAIR|TT_NEED_BASE, &basic_setup, NULL },
	END_OF_TESTCASES
};
