/*
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
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

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _EVENT_HAVE_PTHREADS
#include <pthread.h>
#elif defined(WIN32)
#include <process.h>
#endif
#include <assert.h>

#include "event2/util.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/thread.h"
#include "evthread-internal.h"
#include "regress.h"
#include "tinytest_macros.h"

#ifdef _EVENT_HAVE_PTHREADS
#define THREAD_T pthread_t
#define THREAD_FN void *
#define THREAD_RETURN() return (NULL)
#define THREAD_START(threadvar, fn, arg) \
	pthread_create(&(threadvar), NULL, fn, arg)
#define THREAD_JOIN(th) pthread_join(th, NULL)
#else
#define THREAD_T HANDLE
#define THREAD_FN unsigned __stdcall
#define THREAD_RETURN() return (0)
#define THREAD_START(threadvar, fn, arg) do {		\
	uintptr_t threadhandle = _beginthreadex(NULL,0,fn,(arg),0,NULL); \
	(threadvar) = (HANDLE) threadhandle; \
	} while (0)
#define THREAD_JOIN(th) WaitForSingleObject(th, INFINITE)
#endif

struct cond_wait {
	void *lock;
	void *cond;
};

static void
basic_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	EVLOCK_LOCK(cw->lock, 0);
	EVTHREAD_COND_BROADCAST(cw->cond);
	EVLOCK_UNLOCK(cw->lock, 0);

}

#define NUM_THREADS	100
void *count_lock;
static int count;

static THREAD_FN
basic_thread(void *arg)
{
	struct cond_wait cw;
	struct event_base *base = arg;
	struct event ev;
	int i = 0;

	EVTHREAD_ALLOC_LOCK(cw.lock, 0);
	EVTHREAD_ALLOC_COND(cw.cond);
	assert(cw.lock);
	assert(cw.cond);

	evtimer_assign(&ev, base, basic_timeout, &cw);
	for (i = 0; i < 100; i++) {
		struct timeval tv;
		evutil_timerclear(&tv);

		EVLOCK_LOCK(cw.lock, 0);
		/* we need to make sure that even does not happen before
		 * we get to wait on the conditional variable */
		assert(evtimer_add(&ev, &tv) == 0);

		assert(EVTHREAD_COND_WAIT(cw.cond, cw.lock) == 0);
		EVLOCK_UNLOCK(cw.lock, 0);

		EVLOCK_LOCK(count_lock, 0);
		++count;
		EVLOCK_UNLOCK(count_lock, 0);
	}

	/* exit the loop only if all threads fired all timeouts */
	EVLOCK_LOCK(count_lock, 0);
	if (count >= NUM_THREADS * 100)
		event_base_loopexit(base, NULL);
	EVLOCK_UNLOCK(count_lock, 0);

	EVTHREAD_FREE_LOCK(cw.lock, 0);
	EVTHREAD_FREE_COND(cw.cond);

	THREAD_RETURN();
}

static void
thread_basic(void *arg)
{
	THREAD_T threads[NUM_THREADS];
	struct event ev;
	struct timeval tv;
	int i;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;

	EVTHREAD_ALLOC_LOCK(count_lock, 0);
	tt_assert(count_lock);

	tt_assert(base);
	if (evthread_make_base_notifiable(base)<0) {
		tt_abort_msg("Couldn't make base notifiable!");
	}

	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_START(threads[i], basic_thread, base);

	evtimer_assign(&ev, base, NULL, NULL);
	evutil_timerclear(&tv);
	tv.tv_sec = 1000;
	event_add(&ev, &tv);

	event_base_dispatch(base);

	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_JOIN(threads[i]);

	event_del(&ev);
	EVTHREAD_FREE_LOCK(count_lock, 0);
end:
	;
}

struct testcase_t thread_testcases[] = {
	{ "basic", thread_basic, TT_FORK|TT_NEED_THREADS|TT_NEED_BASE,
	  &basic_setup, NULL },
	END_OF_TESTCASES
};

