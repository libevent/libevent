/*
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
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

#include "event-config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <assert.h>

#include "event2/util.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/thread.h"
#include "regress.h"
#include "tinytest_macros.h"

struct cond_wait {
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

static void
basic_timeout(int fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	assert(pthread_mutex_lock(&cw->lock) == 0);
	assert(pthread_cond_broadcast(&cw->cond) == 0);
	assert(pthread_mutex_unlock(&cw->lock) == 0);
}

#define NUM_THREADS	100
static pthread_mutex_t count_lock;
static int count;

static void *
basic_thread(void *arg)
{
	struct cond_wait cw;
	struct event_base *base = arg;
	struct event ev;
	int i = 0;

	assert(pthread_mutex_init(&cw.lock, NULL) == 0);
	assert(pthread_cond_init(&cw.cond, NULL) == 0);

	evtimer_assign(&ev, base, basic_timeout, &cw);
	for (i = 0; i < 100; i++) {
		struct timeval tv;
		evutil_timerclear(&tv);

		assert(pthread_mutex_lock(&cw.lock) == 0);
		/* we need to make sure that even does not happen before
		 * we get to wait on the conditional variable */
		assert(evtimer_add(&ev, &tv) == 0);
		assert(pthread_cond_wait(&cw.cond, &cw.lock) == 0);
		assert(pthread_mutex_unlock(&cw.lock) == 0);

		assert(pthread_mutex_lock(&count_lock) == 0);
		++count;
		assert(pthread_mutex_unlock(&count_lock) == 0);
	}

	/* exit the loop only if all threads fired all timeouts */
	assert(pthread_mutex_lock(&count_lock) == 0);
	if (count >= NUM_THREADS * 100)
		event_base_loopexit(base, NULL);
	assert(pthread_mutex_unlock(&count_lock) == 0);

	assert(pthread_cond_destroy(&cw.cond) == 0);
	assert(pthread_mutex_destroy(&cw.lock) == 0);

	return (NULL);
}

static void
pthread_basic(struct event_base *base)
{
	pthread_t threads[NUM_THREADS];
	struct event ev;
	struct timeval tv;
	int i;

	for (i = 0; i < NUM_THREADS; ++i)
		pthread_create(&threads[i], NULL, basic_thread, base);

	evtimer_assign(&ev, base, NULL, NULL);
	evutil_timerclear(&tv);
	tv.tv_sec = 1000;
	event_add(&ev, &tv);

	event_base_dispatch(base);

	for (i = 0; i < NUM_THREADS; ++i)
		pthread_join(threads[i], NULL);

	event_del(&ev);
}

void
regress_threads(void *arg)
{
	struct event_base *base;
        (void) arg;

	pthread_mutex_init(&count_lock, NULL);

        if (evthread_use_pthreads()<0)
		tt_abort_msg("Couldn't initialize pthreads!");

        base = event_base_new();
        if (evthread_make_base_notifiable(base)<0) {
                tt_abort_msg("Couldn't make base notifiable!");
        }

	pthread_basic(base);

	pthread_mutex_destroy(&count_lock);

	event_base_free(base);
end:
        ;
}
