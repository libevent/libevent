/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
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

/* The old tests here need assertions to work. */
#undef NDEBUG

#include "event2/event-config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _EVENT_HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef _EVENT_HAVE_PTHREADS
#include <pthread.h>
#elif defined(WIN32)
#include <process.h>
#endif
#include <assert.h>
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "sys/queue.h"

#include "event2/util.h"
#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/thread.h"
#include "evthread-internal.h"
#include "event-internal.h"
#include "defer-internal.h"
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
wake_all_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	EVLOCK_LOCK(cw->lock, 0);
	EVTHREAD_COND_BROADCAST(cw->cond);
	EVLOCK_UNLOCK(cw->lock, 0);

}

static void
wake_one_timeout(evutil_socket_t fd, short what, void *arg)
{
	struct cond_wait *cw = arg;
	EVLOCK_LOCK(cw->lock, 0);
	EVTHREAD_COND_SIGNAL(cw->cond);
	EVLOCK_UNLOCK(cw->lock, 0);
}

#define NUM_THREADS	100
#define NUM_ITERATIONS  100
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

	evtimer_assign(&ev, base, wake_all_timeout, &cw);
	for (i = 0; i < NUM_ITERATIONS; i++) {
		struct timeval tv;
		evutil_timerclear(&tv);
		tv.tv_sec = 0;
		tv.tv_usec = 3000;

		EVLOCK_LOCK(cw.lock, 0);
		/* we need to make sure that event does not happen before
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
	if (count >= NUM_THREADS * NUM_ITERATIONS)
		event_base_loopexit(base, NULL);
	EVLOCK_UNLOCK(count_lock, 0);

	EVTHREAD_FREE_LOCK(cw.lock, 0);
	EVTHREAD_FREE_COND(cw.cond);

	THREAD_RETURN();
}

static int notification_fd_used = 0;
#ifndef WIN32
static int got_sigchld = 0;
static void
sigchld_cb(evutil_socket_t fd, short event, void *arg)
{
	struct timeval tv;
	struct event_base *base = arg;

	got_sigchld++;
	tv.tv_usec = 100000;
	tv.tv_sec = 0;
	event_base_loopexit(base, &tv);
}


static void
notify_fd_cb(evutil_socket_t fd, short event, void *arg)
{
	++notification_fd_used;
}
#endif

static void
thread_basic(void *arg)
{
	THREAD_T threads[NUM_THREADS];
	struct event ev;
	struct timeval tv;
	int i;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;

	struct event *notification_event = NULL;
	struct event *sigchld_event = NULL;

	EVTHREAD_ALLOC_LOCK(count_lock, 0);
	tt_assert(count_lock);

	tt_assert(base);
	if (evthread_make_base_notifiable(base)<0) {
		tt_abort_msg("Couldn't make base notifiable!");
	}

#ifndef WIN32
	if (data->setup_data && !strcmp(data->setup_data, "forking")) {
		pid_t pid;
		int status;
		sigchld_event = evsignal_new(base, SIGCHLD, sigchld_cb, base);
		/* This piggybacks on the th_notify_fd weirdly, and looks
		 * inside libevent internals.  Not a good idea in non-testing
		 * code! */
		notification_event = event_new(base,
		    base->th_notify_fd[0], EV_READ|EV_PERSIST, notify_fd_cb,
		    NULL);
		event_add(sigchld_event, NULL);
		event_add(notification_event, NULL);

		if ((pid = fork()) == 0) {
			event_del(notification_event);
			if (event_reinit(base) < 0) {
				TT_FAIL(("reinit"));
				exit(1);
			}
			event_assign(notification_event, base,
			    base->th_notify_fd[0], EV_READ|EV_PERSIST,
			    notify_fd_cb, NULL);
			event_add(notification_event, NULL);
	 		goto child;
		}

		event_base_dispatch(base);

		if (waitpid(pid, &status, 0) == -1)
			tt_abort_perror("waitpid");
		TT_BLATHER(("Waitpid okay\n"));

		tt_assert(got_sigchld);
		tt_int_op(notification_fd_used, ==, 0);

		goto end;
	}

child:
#endif
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

	tt_int_op(count, ==, NUM_THREADS * NUM_ITERATIONS);

	EVTHREAD_FREE_LOCK(count_lock, 0);

	TT_BLATHER(("notifiations==%d", notification_fd_used));

end:

	if (notification_event)
		event_free(notification_event);
	if (sigchld_event)
		event_free(sigchld_event);
}

#undef NUM_THREADS
#define NUM_THREADS 10

struct alerted_record {
	struct cond_wait *cond;
	struct timeval delay;
	struct timeval alerted_at;
	int timed_out;
};

static THREAD_FN
wait_for_condition(void *arg)
{
	struct alerted_record *rec = arg;
	int r;

	EVLOCK_LOCK(rec->cond->lock, 0);
	if (rec->delay.tv_sec || rec->delay.tv_usec) {
		r = EVTHREAD_COND_WAIT_TIMED(rec->cond->cond, rec->cond->lock,
		    &rec->delay);
	} else {
		r = EVTHREAD_COND_WAIT(rec->cond->cond, rec->cond->lock);
	}
	EVLOCK_UNLOCK(rec->cond->lock, 0);

	evutil_gettimeofday(&rec->alerted_at, NULL);
	if (r == 1)
		rec->timed_out = 1;

	THREAD_RETURN();
}

static void
thread_conditions_simple(void *arg)
{
	struct timeval tv_signal, tv_timeout, tv_broadcast;
	struct alerted_record alerted[NUM_THREADS];
	THREAD_T threads[NUM_THREADS];
	struct cond_wait cond;
	int i;
	struct timeval launched_at;
	struct event wake_one;
	struct event wake_all;
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	int n_timed_out=0, n_signal=0, n_broadcast=0;

	tv_signal.tv_sec = tv_timeout.tv_sec = tv_broadcast.tv_sec = 0;
	tv_signal.tv_usec = 30*1000;
	tv_timeout.tv_usec = 150*1000;
	tv_broadcast.tv_usec = 500*1000;

	EVTHREAD_ALLOC_LOCK(cond.lock, EVTHREAD_LOCKTYPE_RECURSIVE);
	EVTHREAD_ALLOC_COND(cond.cond);
	tt_assert(cond.lock);
	tt_assert(cond.cond);
	for (i = 0; i < NUM_THREADS; ++i) {
		memset(&alerted[i], 0, sizeof(struct alerted_record));
		alerted[i].cond = &cond;
	}

	/* Threads 5 and 6 will be allowed to time out */
	memcpy(&alerted[5].delay, &tv_timeout, sizeof(tv_timeout));
	memcpy(&alerted[6].delay, &tv_timeout, sizeof(tv_timeout));

	evtimer_assign(&wake_one, base, wake_one_timeout, &cond);
	evtimer_assign(&wake_all, base, wake_all_timeout, &cond);

	evutil_gettimeofday(&launched_at, NULL);

	/* Launch the threads... */
	for (i = 0; i < NUM_THREADS; ++i) {
		THREAD_START(threads[i], wait_for_condition, &alerted[i]);
	}

	/* Start the timers... */
	tt_int_op(event_add(&wake_one, &tv_signal), ==, 0);
	tt_int_op(event_add(&wake_all, &tv_broadcast), ==, 0);

	/* And run for a bit... */
	event_base_dispatch(base);

	/* And wait till the threads are done. */
	for (i = 0; i < NUM_THREADS; ++i)
		THREAD_JOIN(threads[i]);

	/* Now, let's see what happened. At least one of 5 or 6 should
	 * have timed out. */
	n_timed_out = alerted[5].timed_out + alerted[6].timed_out;
	tt_int_op(n_timed_out, >=, 1);
	tt_int_op(n_timed_out, <=, 2);

	for (i = 0; i < NUM_THREADS; ++i) {
		const struct timeval *target_delay;
		struct timeval target_time, actual_delay;
		if (alerted[i].timed_out) {
			TT_BLATHER(("%d looks like a timeout\n", i));
			target_delay = &tv_timeout;
			tt_assert(i == 5 || i == 6);
		} else if (evutil_timerisset(&alerted[i].alerted_at)) {
			long diff1,diff2;
			evutil_timersub(&alerted[i].alerted_at,
			    &launched_at, &actual_delay);
			diff1 = timeval_msec_diff(&actual_delay,
			    &tv_signal);
			diff2 = timeval_msec_diff(&actual_delay,
			    &tv_broadcast);
			if (abs(diff1) < abs(diff2)) {
				TT_BLATHER(("%d looks like a signal\n", i));
				target_delay = &tv_signal;
				++n_signal;
			} else {
				TT_BLATHER(("%d looks like a broadcast\n", i));
				target_delay = &tv_broadcast;
				++n_broadcast;
			}
		} else {
			TT_FAIL(("Thread %d never got woken", i));
			continue;
		}
		evutil_timeradd(target_delay, &launched_at, &target_time);
		test_timeval_diff_leq(&target_time, &alerted[i].alerted_at,
		    0, 50);
	}
	tt_int_op(n_broadcast + n_signal + n_timed_out, ==, NUM_THREADS);
	tt_int_op(n_signal, ==, 1);

end:
	;
}

#define CB_COUNT 128
#define QUEUE_THREAD_COUNT 8

#ifdef WIN32
#define SLEEP_MS(ms) Sleep(ms)
#else
#define SLEEP_MS(ms) usleep((ms) * 1000)
#endif

struct deferred_test_data {
	struct deferred_cb cbs[CB_COUNT];
	struct deferred_cb_queue *queue;
};

static time_t timer_start = 0;
static time_t timer_end = 0;
static unsigned callback_count = 0;
static THREAD_T load_threads[QUEUE_THREAD_COUNT];
static struct deferred_test_data deferred_data[QUEUE_THREAD_COUNT];

static void
deferred_callback(struct deferred_cb *cb, void *arg)
{
	SLEEP_MS(1);
	callback_count += 1;
}

static THREAD_FN
load_deferred_queue(void *arg)
{
	struct deferred_test_data *data = arg;
	size_t i;

	for (i = 0; i < CB_COUNT; ++i) {
		event_deferred_cb_init(&data->cbs[i], deferred_callback, NULL);
		event_deferred_cb_schedule(data->queue, &data->cbs[i]);
		SLEEP_MS(1);
	}

	THREAD_RETURN();
}

static void
timer_callback(evutil_socket_t fd, short what, void *arg)
{
	timer_end = time(NULL);
}

static void
start_threads_callback(evutil_socket_t fd, short what, void *arg)
{
	int i;

	for (i = 0; i < QUEUE_THREAD_COUNT; ++i) {
		THREAD_START(load_threads[i], load_deferred_queue,
				&deferred_data[i]);
	}
}

static void
thread_deferred_cb_skew(void *arg)
{
	struct basic_test_data *data = arg;
	struct timeval tv_timer = {4, 0};
	struct deferred_cb_queue *queue;
	time_t elapsed;
	int i;

	queue = event_base_get_deferred_cb_queue(data->base);
	tt_assert(queue);

	for (i = 0; i < QUEUE_THREAD_COUNT; ++i)
		deferred_data[i].queue = queue;

	timer_start = time(NULL);
	event_base_once(data->base, -1, EV_TIMEOUT, timer_callback, NULL,
			&tv_timer);
	event_base_once(data->base, -1, EV_TIMEOUT, start_threads_callback,
			NULL, NULL);
	event_base_dispatch(data->base);

	elapsed = timer_end - timer_start;
	TT_BLATHER(("callback count, %u", callback_count));
	TT_BLATHER(("elapsed time, %u", (unsigned)elapsed));
	/* XXX be more intelligent here.  just make sure skew is
	 * within 2 seconds for now. */
	tt_assert(elapsed >= 4 && elapsed <= 6);

end:
	for (i = 0; i < QUEUE_THREAD_COUNT; ++i)
		THREAD_JOIN(load_threads[i]);
}

#define TEST(name)							\
	{ #name, thread_##name, TT_FORK|TT_NEED_THREADS|TT_NEED_BASE,	\
	  &basic_setup, NULL }

struct testcase_t thread_testcases[] = {
	{ "basic", thread_basic, TT_FORK|TT_NEED_THREADS|TT_NEED_BASE,
	  &basic_setup, NULL },
#ifndef WIN32
	{ "forking", thread_basic, TT_FORK|TT_NEED_THREADS|TT_NEED_BASE,
	  &basic_setup, (char*)"forking" },
#endif
	TEST(conditions_simple),
	TEST(deferred_cb_skew),
	END_OF_TESTCASES
};

