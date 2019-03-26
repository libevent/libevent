/*
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
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>

#include "event2/event.h"
#include "event2/watch.h"
#include "regress.h"

static int iteration = 0;
static int prepare_callback_1_count = 0;
static int prepare_callback_2_count = 0;
static int check_callback_1_count = 0;
static int check_callback_2_count = 0;
static struct timeval start_time = { 0, 0 };
static struct timeval end_time = { 0, 0 };
static int user_arg = 8675309;

static void
prepare_callback_1(struct evwatch *watcher, const struct evwatch_prepare_cb_info *info, void *arg)
{
	struct timeval timeout;
	int timeout_msec;

	/* user argument should be passed properly */
	tt_ptr_op(arg, ==, &user_arg);

	++prepare_callback_1_count;

	/* prepare_callback_1 should always fire before prepare_callback_2, and
	 * before both check callbacks */
	tt_int_op(prepare_callback_1_count, >, prepare_callback_2_count);
	tt_int_op(prepare_callback_1_count, >, check_callback_1_count);
	tt_int_op(prepare_callback_1_count, >, check_callback_2_count);

	/* if we've just scheduled the timeout event at the beginning of the
	 * iteration, save the current time and assert that the timeout is
	 * roughly what we set (this won't be exact on some platforms) */
	if (start_time.tv_sec == 0) {
		event_base_gettimeofday_cached(evwatch_base(watcher), &start_time);
		tt_int_op(evwatch_prepare_get_timeout(info, &timeout), ==, 1);

		timeout_msec = (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000);
		tt_int_op(timeout_msec, >=, 995);
		tt_int_op(timeout_msec, <=, 1005);
	}
end:
	;
}

static void
prepare_callback_2(struct evwatch *watcher, const struct evwatch_prepare_cb_info *info, void *arg)
{
	/* user argument should be passed properly */
	tt_ptr_op(arg, ==, &user_arg);

	++prepare_callback_2_count;

	/* prepare_callback_2 should only fire on the first iteration, and
	* should fire before both check callbacks */
	tt_int_op(iteration, ==, 0);
	tt_int_op(prepare_callback_2_count, >, check_callback_1_count);
	tt_int_op(prepare_callback_2_count, >, check_callback_2_count);
end:
	;
}

static void
check_callback_1(struct evwatch *watcher, const struct evwatch_check_cb_info *info, void *arg)
{
	/* user argument should be passed properly */
	tt_ptr_op(arg, ==, &user_arg);

	++check_callback_1_count;

	/* check_callback_1 should always fire before check_callback_2 */
	tt_int_op(check_callback_1_count, >, check_callback_2_count);

	/* save the end time, in case the timeout fires this time through the
	 * event loop */
	event_base_gettimeofday_cached(evwatch_base(watcher), &end_time);
end:
	;
}

static void
check_callback_2(struct evwatch *watcher, const struct evwatch_check_cb_info *info, void *arg)
{
	/* user argument should be passed properly */
	tt_ptr_op(arg, ==, &user_arg);

	++check_callback_2_count;

	/* check_callback_2 should only fire on the first iteration */
	tt_int_op(iteration, ==, 0);
end:
	;
}

static void
timeout_callback(evutil_socket_t fd, short events, void *arg)
{
	/* the duration between the start and end times should be at least 1
	 * second */
	tt_int_op(end_time.tv_sec, >=, start_time.tv_sec + 1);
end:
	;
}

/**
  This tests a few important properties of "prepare" and "check" watchers:
    - Watchers should be called in the order they were registered.
    - Prepare watchers should be called before check watchers.
    - Freeing a watcher will stop callbacks to it, but not to other watchers.
    - Reported durations should align with the registered timeouts.
    - It should be possible to call back into libevent from a callback without a
      recursive lock.
    - If this test is compiled with ASAN or similar, this test also illustrates
      that event_base_free will free any watchers not previously freed by
      evwatch_free.
 */
static void
test_callback_ordering(void *ptr)
{
	struct basic_test_data *data = ptr;
	struct event_base *base = data->base;
	struct evwatch *prepare_callback_2_watcher;
	struct evwatch *check_callback_2_watcher;
	struct timeval timeout;

	/* install prepare and check watchers */
	evwatch_prepare_new(base, &prepare_callback_1, &user_arg);
	evwatch_check_new(base, &check_callback_1, &user_arg);
	prepare_callback_2_watcher = evwatch_prepare_new(base, &prepare_callback_2, &user_arg);
	check_callback_2_watcher = evwatch_check_new(base, &check_callback_2, &user_arg);

	/* schedule an 1 second timeout event, and run the event loop until the
	 * timeout fires */
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	event_base_once(base, -1, EV_TIMEOUT, &timeout_callback, 0, &timeout);
	event_base_dispatch(base);

	/* second iteration: free two of the watchers, schedule a timeout and
	 * run the event loop again */
	iteration = 1;
	start_time.tv_sec = 0;
	evwatch_free(prepare_callback_2_watcher);
	evwatch_free(check_callback_2_watcher);
	event_base_once(base, -1, EV_TIMEOUT, &timeout_callback, 0, &timeout);
	event_base_dispatch(base);
}

static void
prepare_callback_3(struct evwatch *watcher, const struct evwatch_prepare_cb_info *info, void *arg)
{
	/* timeout should not be written to */
	struct timeval timeout = { 123, 456 };
	tt_int_op(evwatch_prepare_get_timeout(info, &timeout), ==, 0);
	tt_int_op(timeout.tv_sec, ==, 123);
	tt_int_op(timeout.tv_usec, ==, 456);
end:
	;
}

/**
  Test that evwatch_prepare_get_timeout behaves correctly when there is no
  timeout.
 */
static void
test_timeout_unavailable(void *ptr)
{
	struct basic_test_data *data = ptr;
	struct event_base *base = data->base;

	evwatch_prepare_new(base, &prepare_callback_3, NULL);
	event_base_dispatch(base);
}

#ifndef EVENT__DISABLE_MM_REPLACEMENT
static void *
bad_malloc(size_t sz)
{
	return NULL;
}

/**
  Test that creating prepare and check watchers fails gracefully if we can't
  allocate memory.
 */
static void
test_malloc_failure(void *ptr)
{
	struct basic_test_data *data = ptr;
	struct event_base *base = data->base;
	struct evwatch *bad_prepare, *bad_check;

	event_set_mem_functions(bad_malloc, realloc, free);
	bad_prepare = evwatch_prepare_new(base, &prepare_callback_1, NULL);
	tt_ptr_op(bad_prepare, ==, NULL);

	bad_check = evwatch_check_new(base, &check_callback_1, NULL);
	tt_ptr_op(bad_check, ==, NULL);

	event_set_mem_functions(malloc, realloc, free);
end:
	;
}
#endif

struct testcase_t watch_testcases[] = {
	BASIC(callback_ordering, TT_FORK|TT_NEED_BASE),
	BASIC(timeout_unavailable, TT_FORK|TT_NEED_BASE),
#ifndef EVENT__DISABLE_MM_REPLACEMENT
	BASIC(malloc_failure, TT_FORK|TT_NEED_BASE),
#endif
	END_OF_TESTCASES
};
