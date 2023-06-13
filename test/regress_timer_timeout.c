// Copyright (c) 2023 Krzysztof Dynowski krzydyn@gmail.com

#include <event2/event.h>
#include <event2/util.h>
#include "regress.h"
#include "time-internal.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#ifndef _WIN32
#include <unistd.h>
#endif

typedef struct
{
	struct event_base *eb;
	struct event *e;
	struct timeval tv_tmo;
} EventTimeoutTest;

static void trigger_timer(evutil_socket_t fd, short events, void * arg)
{
}

static void init_test(EventTimeoutTest *test, int flags)
{
	if (flags) {
		struct event_config * cfg = event_config_new();
		event_config_set_flag(cfg, flags);
		test->eb = event_base_new_with_config(cfg);
		event_config_free(cfg);
	} else {
		test->eb = event_base_new();
	}
	test->e = evtimer_new(test->eb, trigger_timer, NULL);
}
static void cleanup_test(EventTimeoutTest *test)
{
	event_del(test->e);
	event_free(test->e);
	event_base_free(test->eb);
}

static void set_timer_tv(EventTimeoutTest *test, const struct timeval* delay)
{
	int result;
	evutil_gettimeofday(&test->tv_tmo, NULL);
	result = evtimer_add(test->e, delay);
	if (result == -1) {
		perror("evtimer_add");
		exit(1);
	}
	evutil_timeradd(&test->tv_tmo, delay, &test->tv_tmo);
}
static void set_timer(EventTimeoutTest *test, const long delay_us)
{
	struct timeval tv;
	tv.tv_sec = delay_us/1000000;
	tv.tv_usec = delay_us%1000000;
	set_timer_tv(test, &tv);
}
static long remaining(EventTimeoutTest *test)
{
	struct timeval tv;
	struct timeval now, rem;
	int result = evtimer_pending(test->e, &tv);
	if (result == -1) {
		perror("evtimer_pending");
		exit(1);
	}
	if (result == 0) {
		return LONG_MAX;
	}
	evutil_gettimeofday(&now, NULL);
	evutil_timersub(&tv, &now, &rem);
	return rem.tv_sec*10000000L + rem.tv_usec;
}

static int test_with_flags(int flags)
{
	EventTimeoutTest test;
	long i;
	long err = 0;
	int maxdiff = 0;
	long rem, dur = 100;
	struct timeval sleep_tm = { 0, 1 };
	init_test(&test, flags);
	for (i = 0; i < 1000; ++i) {
		set_timer(&test, dur);
		rem = remaining(&test);
		if (rem > dur) {
			int d = rem - dur;
			++err;
			if (maxdiff < d) maxdiff = d;
		}
		evutil_usleep_(&sleep_tm);
	}
	(void)err;
	cleanup_test(&test);
	return maxdiff;
}

static void timer_timeout_test(void *arg)
{
	struct basic_test_data *data = arg;
	const char *flags_str = data ? data->setup_data : NULL;
	int maxdiff;
	if (flags_str == NULL) {
		maxdiff = test_with_flags(0);
		tt_int_op(maxdiff, ==, 0);
	} else if (strstr("precise", flags_str)) {
		maxdiff = test_with_flags(EVENT_BASE_FLAG_PRECISE_TIMER);
		tt_int_op(maxdiff, ==, 0);
	} else {
		tt_fail_msg("Unsupported clock");
	}
end:
	;
}

struct testcase_t event_timer_testcases[] = {
	{ "default_clock", timer_timeout_test, TT_FORK, &basic_setup, NULL },
	{ "precise_clock", timer_timeout_test, TT_FORK, &basic_setup, (void *)"precise" },
	END_OF_TESTCASES
};
