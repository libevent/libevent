/*
 * This example spawns a number of worker threads all consuming work from the
 * main thread.
 * It exits cleanly in response to a SIGINT (ctrl-c).
 *
 * Copyright (c) 2019 David Disseldorp
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <sys/queue.h>
#include <unistd.h>

#include "event2/util.h"
#include "event2/thread.h"
#include "event2/event.h"

#ifdef NDEBUG
/* hack to avoid -Wunused-but-set-variable breakage */
#define ASSERT(x) do { (void)sizeof(x);} while (0)
#else
#include <assert.h>
#define ASSERT(x) assert(x)
#endif

#define NUM_THREADS 10
#define NUM_WORK 40
#define WORKER_SLEEP_MAX 4

struct main_state {
	struct event_base *base;
	int num_workers;
	TAILQ_HEAD(wstate_q, worker_state) wstates;
	int exit_pending;
	int work_items_completed;
	int work_items_cancelled;
};

struct worker_state {
	TAILQ_ENTRY(worker_state) next;
	struct event_base *wbase;
	struct event *exit_ev;
	pthread_t thread;
	struct main_state *ms;
};

enum {
	WORK_ITEM_QUEUED = 0,
	WORK_ITEM_PROCESSED,
	WORK_ITEM_CANCELLED,
};

struct work_item {
	int status;
	struct event *work_ev;
	struct event *completion_ev;
	struct main_state *ms;
};

/* exit callbacks are called from the main process */
static void
worker_exit_cb(evutil_socket_t fd, short what, void *user_data)
{
	struct worker_state *wstate = user_data;
	struct main_state *ms = wstate->ms;
	int ret;

	printf("main: worker thread exit cb\n");
	ret = pthread_join(wstate->thread, NULL);
	ASSERT(ret == 0);
	event_free(wstate->exit_ev);
	event_base_free(wstate->wbase);

	TAILQ_REMOVE(&ms->wstates, wstate, next);
	ms->num_workers--;
	free(wstate);

	if (ms->exit_pending && (ms->num_workers == 0)) {
		printf("main: pending exit now ready to proceed\n");
		event_base_loopbreak(ms->base);
	}
}

static void
worker_do_work(evutil_socket_t fd, short what, void *user_data)
{
	struct work_item *wi = user_data;
	unsigned int r = 0;

	evutil_secure_rng_get_bytes(&r, sizeof(r));
	r = r % (WORKER_SLEEP_MAX + 1);
	printf("worker 0x%lx: sleeping %d seconds\n", pthread_self(), r);
	sleep(r);
	printf("worker 0x%lx: finished %d second sleep\n", pthread_self(), r);
	wi->status = WORK_ITEM_PROCESSED;
	evuser_trigger(wi->completion_ev);
}

static void
work_completed_cb(evutil_socket_t fd, short what, void *user_data)
{
	struct work_item *wi = user_data;

	if (wi->status == WORK_ITEM_PROCESSED) {
		wi->ms->work_items_completed++;
		printf("main: %d work items completed\n",
		       wi->ms->work_items_completed);
	} else {
		ASSERT(wi->status == WORK_ITEM_CANCELLED);
		wi->ms->work_items_cancelled++;
		printf("main: %d work items cancelled\n",
		       wi->ms->work_items_cancelled);
	}
	if (wi->ms->work_items_completed == NUM_WORK) {
		printf("main: all work finished, press ctrl-c to exit...\n");
	}
	event_free(wi->work_ev);
	event_free(wi->completion_ev);
	free(wi);
}

/*
 * Take the worker from the front of the tailq and put it at the back after
 * queueing work on its event_base. This means that (ideally) we always schedule
 * new work on the worker thread that has waited the longest since receiving its
 * last new work, (i.e. is more likely to drain its queue first).
 *
 * Possible Optimisation:
 * Given that the time to process an item of work isn't uniform, the order of
 * the tailq likely won't properly represent first-to-drain probability. It'd
 * make sense to use the work completion event to explicitly move idle workers
 * to the front of the tailq.
 */
static void
queue_work(struct main_state *ms)
{
	int ret;
	struct work_item *wi;
	struct worker_state *wstate = TAILQ_FIRST(&ms->wstates);
	TAILQ_REMOVE(&ms->wstates, wstate, next);
	TAILQ_INSERT_TAIL(&ms->wstates, wstate, next);

	wi = malloc(sizeof(*wi));
	ASSERT(wi);
	memset(wi, 0, sizeof(*wi));

	wi->ms = ms;
	wi->completion_ev = evuser_new(ms->base, work_completed_cb, wi);
	ASSERT(wi->completion_ev);
	ret = event_add(wi->completion_ev, NULL);
	ASSERT(ret >= 0);

	printf("main: queueing work on thread %lx\n", wstate->thread);

	wi->work_ev = evuser_new(wstate->wbase, worker_do_work, wi);
	ASSERT(wi->work_ev);
	evuser_trigger(wi->work_ev);
	ret = event_add(wi->work_ev, NULL);
	ASSERT(ret >= 0);
}

static int
worker_cancel_unprocessed_work(const struct event_base *wbase,
			       const struct event *ev,
			       void *arg)
{
	struct work_item *wi;

	if (event_get_callback(ev) != worker_do_work) {
		return 0;
	}

	wi = event_get_callback_arg(ev);
	wi->status = WORK_ITEM_CANCELLED;
	evuser_trigger(wi->completion_ev);
	return 0;
}

static void *
worker(void *_worker_state)
{
	struct worker_state *wstate = _worker_state;
	int ret;

	printf("worker 0x%lx: waiting for work\n", pthread_self());

	event_base_loop(wstate->wbase, EVLOOP_NO_EXIT_ON_EMPTY);

	printf("worker 0x%lx: exiting\n", pthread_self());

	/* cancel unprocessed work in case we didn't get to drain everything */
	ret = event_base_foreach_event(wstate->wbase,
				       worker_cancel_unprocessed_work, NULL);
	ASSERT(ret == 0);

	evuser_trigger(wstate->exit_ev);
	pthread_exit(NULL);
}

static void
spawn_worker(struct main_state *ms)
{
	int ret;
	struct worker_state *wstate = malloc(sizeof(*wstate));

	ASSERT(wstate);
	memset(wstate, 0, sizeof(*wstate));
	wstate->ms = ms;
	wstate->wbase = event_base_new();
	ASSERT(wstate->wbase);

	/* exit_ev notifies main that this thread is exiting */
	wstate->exit_ev = evuser_new(ms->base, worker_exit_cb, wstate);
	ASSERT(wstate->exit_ev);
	ret = event_add(wstate->exit_ev, NULL);
	ASSERT(ret >= 0);

	ret = pthread_create(&wstate->thread, NULL, &worker, wstate);
	ASSERT(ret == 0);

	TAILQ_INSERT_HEAD(&ms->wstates, wstate, next);
	ms->num_workers++;
}


static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct main_state *ms = user_data;
	struct worker_state *wstate;
	struct timeval delay = { WORKER_SLEEP_MAX, 0 };

	printf("main: caught an interrupt signal, stopping...\n");

	/* tell worker_exit_cb() to exit the main loop after all workers stop */
	ms->exit_pending = 1;

	if (ms->num_workers == 0) {
		/* no need to wait for worker teardown */
		event_base_loopbreak(ms->base);
		return;
	}

	/* Tell workers to exit. They could be sleeping, so it may take time */
	TAILQ_FOREACH(wstate, &ms->wstates, next) {
		event_base_loopbreak(wstate->wbase);
	}

	/* tell the main base loop to exit unconditionally after a delay */
	event_base_loopexit(ms->base, &delay);
}

int
main(int argc, char **argv)
{
	struct main_state ms;
	struct event *signal_event;
	int ret;
	int i;

	/* only pthread based threading currently supported */
	evthread_use_pthreads();

	memset(&ms, 0, sizeof(ms));
	ms.base = event_base_new();
	ASSERT(ms.base);
	TAILQ_INIT(&ms.wstates);

	signal_event = evsignal_new(ms.base, SIGINT, signal_cb, &ms);
	ASSERT(signal_event);
	ret = event_add(signal_event, NULL);
	ASSERT(ret >= 0);

	for (i = 0; i < NUM_THREADS; i++) {
		spawn_worker(&ms);
	}

	for (i = 0; i < NUM_WORK; i++) {
		queue_work(&ms);
	}

	event_base_dispatch(ms.base);

	if (ms.num_workers == 0) {
		printf("main: all workers cleaned up\n");
		if (ms.work_items_cancelled > 0) {
			printf("main: cancelled %d unprocessed work items\n",
			       ms.work_items_cancelled);
		}
	} else {
		fprintf(stderr,
			"main error: %d workers still remain on exit\n",
			ms.num_workers);
	}

	event_free(signal_event);
	event_base_free(ms.base);

	return 0;
}
