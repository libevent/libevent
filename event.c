/*
 * Copyright 2000-2002 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
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
#include "config.h"

#include <sys/types.h>
#include <sys/tree.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <assert.h>

#ifdef USE_LOG
#include "log.h"
#else
#define LOG_DBG(x)
#define log_error(x)	perror(x)
#endif

#include "event.h"

#ifdef HAVE_SELECT
extern struct eventop selectops;
#endif
#ifdef HAVE_WORKING_KQUEUE
extern struct eventop kqops;
#endif

/* In order of preference */
struct eventop *eventops[] = {
#ifdef HAVE_WORKING_KQUEUE
	&kqops,
#endif
#ifdef HAVE_SELECT
	&selectops,
#endif
	NULL
};

struct eventop *evsel;
void *evbase;

/* Handle signals */
int (*event_sigcb)(void);	/* Signal callback when gotsig is set */
int event_gotsig;		/* Set in signal handler */

/* Prototypes */
void	event_queue_insert(struct event *, int);
void	event_queue_remove(struct event *, int);

static RB_HEAD(event_tree, event) timetree;
static struct event_list activequeue;
struct event_list signalqueue;
struct event_list eventqueue;
static struct timeval event_tv;

static int
compare(struct event *a, struct event *b)
{
	if (timercmp(&a->ev_timeout, &b->ev_timeout, <))
		return (-1);
	else if (timercmp(&a->ev_timeout, &b->ev_timeout, >))
		return (1);
	return (0);
}

RB_PROTOTYPE(event_tree, event, ev_timeout_node, compare);

RB_GENERATE(event_tree, event, ev_timeout_node, compare);


void
event_init(void)
{
	int i;

	event_sigcb = NULL;
	event_gotsig = 0;
	gettimeofday(&event_tv, NULL);
	
	RB_INIT(&timetree);
	TAILQ_INIT(&eventqueue);
	TAILQ_INIT(&activequeue);
	TAILQ_INIT(&signalqueue);
	
	evbase = NULL;
	for (i = 0; eventops[i] && !evbase; i++) {
		evsel = eventops[i];

		evbase = evsel->init();
	}

#if defined(USE_LOG) && defined(USE_DEBUG)
	log_to(stderr);
	log_debug_cmd(LOG_MISC, 80);
#endif
}

int
event_haveevents(void)
{
	return (RB_ROOT(&timetree) || TAILQ_FIRST(&eventqueue) ||
	    TAILQ_FIRST(&signalqueue) || TAILQ_FIRST(&activequeue));
}

void
event_process_active(void)
{
	struct event *ev;
	short ncalls;

	for (ev = TAILQ_FIRST(&activequeue); ev;
	    ev = TAILQ_FIRST(&activequeue)) {
		event_queue_remove(ev, EVLIST_ACTIVE);
		
		/* Allows deletes to work */
		ncalls = ev->ev_ncalls;
		ev->ev_pncalls = &ncalls;
		while (ncalls) {
			ncalls--;
			ev->ev_ncalls = ncalls;
			(*ev->ev_callback)(ev->ev_fd, ev->ev_res, ev->ev_arg);
		}
	}
}

int
event_dispatch(void)
{
	return (event_loop(0));
}

int
event_loop(int flags)
{
	struct timeval tv;
	int res, done;

	/* Calculate the initial events that we are waiting for */
	if (evsel->recalc(evbase, 0) == -1)
		return (-1);

	done = 0;
	while (!done) {
		while (event_gotsig) {
			event_gotsig = 0;
			if (event_sigcb) {
				res = (*event_sigcb)();
				if (res == -1) {
					errno = EINTR;
					return (-1);
				}
			}
		}

		/* Check if time is running backwards */
		gettimeofday(&tv, NULL);
		if (timercmp(&tv, &event_tv, <)) {
			struct timeval off;
			LOG_DBG((LOG_MIST, 10,
				    "%s: time is running backwards, corrected",
				    __FUNCTION__));

			timersub(&event_tv, &tv, &off);
			timeout_correct(&off);
		}
		event_tv = tv;

		if (!(flags & EVLOOP_NONBLOCK))
			timeout_next(&tv);
		else
			timerclear(&tv);
		
		/* If we have no events, we just exit */
		if (!event_haveevents())
			return (1);

		res = evsel->dispatch(evbase, &tv);

		if (res == -1)
			return (-1);

		timeout_process();

		if (TAILQ_FIRST(&activequeue)) {
			event_process_active();
			if (flags & EVLOOP_ONCE)
				done = 1;
		} else if (flags & EVLOOP_NONBLOCK)
			done = 1;

		if (evsel->recalc(evbase, 0) == -1)
			return (-1);
	}

	return (0);
}

void
event_set(struct event *ev, int fd, short events,
	  void (*callback)(int, short, void *), void *arg)
{
	ev->ev_callback = callback;
	ev->ev_arg = arg;
	ev->ev_fd = fd;
	ev->ev_events = events;
	ev->ev_flags = EVLIST_INIT;
	ev->ev_ncalls = 0;
	ev->ev_pncalls = NULL;
}

/*
 * Checks if a specific event is pending or scheduled.
 */

int
event_pending(struct event *ev, short event, struct timeval *tv)
{
	int flags = 0;

	if (ev->ev_flags & EVLIST_INSERTED)
		flags |= (ev->ev_events & (EV_READ|EV_WRITE));
	if (ev->ev_flags & EVLIST_ACTIVE)
		flags |= ev->ev_res;
	if (ev->ev_flags & EVLIST_TIMEOUT)
		flags |= EV_TIMEOUT;

	event &= (EV_TIMEOUT|EV_READ|EV_WRITE);

	/* See if there is a timeout that we should report */
	if (tv != NULL && (flags & event & EV_TIMEOUT))
		*tv = ev->ev_timeout;

	return (flags & event);
}

int
event_add(struct event *ev, struct timeval *tv)
{
	LOG_DBG((LOG_MISC, 55,
		 "event_add: event: %p, %s%s%scall %p",
		 ev,
		 ev->ev_events & EV_READ ? "EV_READ " : " ",
		 ev->ev_events & EV_WRITE ? "EV_WRITE " : " ",
		 tv ? "EV_TIMEOUT " : " ",
		 ev->ev_callback));

	assert(!(ev->ev_flags & ~EVLIST_ALL));

	if (tv != NULL) {
		struct timeval now;

		if (ev->ev_flags & EVLIST_TIMEOUT)
			event_queue_remove(ev, EVLIST_TIMEOUT);

		gettimeofday(&now, NULL);
		timeradd(&now, tv, &ev->ev_timeout);

		LOG_DBG((LOG_MISC, 55,
			 "event_add: timeout in %d seconds, call %p",
			 tv->tv_sec, ev->ev_callback));

		event_queue_insert(ev, EVLIST_TIMEOUT);
	}

	if ((ev->ev_events & (EV_READ|EV_WRITE)) &&
	    !(ev->ev_flags & EVLIST_INSERTED)) {
		event_queue_insert(ev, EVLIST_INSERTED);

		return (evsel->add(evbase, ev));
	} else if ((ev->ev_events & EV_SIGNAL) &&
	    !(ev->ev_flags & EVLIST_SIGNAL)) {
		event_queue_insert(ev, EVLIST_SIGNAL);

		return (evsel->add(evbase, ev));
	}

	return (0);
}

int
event_del(struct event *ev)
{
	LOG_DBG((LOG_MISC, 80, "event_del: %p, callback %p",
		 ev, ev->ev_callback));

	assert(!(ev->ev_flags & ~EVLIST_ALL));

	/* See if we are just active executing this event in a loop */
	if (ev->ev_ncalls && ev->ev_pncalls) {
		/* Abort loop */
		*ev->ev_pncalls = 0;
	}

	if (ev->ev_flags & EVLIST_TIMEOUT)
		event_queue_remove(ev, EVLIST_TIMEOUT);

	if (ev->ev_flags & EVLIST_ACTIVE)
		event_queue_remove(ev, EVLIST_ACTIVE);

	if (ev->ev_flags & EVLIST_INSERTED) {
		event_queue_remove(ev, EVLIST_INSERTED);
		return (evsel->del(evbase, ev));
	} else if (ev->ev_flags & EVLIST_SIGNAL) {
		event_queue_remove(ev, EVLIST_SIGNAL);
		return (evsel->del(evbase, ev));
	}

	return (0);
}

void
event_active(struct event *ev, int res, short ncalls)
{
	/* We get different kinds of events, add them together */
	if (ev->ev_flags & EVLIST_ACTIVE) {
		ev->ev_res |= res;
		return;
	}

	ev->ev_res = res;
	ev->ev_ncalls = ncalls;
	ev->ev_pncalls = NULL;
	event_queue_insert(ev, EVLIST_ACTIVE);
}

int
timeout_next(struct timeval *tv)
{
	struct timeval dflt = TIMEOUT_DEFAULT;

	struct timeval now;
	struct event *ev;

	if ((ev = RB_MIN(event_tree, &timetree)) == NULL) {
		*tv = dflt;
		return (0);
	}

	if (gettimeofday(&now, NULL) == -1)
		return (-1);

	if (timercmp(&ev->ev_timeout, &now, <=)) {
		timerclear(tv);
		return (0);
	}

	timersub(&ev->ev_timeout, &now, tv);

	LOG_DBG((LOG_MISC, 60, "timeout_next: in %d seconds", tv->tv_sec));
	return (0);
}

void
timeout_correct(struct timeval *off)
{
	struct event *ev;

	/* We can modify the key element of the node without destroying
	 * the key, beause we apply it to all in the right order.
	 */
	RB_FOREACH(ev, event_tree, &timetree)
		timersub(&ev->ev_timeout, off, &ev->ev_timeout);
}

void
timeout_process(void)
{
	struct timeval now;
	struct event *ev, *next;

	gettimeofday(&now, NULL);

	for (ev = RB_MIN(event_tree, &timetree); ev; ev = next) {
		if (timercmp(&ev->ev_timeout, &now, >))
			break;
		next = RB_NEXT(event_tree, &timetree, ev);

		event_queue_remove(ev, EVLIST_TIMEOUT);

		/* delete this event from the I/O queues */
		event_del(ev);

		LOG_DBG((LOG_MISC, 60, "timeout_process: call %p",
			 ev->ev_callback));
		event_active(ev, EV_TIMEOUT, 1);
	}
}

void
timeout_insert(struct event *ev)
{
	struct event *tmp;

	tmp = RB_FIND(event_tree, &timetree, ev);

	if (tmp != NULL) {
		struct timeval tv;
		struct timeval add = {0,1};

		/* Find unique time */
		tv = ev->ev_timeout;
		do {
			timeradd(&tv, &add, &tv);
			tmp = RB_NEXT(event_tree, &timetree, tmp);
		} while (tmp != NULL && timercmp(&tmp->ev_timeout, &tv, ==));

		ev->ev_timeout = tv;
	}

	tmp = RB_INSERT(event_tree, &timetree, ev);
	assert(tmp == NULL);
}

void
event_queue_remove(struct event *ev, int queue)
{
	if (!(ev->ev_flags & queue))
		errx(1, "%s: %p(fd %d) not on queue %x", __FUNCTION__,
		    ev, ev->ev_fd, queue);

	ev->ev_flags &= ~queue;
	switch (queue) {
	case EVLIST_ACTIVE:
		TAILQ_REMOVE(&activequeue, ev, ev_active_next);
		break;
	case EVLIST_SIGNAL:
		TAILQ_REMOVE(&signalqueue, ev, ev_signal_next);
		break;
	case EVLIST_TIMEOUT:
		RB_REMOVE(event_tree, &timetree, ev);
		break;
	case EVLIST_INSERTED:
		TAILQ_REMOVE(&eventqueue, ev, ev_next);
		break;
	default:
		errx(1, "%s: unknown queue %x", __FUNCTION__, queue);
	}
}

void
event_queue_insert(struct event *ev, int queue)
{
	if (ev->ev_flags & queue)
		errx(1, "%s: %p(fd %d) already on queue %x", __FUNCTION__,
		    ev, ev->ev_fd, queue);

	ev->ev_flags |= queue;
	switch (queue) {
	case EVLIST_ACTIVE:
		TAILQ_INSERT_TAIL(&activequeue, ev, ev_active_next);
		break;
	case EVLIST_SIGNAL:
		TAILQ_INSERT_TAIL(&signalqueue, ev, ev_signal_next);
		break;
	case EVLIST_TIMEOUT:
		timeout_insert(ev);
		break;
	case EVLIST_INSERTED:
		TAILQ_INSERT_TAIL(&eventqueue, ev, ev_next);
		break;
	default:
		errx(1, "%s: unknown queue %x", __FUNCTION__, queue);
	}
}
