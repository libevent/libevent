/*
 * Copyright (c) 2000-2004 Niels Provos <provos@citi.umich.edu>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include "misc.h"
#endif
#include <sys/types.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else 
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
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
extern const struct eventop selectops;
#endif
#ifdef HAVE_POLL
extern const struct eventop pollops;
#endif
#ifdef HAVE_RTSIG
extern const struct eventop rtsigops;
#endif
#ifdef HAVE_EPOLL
extern const struct eventop epollops;
#endif
#ifdef HAVE_WORKING_KQUEUE
extern const struct eventop kqops;
#endif
#ifdef WIN32
extern const struct eventop win32ops;
#endif

/* In order of preference */
const struct eventop *eventops[] = {
#ifdef HAVE_WORKING_KQUEUE
	&kqops,
#endif
#ifdef HAVE_EPOLL
	&epollops,
#endif
#ifdef HAVE_RTSIG
	&rtsigops,
#endif
#ifdef HAVE_POLL
	&pollops,
#endif
#ifdef HAVE_SELECT
	&selectops,
#endif
#ifdef WIN32
	&win32ops,
#endif
	NULL
};

const struct eventop *evsel;
void *evbase;

/* Handle signals - This is a deprecated interface */
int (*event_sigcb)(void);	/* Signal callback when gotsig is set */
int event_gotsig;		/* Set in signal handler */
int event_gotterm;		/* Set to terminate loop */

/* Prototypes */
void		event_queue_insert(struct event *, int);
void		event_queue_remove(struct event *, int);
int		event_haveevents(void);

static void	event_process_active(void);

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
	if (a < b)
		return (-1);
	if (a > b)
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

	if (evbase == NULL)
		errx(1, "%s: no event mechanism available", __func__);

	if (getenv("EVENT_SHOW_METHOD")) 
		fprintf(stderr, "libevent using: %s\n", evsel->name); 

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

static void
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
			(*ev->ev_callback)((int)ev->ev_fd, ev->ev_res, ev->ev_arg);
		}
	}
}

/*
 * Wait continously for events.  We exit only if no events are left.
 */

int
event_dispatch(void)
{
	return (event_loop(0));
}

static void
event_loopexit_cb(int fd, short what, void *arg)
{
	event_gotterm = 1;
}

int
event_loopexit(struct timeval *tv)
{
	return (event_once(-1, EV_TIMEOUT, event_loopexit_cb, NULL, tv));
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
		/* Terminate the loop if we have been asked to */
		if (event_gotterm) {
			event_gotterm = 0;
			break;
		}

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
			LOG_DBG((LOG_MISC, 10,
				    "%s: time is running backwards, corrected",
				    __func__));

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

/* Sets up an event for processing once */

struct event_once {
	struct event ev;

	void (*cb)(int, short, void *);
	void *arg;
};

/* One-time callback, it deletes itself */

static void
event_once_cb(int fd, short events, void *arg)
{
	struct event_once *eonce = arg;

	(*eonce->cb)(fd, events, eonce->arg);
	free(eonce);
}

/* Schedules an event once */

int
event_once(int fd, short events,
    void (*callback)(int, short, void *), void *arg, struct timeval *tv)
{
	struct event_once *eonce;
	struct timeval etv;

	/* We cannot support signals that just fire once */
	if (events & EV_SIGNAL)
		return (-1);

	if ((eonce = calloc(1, sizeof(struct event_once))) == NULL)
		return (-1);

	if (events == EV_TIMEOUT) {
		if (tv == NULL) {
			timerclear(&etv);
			tv = &etv;
		}

		eonce->cb = callback;
		eonce->arg = arg;

		evtimer_set(&eonce->ev, event_once_cb, eonce);
	} else if (events & (EV_READ|EV_WRITE)) {
		events &= EV_READ|EV_WRITE;

		event_set(&eonce->ev, fd, events, event_once_cb, eonce);
	} else {
		/* Bad event combination */
		return (-1);
	}

	event_add(&eonce->ev, tv);

	return (0);
}

void
event_set(struct event *ev, int fd, short events,
	  void (*callback)(int, short, void *), void *arg)
{
	ev->ev_callback = callback;
	ev->ev_arg = arg;
#ifdef WIN32
	ev->ev_fd = (HANDLE)fd;
	ev->overlap.hEvent = ev;
#else
	ev->ev_fd = fd;
#endif
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
	if (ev->ev_flags & EVLIST_SIGNAL)
		flags |= EV_SIGNAL;

	event &= (EV_TIMEOUT|EV_READ|EV_WRITE|EV_SIGNAL);

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

		/* Check if it is active due to a timeout.  Rescheduling
		 * this timeout before the callback can be executed
		 * removes it from the active list. */
		if ((ev->ev_flags & EVLIST_ACTIVE) &&
		    (ev->ev_res & EV_TIMEOUT)) {
			/* See if we are just active executing this
			 * event in a loop
			 */
			if (ev->ev_ncalls && ev->ev_pncalls) {
				/* Abort loop */
				*ev->ev_pncalls = 0;
			}
			
			event_queue_remove(ev, EVLIST_ACTIVE);
		}

		gettimeofday(&now, NULL);
		timeradd(&now, tv, &ev->ev_timeout);

		LOG_DBG((LOG_MISC, 55,
			 "event_add: timeout in %d seconds, call %p",
			 tv->tv_sec, ev->ev_callback));

		event_queue_insert(ev, EVLIST_TIMEOUT);
	}

	if ((ev->ev_events & (EV_READ|EV_WRITE)) &&
	    !(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE))) {
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

	assert(tv->tv_sec >= 0);
	assert(tv->tv_usec >= 0);

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
event_queue_remove(struct event *ev, int queue)
{
	if (!(ev->ev_flags & queue))
		errx(1, "%s: %p(fd %d) not on queue %x", __func__,
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
		errx(1, "%s: unknown queue %x", __func__, queue);
	}
}

void
event_queue_insert(struct event *ev, int queue)
{
	if (ev->ev_flags & queue)
		errx(1, "%s: %p(fd %d) already on queue %x", __func__,
		    ev, ev->ev_fd, queue);

	ev->ev_flags |= queue;
	switch (queue) {
	case EVLIST_ACTIVE:
		TAILQ_INSERT_TAIL(&activequeue, ev, ev_active_next);
		break;
	case EVLIST_SIGNAL:
		TAILQ_INSERT_TAIL(&signalqueue, ev, ev_signal_next);
		break;
	case EVLIST_TIMEOUT: {
		struct event *tmp = RB_INSERT(event_tree, &timetree, ev);
		assert(tmp == NULL);
		break;
	}
	case EVLIST_INSERTED:
		TAILQ_INSERT_TAIL(&eventqueue, ev, ev_next);
		break;
	default:
		errx(1, "%s: unknown queue %x", __func__, queue);
	}
}
