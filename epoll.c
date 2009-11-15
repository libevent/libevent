/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2009 Niels Provos, Nick Mathewson
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

#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#include <sys/epoll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef _EVENT_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "event-internal.h"
#include "evsignal-internal.h"
#include "event2/thread.h"
#include "evthread-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"

struct epollop {
	struct epoll_event *events;
	int nevents;
	int epfd;
};

static void *epoll_init	(struct event_base *);
static int epoll_add(struct event_base *, int fd, short old, short events, void *);
static int epoll_del(struct event_base *, int fd, short old, short events, void *);
static int epoll_dispatch	(struct event_base *, struct timeval *);
static void epoll_dealloc	(struct event_base *);

const struct eventop epollops = {
	"epoll",
	epoll_init,
	epoll_add,
	epoll_del,
	epoll_dispatch,
	epoll_dealloc,
	1, /* need reinit */
	EV_FEATURE_ET|EV_FEATURE_O1,
	0
};

#ifdef _EVENT_HAVE_SETFD
#define FD_CLOSEONEXEC(x) do { \
        if (fcntl(x, F_SETFD, 1) == -1) \
                event_warn("fcntl(%d, F_SETFD)", x); \
} while (0)
#else
#define FD_CLOSEONEXEC(x)
#endif

#define INITIAL_NEVENT 32
#define MAX_NEVENT 4096

/* On Linux kernels at least up to 2.6.24.4, epoll can't handle timeout
 * values bigger than (LONG_MAX - 999ULL)/HZ.  HZ in the wild can be
 * as big as 1000, and LONG_MAX can be as small as (1<<31)-1, so the
 * largest number of msec we can support here is 2147482.  Let's
 * round that down by 47 seconds.
 */
#define MAX_EPOLL_TIMEOUT_MSEC (35*60*1000)

static void *
epoll_init(struct event_base *base)
{
	int epfd;
	struct epollop *epollop;

	/* Initialize the kernel queue.  (The size field is ignored since
	 * 2.6.8.) */
	if ((epfd = epoll_create(32000)) == -1) {
		if (errno != ENOSYS)
			event_warn("epoll_create");
		return (NULL);
	}

	FD_CLOSEONEXEC(epfd);

	if (!(epollop = mm_calloc(1, sizeof(struct epollop))))
		return (NULL);

	epollop->epfd = epfd;

	/* Initialize fields */
	epollop->events = mm_calloc(INITIAL_NEVENT, sizeof(struct epoll_event));
	if (epollop->events == NULL) {
		mm_free(epollop);
		return (NULL);
	}
	epollop->nevents = INITIAL_NEVENT;

	evsig_init(base);

	return (epollop);
}

static int
epoll_dispatch(struct event_base *base, struct timeval *tv)
{
	struct epollop *epollop = base->evbase;
	struct epoll_event *events = epollop->events;
	int i, res, timeout = -1;

	if (tv != NULL)
		timeout = tv->tv_sec * 1000 + (tv->tv_usec + 999) / 1000;

	if (timeout > MAX_EPOLL_TIMEOUT_MSEC) {
		/* Linux kernels can wait forever if the timeout is too big;
		 * see comment on MAX_EPOLL_TIMEOUT_MSEC. */
		timeout = MAX_EPOLL_TIMEOUT_MSEC;
	}

	EVBASE_RELEASE_LOCK(base, EVTHREAD_WRITE, th_base_lock);

	res = epoll_wait(epollop->epfd, events, epollop->nevents, timeout);

	EVBASE_ACQUIRE_LOCK(base, EVTHREAD_WRITE, th_base_lock);

	if (res == -1) {
		if (errno != EINTR) {
			event_warn("epoll_wait");
			return (-1);
		}

		evsig_process(base);
		return (0);
	} else if (base->sig.evsig_caught) {
		evsig_process(base);
	}

	event_debug(("%s: epoll_wait reports %d", __func__, res));
	EVUTIL_ASSERT(res <= epollop->nevents);

	for (i = 0; i < res; i++) {
		int what = events[i].events;
		short ev = 0;

		if (what & (EPOLLHUP|EPOLLERR)) {
			ev = EV_READ | EV_WRITE;
		} else {
			if (what & EPOLLIN)
				ev |= EV_READ;
			if (what & EPOLLOUT)
				ev |= EV_WRITE;
		}

		if (!events)
			continue;

		evmap_io_active(base, events[i].data.fd, ev | EV_ET);
	}

	if (res == epollop->nevents && epollop->nevents < MAX_NEVENT) {
		/* We used all of the event space this time.  We should
		   be ready for more events next time. */
		int new_nevents = epollop->nevents * 2;
		struct epoll_event *new_events;

		new_events = mm_realloc(epollop->events,
		    new_nevents * sizeof(struct epoll_event));
		if (new_events) {
			epollop->events = new_events;
			epollop->nevents = new_nevents;
		}
	}

	return (0);
}

static int
epoll_add(struct event_base *base, int fd, short old, short events, void *p)
{
	struct epollop *epollop = base->evbase;
	struct epoll_event epev = {0, {0}};
	int op, res;
	(void)p;

	op = EPOLL_CTL_ADD;
	res = 0;

	events |= old;
	if (events & EV_READ)
		res |= EPOLLIN;
	if (events & EV_WRITE)
		res |= EPOLLOUT;
	if (events & EV_ET)
		res |= EPOLLET;

	if (old != 0)
		op = EPOLL_CTL_MOD;

	epev.data.fd = fd;
	epev.events = res;
	if (epoll_ctl(epollop->epfd, op, fd, &epev) == -1)
		return (-1);

	return (0);
}

static int
epoll_del(struct event_base *base, int fd, short old, short events, void *p)
{
	struct epollop *epollop = base->evbase;
	struct epoll_event epev = {0, {0}};
	int res, op;
	(void) p;

	op = EPOLL_CTL_DEL;

	res = 0;
	if (events & EV_READ)
		res |= EPOLLIN;
	if (events & EV_WRITE)
		res |= EPOLLOUT;

	if ((res & (EPOLLIN|EPOLLOUT)) != (EPOLLIN|EPOLLOUT)) {
		if ((res & EPOLLIN) && (old & EV_WRITE)) {
			res = EPOLLOUT;
			op = EPOLL_CTL_MOD;
		} else if ((res & EPOLLOUT) && (old & EV_READ)) {
			res = EPOLLIN;
			op = EPOLL_CTL_MOD;
		}
	}

	epev.data.fd = fd;
	epev.events = res;

	if (epoll_ctl(epollop->epfd, op, fd, &epev) == -1)
		return (-1);

	return (0);
}

static void
epoll_dealloc(struct event_base *base)
{
	struct epollop *epollop = base->evbase;

	evsig_dealloc(base);
	if (epollop->events)
		mm_free(epollop->events);
	if (epollop->epfd >= 0)
		close(epollop->epfd);

	memset(epollop, 0, sizeof(struct epollop));
	mm_free(epollop);
}
