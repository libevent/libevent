/*
 * Copyright 2000-2002 Niels Provos <provos@citi.umich.edu>
 * Copyright 2003 Michael A. Davis <mike@datanerds.net>
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
#ifdef _MSC_VER
#include "config.h"
#else
/* Avoid the windows/msvc thing. */
#include "../config.h"
#endif

#include <windows.h>
#include <winsock2.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "log.h"
#include "event.h"
#include "event-internal.h"

#define XFREE(ptr) do { if (ptr) free(ptr); } while(0)

extern struct event_list timequeue;
extern struct event_list addqueue;
#if 0
extern struct event_list signalqueue;
#endif

struct win_fd_set {
	u_int fd_count;
	SOCKET fd_array[1];
};

int evsigcaught[NSIG];
volatile sig_atomic_t signal_caught = 0;
/* MSDN says this is required to handle SIGFPE */
volatile double SIGFPE_REQ = 0.0f;

#if 0
static void signal_handler(int sig);

void signal_process(void);
int signal_recalc(void);
#endif

struct win32op {
	int fd_setsz;
	struct win_fd_set *readset_in;
	struct win_fd_set *writeset_in;
	struct win_fd_set *readset_out;
	struct win_fd_set *writeset_out;
	struct win_fd_set *exset_out;
	int n_events;
	int n_events_alloc;
	struct event **events;
};

void *win32_init	(struct event_base *);
int win32_insert	(void *, struct event *);
int win32_del	(void *, struct event *);
int win32_recalc	(struct event_base *base, void *, int);
int win32_dispatch	(struct event_base *base, void *, struct timeval *);
void win32_dealloc	(struct event_base *, void *);

struct eventop win32ops = {
	"win32",
	win32_init,
	win32_insert,
	win32_del,
	win32_recalc,
	win32_dispatch,
	win32_dealloc
};

#define FD_SET_ALLOC_SIZE(n) ((sizeof(struct win_fd_set) + ((n)-1)*sizeof(SOCKET)))

static int
realloc_fd_sets(struct win32op *op, size_t new_size)
{
	size_t size;

	assert(new_size >= op->readset_in->fd_count &&
	       new_size >= op->writeset_in->fd_count);
	assert(new_size >= 1);

	size = FD_SET_ALLOC_SIZE(new_size);
	if (!(op->readset_in = realloc(op->readset_in, size)))
		return (-1);
	if (!(op->writeset_in = realloc(op->writeset_in, size)))
		return (-1);
	if (!(op->readset_out = realloc(op->readset_out, size)))
		return (-1);
	if (!(op->exset_out = realloc(op->exset_out, size)))
		return (-1);
	if (!(op->writeset_out = realloc(op->writeset_out, size)))
		return (-1);
	op->fd_setsz = new_size;
	return (0);
}

static int
timeval_to_ms(struct timeval *tv)
{
	return ((tv->tv_sec * 1000) + (tv->tv_usec / 1000));
}

static int
do_fd_set(struct win32op *op, SOCKET s, int read)
{
	unsigned int i;
	struct win_fd_set *set = read ? op->readset_in : op->writeset_in;
	for (i=0;i<set->fd_count;++i) {
		if (set->fd_array[i]==s)
			return (0);
	}
	if (set->fd_count == op->fd_setsz) {
		if (realloc_fd_sets(op, op->fd_setsz*2))
			return (-1);
		/* set pointer will have changed and needs reiniting! */
		set = read ? op->readset_in : op->writeset_in;
	}
	set->fd_array[set->fd_count] = s;
	return (set->fd_count++);
}

static int
do_fd_clear(struct win32op *op, SOCKET s, int read)
{
	unsigned int i;
	struct win_fd_set *set = read ? op->readset_in : op->writeset_in;
	for (i=0;i<set->fd_count;++i) {
		if (set->fd_array[i]==s) {
			if (--set->fd_count != i) {
				set->fd_array[i] = set->fd_array[set->fd_count];
			}
			return (0);
		}
	}
	return (0);
}

#define NEVENT 64
void *
win32_init(struct event_base *_base)
{
	struct win32op *winop;
	size_t size;
	if (!(winop = calloc(1, sizeof(struct win32op))))
		return NULL;
	winop->fd_setsz = NEVENT;
	size = FD_SET_ALLOC_SIZE(NEVENT);
	if (!(winop->readset_in = malloc(size)))
		goto err;
	if (!(winop->writeset_in = malloc(size)))
		goto err;
	if (!(winop->readset_out = malloc(size)))
		goto err;
	if (!(winop->writeset_out = malloc(size)))
		goto err;
	if (!(winop->exset_out = malloc(size)))
		goto err;
	winop->n_events = 0;
	winop->n_events_alloc = NEVENT;
	if (!(winop->events = malloc(NEVENT*sizeof(struct event*))))
		goto err;
	winop->readset_in->fd_count = winop->writeset_in->fd_count = 0;
	winop->readset_out->fd_count = winop->writeset_out->fd_count
		= winop->exset_out->fd_count = 0;

	evsignal_init(_base);

	return (winop);
 err:
        XFREE(winop->readset_in);
        XFREE(winop->writeset_in);
        XFREE(winop->readset_out);
        XFREE(winop->writeset_out);
        XFREE(winop->exset_out);
        XFREE(winop->events);
        XFREE(winop);
        return (NULL);
}

int
win32_recalc(struct event_base *base, void *arg, int max)
{
#if 0
	return (evsignal_recalc());
#endif
	return (0);
}

int
win32_insert(void *op, struct event *ev)
{
	struct win32op *win32op = op;
	int i;

	if (ev->ev_events & EV_SIGNAL) {
		return (evsignal_add(ev));
	}
	if (!(ev->ev_events & (EV_READ|EV_WRITE)))
		return (0);

	for (i=0;i<win32op->n_events;++i) {
		if(win32op->events[i] == ev) {
			event_debug(("%s: Event for %d already inserted.",
				     __func__, (int)ev->ev_fd));
			return (0);
		}
	}
	event_debug(("%s: adding event for %d", __func__, (int)ev->ev_fd));
	if (ev->ev_events & EV_READ) {
		if (do_fd_set(win32op, ev->ev_fd, 1)<0)
			return (-1);
	}
	if (ev->ev_events & EV_WRITE) {
		if (do_fd_set(win32op, ev->ev_fd, 0)<0)
			return (-1);
	}

	if (win32op->n_events_alloc == win32op->n_events) {
		size_t sz;
		win32op->n_events_alloc *= 2;
		sz = sizeof(struct event*)*win32op->n_events_alloc;
		if (!(win32op->events = realloc(win32op->events, sz)))
			return (-1);
	}
	win32op->events[win32op->n_events++] = ev;

	return (0);
}

int
win32_del(void *op, struct event *ev)
{
	struct win32op *win32op = op;
	int i, found;

	if (ev->ev_events & EV_SIGNAL)
		return (evsignal_del(ev));

	found = -1;
	for (i=0;i<win32op->n_events;++i) {
		if(win32op->events[i] == ev) {
			found = i;
			break;
		}
	}
	if (found < 0) {
		event_debug(("%s: Unable to remove non-inserted event for %d",
			     __func__, ev->ev_fd));
		return (-1);
	}
	event_debug(("%s: Removing event for %d", __func__, ev->ev_fd));
	if (ev->ev_events & EV_READ)
		do_fd_clear(win32op, ev->ev_fd, 1);
	if (ev->ev_events & EV_WRITE)
		do_fd_clear(win32op, ev->ev_fd, 0);

	if (i != --win32op->n_events) {
		win32op->events[i] = win32op->events[win32op->n_events];
	}

	return 0;
}

static void
fd_set_copy(struct win_fd_set *out, const struct win_fd_set *in)
{
	out->fd_count = in->fd_count;
	memcpy(out->fd_array, in->fd_array, in->fd_count * (sizeof(SOCKET)));
}

/*
  static void dump_fd_set(struct win_fd_set *s)
  {
  unsigned int i;
  printf("[ ");
  for(i=0;i<s->fd_count;++i)
  printf("%d ",(int)s->fd_array[i]);
  printf("]\n");
  }
*/

int
win32_dispatch(struct event_base *base, void *op,
	       struct timeval *tv)
{
	struct win32op *win32op = op;
	int res = 0;
	int i;
	int fd_count;

	fd_set_copy(win32op->readset_out, win32op->readset_in);
	fd_set_copy(win32op->exset_out, win32op->readset_in);
	fd_set_copy(win32op->writeset_out, win32op->writeset_in);

	fd_count =
           (win32op->readset_out->fd_count > win32op->writeset_out->fd_count) ?
	    win32op->readset_out->fd_count : win32op->writeset_out->fd_count;

	if (!fd_count) {
		/* Windows doesn't like you to call select() with no sockets */
		Sleep(timeval_to_ms(tv));
		evsignal_process(base);
		return (0);
	}

	res = select(fd_count,
		     (struct fd_set*)win32op->readset_out,
		     (struct fd_set*)win32op->writeset_out,
		     (struct fd_set*)win32op->exset_out, tv);

	event_debug(("%s: select returned %d", __func__, res));

	if(res <= 0) {
		evsignal_process(base);
		return res;
	} else if (base->sig.evsignal_caught) {
		evsignal_process(base);
	}

	for (i=0;i<win32op->n_events;++i) {
		struct event *ev;
		int got = 0;
		ev = win32op->events[i];
		if ((ev->ev_events & EV_READ)) {
			if (FD_ISSET(ev->ev_fd, win32op->readset_out) ||
			    FD_ISSET(ev->ev_fd, win32op->exset_out)) {
				got |= EV_READ;
			}
		}
		if ((ev->ev_events & EV_WRITE)) {
			if (FD_ISSET(ev->ev_fd, win32op->writeset_out)) {
				got |= EV_WRITE;
			}
		}
		if (!got)
			continue;
		if (!(ev->ev_events & EV_PERSIST)) {
			event_del(ev);
		}
		event_active(ev,got,1);
	}

#if 0
	if (signal_recalc() == -1)
		return (-1);
#endif

	return (0);
}

void
win32_dealloc(struct event_base *_base, void *arg)
{
	struct win32op *win32op = arg;

	evsignal_dealloc(_base);
	if (win32op->readset_in)
		free(win32op->readset_in);
	if (win32op->writeset_in)
		free(win32op->writeset_in);
	if (win32op->readset_out)
		free(win32op->readset_out);
	if (win32op->writeset_out)
		free(win32op->writeset_out);
	if (win32op->exset_out)
		free(win32op->exset_out);
	if (win32op->events)
		free(win32op->events);

	memset(win32op, 0, sizeof(win32op));
	free(win32op);
}

#if 0
static void
signal_handler(int sig)
{
	evsigcaught[sig]++;
	signal_caught = 1;
}

int
signal_recalc(void)
{
	struct event *ev;

	/* Reinstall our signal handler. */
	TAILQ_FOREACH(ev, &signalqueue, ev_signal_next) {
		if((int)signal(EVENT_SIGNAL(ev), signal_handler) == -1)
			return (-1);
	}
	return (0);
}

void
signal_process(void)
{
	struct event *ev;
	short ncalls;

	TAILQ_FOREACH(ev, &signalqueue, ev_signal_next) {
		ncalls = evsigcaught[EVENT_SIGNAL(ev)];
		if (ncalls) {
			if (!(ev->ev_events & EV_PERSIST))
				event_del(ev);
			event_active(ev, EV_SIGNAL, ncalls);
		}
	}

	memset(evsigcaught, 0, sizeof(evsigcaught));
	signal_caught = 0;
}
#endif

