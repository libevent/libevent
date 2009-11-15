/*	$OpenBSD: kqueue.c,v 1.5 2002/07/10 14:41:31 art Exp $	*/

/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2009 Niels Provos and Nick Mathewson
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

#define _GNU_SOURCE

#include <sys/types.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#include <sys/event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef _EVENT_HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Some platforms apparently define the udata field of struct kevent as
 * intptr_t, whereas others define it as void*.  There doesn't seem to be an
 * easy way to tell them apart via autoconf, so we need to use OS macros. */
#if defined(_EVENT_HAVE_INTTYPES_H) && !defined(__OpenBSD__) && !defined(__FreeBSD__) && !defined(__darwin__) && !defined(__APPLE__)
#define PTR_TO_UDATA(x)	((intptr_t)(x))
#else
#define PTR_TO_UDATA(x)	(x)
#endif

#include "event-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"
#include "event2/thread.h"
#include "evthread-internal.h"

#define NEVENT		64

struct kqop {
	struct kevent *changes;
	int nchanges;
	int changes_size;
	struct kevent *pend_changes;
	int n_pend_changes;
	int pend_changes_size;

	struct kevent *events;
	int events_size;
	int kq;
	pid_t pid;
};

static void kqop_free(struct kqop *kqop);

static void *kq_init	(struct event_base *);
static int kq_add (struct event_base *, int, short, short, void *);
static int kq_del (struct event_base *, int, short, short, void *);
static int kq_sig_add (struct event_base *, int, short, short, void *);
static int kq_sig_del (struct event_base *, int, short, short, void *);
static int kq_dispatch	(struct event_base *, struct timeval *);
static int kq_insert	(struct kqop *, struct kevent *);
static void kq_dealloc (struct event_base *);

const struct eventop kqops = {
	"kqueue",
	kq_init,
	kq_add,
	kq_del,
	kq_dispatch,
	kq_dealloc,
	1 /* need reinit */,
    EV_FEATURE_ET|EV_FEATURE_O1|EV_FEATURE_FDS,
	0
};

static const struct eventop kqsigops = {
	"kqueue_signal",
	NULL,
	kq_sig_add,
	kq_sig_del,
	NULL,
	NULL,
	1 /* need reinit */,
	0,
	0
};

static void *
kq_init(struct event_base *base)
{
	int kq = -1;
	struct kqop *kqueueop = NULL;

	if (!(kqueueop = mm_calloc(1, sizeof(struct kqop))))
		return (NULL);

	/* Initialize the kernel queue */

	if ((kq = kqueue()) == -1) {
		event_warn("kqueue");
		goto err;
	}

	kqueueop->kq = kq;

	kqueueop->pid = getpid();

	/* Initialize fields */
	kqueueop->changes = mm_calloc(NEVENT, sizeof(struct kevent));
	if (kqueueop->changes == NULL)
		goto err;
	kqueueop->pend_changes = mm_calloc(NEVENT, sizeof(struct kevent));
	if (kqueueop->pend_changes == NULL)
		goto err;
	kqueueop->events = mm_calloc(NEVENT, sizeof(struct kevent));
	if (kqueueop->events == NULL)
		goto err;
	kqueueop->events_size = kqueueop->changes_size =
	    kqueueop->pend_changes_size = NEVENT;

	/* Check for Mac OS X kqueue bug. */
	kqueueop->changes[0].ident = -1;
	kqueueop->changes[0].filter = EVFILT_READ;
	kqueueop->changes[0].flags = EV_ADD;
	/*
	 * If kqueue works, then kevent will succeed, and it will
	 * stick an error in events[0].  If kqueue is broken, then
	 * kevent will fail.
	 */
	if (kevent(kq,
		kqueueop->changes, 1, kqueueop->events, NEVENT, NULL) != 1 ||
	    kqueueop->events[0].ident != -1 ||
	    kqueueop->events[0].flags != EV_ERROR) {
		event_warn("%s: detected broken kqueue; not using.", __func__);
		goto err;
	}

	base->evsigsel = &kqsigops;
	base->evsigbase = kqueueop;

	return (kqueueop);
err:
	if (kqueueop)
		kqop_free(kqueueop);

	return (NULL);
}

static int
kq_insert(struct kqop *kqop, struct kevent *kev)
{
	int size = kqop->changes_size;

	if (kqop->nchanges == size) {
		struct kevent *newchange;

		size *= 2;

		newchange = mm_realloc(kqop->changes,
				    size * sizeof(struct kevent));
		if (newchange == NULL) {
			event_warn("%s: malloc", __func__);
			return (-1);
		}
		kqop->changes = newchange;
		kqop->changes_size = size;
	}

	memcpy(&kqop->changes[kqop->nchanges++], kev, sizeof(struct kevent));

	event_debug(("%s: fd %d %s%s",
		 __func__, (int)kev->ident,
		 kev->filter == EVFILT_READ ? "EVFILT_READ" : "EVFILT_WRITE",
		 kev->flags == EV_DELETE ? " (del)" : ""));

	return (0);
}

static void
kq_sighandler(int sig)
{
	/* Do nothing here */
}

#define SWAP(tp,a,b)				\
	do {					\
		tp tmp_swap_var = (a);		\
		a = b;				\
		b = tmp_swap_var;		\
	} while (0);

static int
kq_dispatch(struct event_base *base, struct timeval *tv)
{
	struct kqop *kqop = base->evbase;
	struct kevent *events = kqop->events;
	struct timespec ts, *ts_p = NULL;
	int i, res;

	if (tv != NULL) {
		TIMEVAL_TO_TIMESPEC(tv, &ts);
		ts_p = &ts;
	}

	/* We can't hold the lock while we're calling kqueue, so another
	 * thread might potentially mess with changes before the kernel has a
	 * chance to read it.  Therefore, we need to keep the change list
	 * we're looking at in pend_changes, and let other threads mess with
	 * changes. */
	SWAP(struct kevent *, kqop->changes, kqop->pend_changes);
	SWAP(int, kqop->nchanges, kqop->n_pend_changes);
	SWAP(int, kqop->changes_size, kqop->pend_changes_size);

	EVBASE_RELEASE_LOCK(base, EVTHREAD_WRITE, th_base_lock);

	res = kevent(kqop->kq, kqop->pend_changes, kqop->n_pend_changes,
	    events, kqop->events_size, ts_p);

	EVBASE_ACQUIRE_LOCK(base, EVTHREAD_WRITE, th_base_lock);

	kqop->n_pend_changes = 0;
	if (res == -1) {
		if (errno != EINTR) {
                        event_warn("kevent");
			return (-1);
		}

		return (0);
	}

	event_debug(("%s: kevent reports %d", __func__, res));

	for (i = 0; i < res; i++) {
		int which = 0;

		if (events[i].flags & EV_ERROR) {
			/*
			 * Error messages that can happen, when a delete fails.
			 *   EBADF happens when the file descriptor has been
			 *   closed,
			 *   ENOENT when the file descriptor was closed and
			 *   then reopened.
			 *   EINVAL for some reasons not understood; EINVAL
			 *   should not be returned ever; but FreeBSD does :-\
			 * An error is also indicated when a callback deletes
			 * an event we are still processing.  In that case
			 * the data field is set to ENOENT.
			 */
			if (events[i].data == EBADF ||
			    events[i].data == EINVAL ||
			    events[i].data == ENOENT)
				continue;
			errno = events[i].data;
			return (-1);
		}

		if (events[i].filter == EVFILT_READ) {
			which |= EV_READ;
		} else if (events[i].filter == EVFILT_WRITE) {
			which |= EV_WRITE;
		} else if (events[i].filter == EVFILT_SIGNAL) {
			which |= EV_SIGNAL;
		}

		if (!which)
			continue;

		if (events[i].filter == EVFILT_SIGNAL) {
			evmap_signal_active(base, events[i].ident, 1);
		} else {
			evmap_io_active(base, events[i].ident, which | EV_ET);
		}
	}

	if (res == kqop->events_size) {
		struct kevent *newresult;
		int size = kqop->events_size;
		/* We used all the events space that we have. Maybe we should
		   make it bigger. */
		size *= 2;
		newresult = mm_realloc(kqop->events,
		    size * sizeof(struct kevent));
		if (newresult) {
			kqop->events = newresult;
			kqop->events_size = size;
		}
	}

	return (0);
}


static int
kq_add(struct event_base *base, int fd, short old, short events, void *p)
{
	struct kqop *kqop = base->evbase;
	struct kevent kev;
	(void) p;

	if (events & EV_READ) {
 		memset(&kev, 0, sizeof(kev));
		kev.ident = fd;
		kev.filter = EVFILT_READ;
#ifdef NOTE_EOF
		/* Make it behave like select() and poll() */
		kev.fflags = NOTE_EOF;
#endif
		kev.flags = EV_ADD;
		if (events & EV_ET)
			kev.flags |= EV_CLEAR;

		if (kq_insert(kqop, &kev) == -1)
			return (-1);
	}

	if (events & EV_WRITE) {
 		memset(&kev, 0, sizeof(kev));
		kev.ident = fd;
		kev.filter = EVFILT_WRITE;
		kev.flags = EV_ADD;
		if (events & EV_ET)
			kev.flags |= EV_CLEAR;

		if (kq_insert(kqop, &kev) == -1)
			return (-1);
	}

	return (0);
}

static int
kq_del(struct event_base *base, int fd, short old, short events, void *p)
{
	struct kqop *kqop = base->evbase;
	struct kevent kev;
	(void) p;

	if (events & EV_READ) {
 		memset(&kev, 0, sizeof(kev));
		kev.ident = fd;
		kev.filter = EVFILT_READ;
		kev.flags = EV_DELETE;

		if (kq_insert(kqop, &kev) == -1)
			return (-1);
	}

	if (events & EV_WRITE) {
 		memset(&kev, 0, sizeof(kev));
		kev.ident = fd;
		kev.filter = EVFILT_WRITE;
		kev.flags = EV_DELETE;

		if (kq_insert(kqop, &kev) == -1)
			return (-1);
	}

	return (0);
}

static void
kqop_free(struct kqop *kqop)
{
	if (kqop->changes)
		mm_free(kqop->changes);
	if (kqop->pend_changes)
		mm_free(kqop->pend_changes);
	if (kqop->events)
		mm_free(kqop->events);
	if (kqop->kq >= 0 && kqop->pid == getpid())
		close(kqop->kq);
	memset(kqop, 0, sizeof(struct kqop));
	mm_free(kqop);
}

static void
kq_dealloc(struct event_base *base)
{
	struct kqop *kqop = base->evbase;
	kqop_free(kqop);
}

/* signal handling */
static int
kq_sig_add(struct event_base *base, int nsignal, short old, short events, void *p)
{
	struct kqop *kqop = base->evbase;
	struct kevent kev;
	struct timespec timeout = { 0, 0 };
	(void)p;

	EVUTIL_ASSERT(nsignal >= 0 && nsignal < NSIG);

	memset(&kev, 0, sizeof(kev));
	kev.ident = nsignal;
	kev.filter = EVFILT_SIGNAL;
	kev.flags = EV_ADD;

	/* Be ready for the signal if it is sent any
	 * time between now and the next call to
	 * kq_dispatch. */
	if (kevent(kqop->kq, &kev, 1, NULL, 0, &timeout) == -1)
		return (-1);

	if (_evsig_set_handler(base, nsignal, kq_sighandler) == -1)
		return (-1);

	return (0);
}

static int
kq_sig_del(struct event_base *base, int nsignal, short old, short events, void *p)
{
	struct kqop *kqop = base->evbase;
	struct kevent kev;

	struct timespec timeout = { 0, 0 };
	(void)p;

	EVUTIL_ASSERT(nsignal >= 0 && nsignal < NSIG);

	memset(&kev, 0, sizeof(kev));
	kev.ident = nsignal;
	kev.filter = EVFILT_SIGNAL;
	kev.flags = EV_DELETE;

	/* Because we insert signal events
	 * immediately, we need to delete them
	 * immediately, too */
	if (kevent(kqop->kq, &kev, 1, NULL, 0, &timeout) == -1)
		return (-1);

	if (_evsig_restore_handler(base, nsignal) == -1)
		return (-1);

	return (0);
}
