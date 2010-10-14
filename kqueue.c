/*	$OpenBSD: kqueue.c,v 1.5 2002/07/10 14:41:31 art Exp $	*/

/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2010 Niels Provos and Nick Mathewson
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
#include "event2/event-config.h"

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
#include "changelist-internal.h"

#define NEVENT		64

struct kqop {
	struct kevent *changes;
	int changes_size;

	struct kevent *events;
	int events_size;
	int kq;
	pid_t pid;
};

static void kqop_free(struct kqop *kqop);

static void *kq_init(struct event_base *);
static int kq_sig_add(struct event_base *, int, short, short, void *);
static int kq_sig_del(struct event_base *, int, short, short, void *);
static int kq_dispatch(struct event_base *, struct timeval *);
static void kq_dealloc(struct event_base *);

const struct eventop kqops = {
	"kqueue",
	kq_init,
	event_changelist_add,
	event_changelist_del,
	kq_dispatch,
	kq_dealloc,
	1 /* need reinit */,
    EV_FEATURE_ET|EV_FEATURE_O1|EV_FEATURE_FDS,
	EVENT_CHANGELIST_FDINFO_SIZE
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
	kqueueop->events = mm_calloc(NEVENT, sizeof(struct kevent));
	if (kqueueop->events == NULL)
		goto err;
	kqueueop->events_size = kqueueop->changes_size = NEVENT;

	/* Check for Mac OS X kqueue bug. */
	memset(&kqueueop->changes[0], 0, sizeof kqueueop->changes[0]);
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
	    (int)kqueueop->events[0].ident != -1 ||
	    kqueueop->events[0].flags != EV_ERROR) {
		event_warn("%s: detected broken kqueue; not using.", __func__);
		goto err;
	}

	base->evsigsel = &kqsigops;

	return (kqueueop);
err:
	if (kqueueop)
		kqop_free(kqueueop);

	return (NULL);
}

static void
kq_sighandler(int sig)
{
	/* Do nothing here */
}

static void
kq_setup_kevent(struct kevent *out, evutil_socket_t fd, int filter, short change)
{
	memset(out, 0, sizeof(out));
	out->ident = fd;
	out->filter = filter;

	if (change & EV_CHANGE_ADD) {
		out->flags = EV_ADD;
		if (change & EV_ET)
			out->flags |= EV_CLEAR;
#ifdef NOTE_EOF
		/* Make it behave like select() and poll() */
		if (filter == EVFILT_READ)
			out->fflags = NOTE_EOF;
#endif
	} else {
		EVUTIL_ASSERT(change & EV_CHANGE_DEL);
		out->flags = EV_DELETE;
	}
}

static int
kq_build_changes_list(const struct event_changelist *changelist,
    struct kqop *kqop)
{
	int i;
	int n_changes = 0;

	for (i = 0; i < changelist->n_changes; ++i) {
		struct event_change *in_ch = &changelist->changes[i];
		struct kevent *out_ch;
		if (n_changes >= kqop->changes_size - 1) {
			int newsize = kqop->changes_size * 2;
			struct kevent *newchanges;

			newchanges = mm_realloc(kqop->changes,
			    newsize * sizeof(struct kevent));
			if (newchanges == NULL) {
				event_warn("%s: realloc", __func__);
				return (-1);
			}
			kqop->changes = newchanges;
			kqop->changes_size = newsize;
		}
		if (in_ch->read_change) {
			out_ch = &kqop->changes[n_changes++];
			kq_setup_kevent(out_ch, in_ch->fd, EVFILT_READ,
			    in_ch->read_change);
		}
		if (in_ch->write_change) {
			out_ch = &kqop->changes[n_changes++];
			kq_setup_kevent(out_ch, in_ch->fd, EVFILT_WRITE,
			    in_ch->write_change);
		}
	}
	return n_changes;
}

static int
kq_dispatch(struct event_base *base, struct timeval *tv)
{
	struct kqop *kqop = base->evbase;
	struct kevent *events = kqop->events;
	struct kevent *changes;
	struct timespec ts, *ts_p = NULL;
	int i, n_changes, res;

	if (tv != NULL) {
		TIMEVAL_TO_TIMESPEC(tv, &ts);
		ts_p = &ts;
	}

	/* Build "changes" from "base->changes" */
	EVUTIL_ASSERT(kqop->changes);
	n_changes = kq_build_changes_list(&base->changelist, kqop);
	if (n_changes < 0)
		return -1;

	event_changelist_remove_all(&base->changelist, base);

	/* steal the changes array in case some broken code tries to call
	 * dispatch twice at once. */
	changes = kqop->changes;
	kqop->changes = NULL;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	res = kevent(kqop->kq, changes, n_changes,
	    events, kqop->events_size, ts_p);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	EVUTIL_ASSERT(kqop->changes == NULL);
	kqop->changes = changes;

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

static void
kqop_free(struct kqop *kqop)
{
	if (kqop->changes)
		mm_free(kqop->changes);
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
	evsig_dealloc(base);
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

	/* XXXX The manpage suggest we could use SIG_IGN instead of a
	 * do-nothing handler */
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
