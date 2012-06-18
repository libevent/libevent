/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2012 Niels Provos, Nick Mathewson
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
#include "evconfig-private.h"

#ifdef EVENT__HAVE_EPOLL

#include <stdint.h>
#include <sys/types.h>
#include <sys/resource.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#include <sys/epoll.h>
#include <signal.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef EVENT__HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef EVENT__HAVE_SYS_TIMERFD_H
#include <sys/timerfd.h>
#endif

#include "event-internal.h"
#include "evsignal-internal.h"
#include "event2/thread.h"
#include "evthread-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"
#include "changelist-internal.h"
#include "time-internal.h"

#if defined(EVENT__HAVE_SYS_TIMERFD_H) &&			  \
	defined(EVENT__HAVE_TIMERFD_CREATE) &&			  \
	defined(HAVE_POSIX_MONOTONIC) && defined(TFD_NONBLOCK) && \
	defined(TFD_CLOEXEC)
/* Note that we only use timerfd if TFD_NONBLOCK and TFD_CLOEXEC are available
   and working.  This means that we can't support it on 2.6.25 (where timerfd
   was introduced) or 2.6.26, since 2.6.27 introduced those flags.
 */
#define USING_TIMERFD
#endif

struct epollop {
	struct epoll_event *events;
	int nevents;
	int epfd;
#ifdef USING_TIMERFD
	int timerfd;
#endif
};

static void *epoll_init(struct event_base *);
static int epoll_dispatch(struct event_base *, struct timeval *);
static void epoll_dealloc(struct event_base *);

static const struct eventop epollops_changelist = {
	"epoll (with changelist)",
	epoll_init,
	event_changelist_add_,
	event_changelist_del_,
	epoll_dispatch,
	epoll_dealloc,
	1, /* need reinit */
	EV_FEATURE_ET|EV_FEATURE_O1,
	EVENT_CHANGELIST_FDINFO_SIZE
};


static int epoll_nochangelist_add(struct event_base *base, evutil_socket_t fd,
    short old, short events, void *p);
static int epoll_nochangelist_del(struct event_base *base, evutil_socket_t fd,
    short old, short events, void *p);

const struct eventop epollops = {
	"epoll",
	epoll_init,
	epoll_nochangelist_add,
	epoll_nochangelist_del,
	epoll_dispatch,
	epoll_dealloc,
	1, /* need reinit */
	EV_FEATURE_ET|EV_FEATURE_O1,
	0
};

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
	int epfd = -1;
	struct epollop *epollop;

#ifdef EVENT__HAVE_EPOLL_CREATE1
	/* First, try the shiny new epoll_create1 interface, if we have it. */
	epfd = epoll_create1(EPOLL_CLOEXEC);
#endif
	if (epfd == -1) {
		/* Initialize the kernel queue using the old interface.  (The
		size field is ignored   since 2.6.8.) */
		if ((epfd = epoll_create(32000)) == -1) {
			if (errno != ENOSYS)
				event_warn("epoll_create");
			return (NULL);
		}
		evutil_make_socket_closeonexec(epfd);
	}

	if (!(epollop = mm_calloc(1, sizeof(struct epollop)))) {
		close(epfd);
		return (NULL);
	}

	epollop->epfd = epfd;

	/* Initialize fields */
	epollop->events = mm_calloc(INITIAL_NEVENT, sizeof(struct epoll_event));
	if (epollop->events == NULL) {
		mm_free(epollop);
		close(epfd);
		return (NULL);
	}
	epollop->nevents = INITIAL_NEVENT;

	if ((base->flags & EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST) != 0 ||
	    ((base->flags & EVENT_BASE_FLAG_IGNORE_ENV) == 0 &&
		evutil_getenv_("EVENT_EPOLL_USE_CHANGELIST") != NULL)) {

		base->evsel = &epollops_changelist;
	}

#ifdef USING_TIMERFD
	/*
	  The epoll interface ordinarily gives us one-millisecond precision,
	  so on Linux it makes perfect sense to use the CLOCK_MONOTONIC_COARSE
	  timer.  But when the user has set the new PRECISE_TIMER flag for an
	  event_base, we can try to use timerfd to give them finer granularity.
	*/
	if ((base->flags & EVENT_BASE_FLAG_PRECISE_TIMER) &&
	    base->monotonic_timer.monotonic_clock == CLOCK_MONOTONIC) {
		int fd;
		fd = epollop->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
		if (epollop->timerfd >= 0) {
			struct epoll_event epev;
			epev.data.fd = epollop->timerfd;
			epev.events = EPOLLIN;
			if (epoll_ctl(epollop->epfd, EPOLL_CTL_ADD, fd, &epev) < 0) {
				event_warn("epoll_ctl(timerfd)");
				close(fd);
				epollop->timerfd = -1;
			}
		} else {
			if (errno != EINVAL && errno != ENOSYS) {
				/* These errors probably mean that we were
				 * compiled with timerfd/TFD_* support, but
				 * we're running on a kernel that lacks those.
				 */
				event_warn("timerfd_create");
			}
			epollop->timerfd = -1;
		}
	} else {
		epollop->timerfd = -1;
	}
#endif

	evsig_init_(base);

	return (epollop);
}

static const char *
change_to_string(int change)
{
	change &= (EV_CHANGE_ADD|EV_CHANGE_DEL);
	if (change == EV_CHANGE_ADD) {
		return "add";
	} else if (change == EV_CHANGE_DEL) {
		return "del";
	} else if (change == 0) {
		return "none";
	} else {
		return "???";
	}
}

static const char *
epoll_op_to_string(int op)
{
	return op == EPOLL_CTL_ADD?"ADD":
	    op == EPOLL_CTL_DEL?"DEL":
	    op == EPOLL_CTL_MOD?"MOD":
	    "???";
}

/*
  Here are the values we're masking off to decide what operations to do.
  Note that since EV_READ|EV_WRITE.

  Note also that this table is a little sparse, since ADD+DEL is
  nonsensical ("xxx" in the list below.)

  Note also also that we are shifting old_events by only 3 bits, since
  EV_READ is 2 and EV_WRITE is 4.

  The table was auto-generated with a python script, according to this
  pseudocode:

      If either the read or the write change is add+del:
	 This is impossible; Set op==-1, events=0.
      Else, if either the read or the write change is add:
	 Set events to 0.
	 If the read change is add, or
	    (the read change is not del, and ev_read is in old_events):
	       Add EPOLLIN to events.
	 If the write change is add, or
	    (the write change is not del, and ev_write is in old_events):
	       Add EPOLLOUT to events.

	 If old_events is set:
	       Set op to EPOLL_CTL_MOD [*1,*2]
	Else:
	       Set op to EPOLL_CTL_ADD [*3]

      Else, if the read or the write change is del:
	 Set op to EPOLL_CTL_DEL.
	 If the read change is del:
	     If the write change is del:
		 Set events to EPOLLIN|EPOLLOUT
	     Else if ev_write is in old_events:
		 Set events to EPOLLOUT
		Set op to EPOLL_CTL_MOD
	     Else
		 Set events to EPOLLIN
	 Else:
	     {The write change is del.}
	    If ev_read is in old_events:
		 Set events to EPOLLIN
		Set op to EPOLL_CTL_MOD
	    Else:
		Set the events to EPOLLOUT

      Else:
	   There is no read or write change; set op to 0 and events to 0.

      The logic is a little tricky, since we had no events set on the fd before,
      we need to set op="ADD" and set events=the events we want to add.	 If we
      had any events set on the fd before, and we want any events to remain on
      the fd, we need to say op="MOD" and set events=the events we want to
      remain.  But if we want to delete the last event, we say op="DEL" and
      set events=(any non-null pointer).

  [*1] This MOD is only a guess.  MOD might fail with ENOENT if the file was
       closed and a new file was opened with the same fd.  If so, we'll retry
       with ADD.

  [*2] We can't replace this with a no-op even if old_events is the same as
       the new events: if the file was closed and reopened, we need to retry
       with an ADD.  (We do a MOD in this case since "no change" is more
       common than "close and reopen", so we'll usually wind up doing 1
       syscalls instead of 2.)

  [*3] This ADD is only a guess.  There is a fun Linux kernel issue where if
       you have two fds for the same file (via dup) and you ADD one to an
       epfd, then close it, then re-create it with the same fd (via dup2 or an
       unlucky dup), then try to ADD it again, you'll get an EEXIST, since the
       struct epitem is not actually removed from the struct eventpoll until
       the file itself is closed.

  EV_CHANGE_ADD==1
  EV_CHANGE_DEL==2
  EV_READ      ==2
  EV_WRITE     ==4
  Bit 0: read change is add
  Bit 1: read change is del
  Bit 2: write change is add
  Bit 3: write change is del
  Bit 4: old events had EV_READ
  Bit 5: old events had EV_WRITE
*/

#define INDEX(c) \
	(   (((c)->read_change&(EV_CHANGE_ADD|EV_CHANGE_DEL))) |       \
	    (((c)->write_change&(EV_CHANGE_ADD|EV_CHANGE_DEL)) << 2) | \
	    (((c)->old_events&(EV_READ|EV_WRITE)) << 3) )

#if EV_READ != 2 || EV_WRITE != 4 || EV_CHANGE_ADD != 1 || EV_CHANGE_DEL != 2
#error "Libevent's internals changed!  Regenerate the op_table in epoll.c"
#endif

static const struct operation {
	int events;
	int op;
} op_table[] = {
	{ 0, 0 },                           /* old= 0, write:  0, read:  0 */
	{ EPOLLIN, EPOLL_CTL_ADD },         /* old= 0, write:  0, read:add */
	{ EPOLLIN, EPOLL_CTL_DEL },         /* old= 0, write:  0, read:del */
	{ 0, -1 },                          /* old= 0, write:  0, read:xxx */
	{ EPOLLOUT, EPOLL_CTL_ADD },        /* old= 0, write:add, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_ADD },/* old= 0, write:add, read:add */
	{ EPOLLOUT, EPOLL_CTL_ADD },        /* old= 0, write:add, read:del */
	{ 0, -1 },                          /* old= 0, write:add, read:xxx */
	{ EPOLLOUT, EPOLL_CTL_DEL },        /* old= 0, write:del, read:  0 */
	{ EPOLLIN, EPOLL_CTL_ADD },         /* old= 0, write:del, read:add */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_DEL },/* old= 0, write:del, read:del */
	{ 0, -1 },                          /* old= 0, write:del, read:xxx */
	{ 0, -1 },                          /* old= 0, write:xxx, read:  0 */
	{ 0, -1 },                          /* old= 0, write:xxx, read:add */
	{ 0, -1 },                          /* old= 0, write:xxx, read:del */
	{ 0, -1 },                          /* old= 0, write:xxx, read:xxx */
	{ 0, 0 },                           /* old= r, write:  0, read:  0 */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old= r, write:  0, read:add */
	{ EPOLLIN, EPOLL_CTL_DEL },         /* old= r, write:  0, read:del */
	{ 0, -1 },                          /* old= r, write:  0, read:xxx */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old= r, write:add, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old= r, write:add, read:add */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old= r, write:add, read:del */
	{ 0, -1 },                          /* old= r, write:add, read:xxx */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old= r, write:del, read:  0 */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old= r, write:del, read:add */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_DEL },/* old= r, write:del, read:del */
	{ 0, -1 },                          /* old= r, write:del, read:xxx */
	{ 0, -1 },                          /* old= r, write:xxx, read:  0 */
	{ 0, -1 },                          /* old= r, write:xxx, read:add */
	{ 0, -1 },                          /* old= r, write:xxx, read:del */
	{ 0, -1 },                          /* old= r, write:xxx, read:xxx */
	{ 0, 0 },                           /* old= w, write:  0, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old= w, write:  0, read:add */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old= w, write:  0, read:del */
	{ 0, -1 },                          /* old= w, write:  0, read:xxx */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old= w, write:add, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old= w, write:add, read:add */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old= w, write:add, read:del */
	{ 0, -1 },                          /* old= w, write:add, read:xxx */
	{ EPOLLOUT, EPOLL_CTL_DEL },        /* old= w, write:del, read:  0 */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old= w, write:del, read:add */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_DEL },/* old= w, write:del, read:del */
	{ 0, -1 },                          /* old= w, write:del, read:xxx */
	{ 0, -1 },                          /* old= w, write:xxx, read:  0 */
	{ 0, -1 },                          /* old= w, write:xxx, read:add */
	{ 0, -1 },                          /* old= w, write:xxx, read:del */
	{ 0, -1 },                          /* old= w, write:xxx, read:xxx */
	{ 0, 0 },                           /* old=rw, write:  0, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old=rw, write:  0, read:add */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old=rw, write:  0, read:del */
	{ 0, -1 },                          /* old=rw, write:  0, read:xxx */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old=rw, write:add, read:  0 */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_MOD },/* old=rw, write:add, read:add */
	{ EPOLLOUT, EPOLL_CTL_MOD },        /* old=rw, write:add, read:del */
	{ 0, -1 },                          /* old=rw, write:add, read:xxx */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old=rw, write:del, read:  0 */
	{ EPOLLIN, EPOLL_CTL_MOD },         /* old=rw, write:del, read:add */
	{ EPOLLIN|EPOLLOUT, EPOLL_CTL_DEL },/* old=rw, write:del, read:del */
	{ 0, -1 },                          /* old=rw, write:del, read:xxx */
	{ 0, -1 },                          /* old=rw, write:xxx, read:  0 */
	{ 0, -1 },                          /* old=rw, write:xxx, read:add */
	{ 0, -1 },                          /* old=rw, write:xxx, read:del */
	{ 0, -1 },                          /* old=rw, write:xxx, read:xxx */
};

static int
epoll_apply_one_change(struct event_base *base,
    struct epollop *epollop,
    const struct event_change *ch)
{
	struct epoll_event epev;
	int op, events = 0;
	int idx;

	idx = INDEX(ch);
	op = op_table[idx].op;
	events = op_table[idx].events;

	if (!events) {
		EVUTIL_ASSERT(op == 0);
		return 0;
	}

	if ((ch->read_change|ch->write_change) & EV_CHANGE_ET)
		events |= EPOLLET;

	memset(&epev, 0, sizeof(epev));
	epev.data.fd = ch->fd;
	epev.events = events;
	if (epoll_ctl(epollop->epfd, op, ch->fd, &epev) == 0) {
		event_debug(("Epoll %s(%d) on fd %d okay. [old events were %d; read change was %d; write change was %d]",
			epoll_op_to_string(op),
			(int)epev.events,
			(int)ch->fd,
			ch->old_events,
			ch->read_change,
			ch->write_change));
		return 0;
	}

	switch (op) {
	case EPOLL_CTL_MOD:
		if (errno == ENOENT) {
			/* If a MOD operation fails with ENOENT, the
			 * fd was probably closed and re-opened.  We
			 * should retry the operation as an ADD.
			 */
			if (epoll_ctl(epollop->epfd, EPOLL_CTL_ADD, ch->fd, &epev) == -1) {
				event_warn("Epoll MOD(%d) on %d retried as ADD; that failed too",
				    (int)epev.events, ch->fd);
				return -1;
			} else {
				event_debug(("Epoll MOD(%d) on %d retried as ADD; succeeded.",
					(int)epev.events,
					ch->fd));
				return 0;
			}
		}
		break;
	case EPOLL_CTL_ADD:
		if (errno == EEXIST) {
			/* If an ADD operation fails with EEXIST,
			 * either the operation was redundant (as with a
			 * precautionary add), or we ran into a fun
			 * kernel bug where using dup*() to duplicate the
			 * same file into the same fd gives you the same epitem
			 * rather than a fresh one.  For the second case,
			 * we must retry with MOD. */
			if (epoll_ctl(epollop->epfd, EPOLL_CTL_MOD, ch->fd, &epev) == -1) {
				event_warn("Epoll ADD(%d) on %d retried as MOD; that failed too",
				    (int)epev.events, ch->fd);
				return -1;
			} else {
				event_debug(("Epoll ADD(%d) on %d retried as MOD; succeeded.",
					(int)epev.events,
					ch->fd));
				return 0;
			}
		}
		break;
	case EPOLL_CTL_DEL:
		if (errno == ENOENT || errno == EBADF || errno == EPERM) {
			/* If a delete fails with one of these errors,
			 * that's fine too: we closed the fd before we
			 * got around to calling epoll_dispatch. */
			event_debug(("Epoll DEL(%d) on fd %d gave %s: DEL was unnecessary.",
				(int)epev.events,
				ch->fd,
				strerror(errno)));
			return 0;
		}
		break;
	default:
		break;
	}

	event_warn("Epoll %s(%d) on fd %d failed.  Old events were %d; read change was %d (%s); write change was %d (%s)",
	    epoll_op_to_string(op),
	    (int)epev.events,
	    ch->fd,
	    ch->old_events,
	    ch->read_change,
	    change_to_string(ch->read_change),
	    ch->write_change,
	    change_to_string(ch->write_change));

	return -1;
}

static int
epoll_apply_changes(struct event_base *base)
{
	struct event_changelist *changelist = &base->changelist;
	struct epollop *epollop = base->evbase;
	struct event_change *ch;

	int r = 0;
	int i;

	for (i = 0; i < changelist->n_changes; ++i) {
		ch = &changelist->changes[i];
		if (epoll_apply_one_change(base, epollop, ch) < 0)
			r = -1;
	}

	return (r);
}

static int
epoll_nochangelist_add(struct event_base *base, evutil_socket_t fd,
    short old, short events, void *p)
{
	struct event_change ch;
	ch.fd = fd;
	ch.old_events = old;
	ch.read_change = ch.write_change = 0;
	if (events & EV_WRITE)
		ch.write_change = EV_CHANGE_ADD |
		    (events & EV_ET);
	if (events & EV_READ)
		ch.read_change = EV_CHANGE_ADD |
		    (events & EV_ET);

	return epoll_apply_one_change(base, base->evbase, &ch);
}

static int
epoll_nochangelist_del(struct event_base *base, evutil_socket_t fd,
    short old, short events, void *p)
{
	struct event_change ch;
	ch.fd = fd;
	ch.old_events = old;
	ch.read_change = ch.write_change = 0;
	if (events & EV_WRITE)
		ch.write_change = EV_CHANGE_DEL;
	if (events & EV_READ)
		ch.read_change = EV_CHANGE_DEL;

	return epoll_apply_one_change(base, base->evbase, &ch);
}

static int
epoll_dispatch(struct event_base *base, struct timeval *tv)
{
	struct epollop *epollop = base->evbase;
	struct epoll_event *events = epollop->events;
	int i, res;
	long timeout = -1;

#ifdef USING_TIMERFD
	if (epollop->timerfd >= 0) {
		struct itimerspec is;
		is.it_interval.tv_sec = 0;
		is.it_interval.tv_nsec = 0;
		if (tv == NULL) {
			/* No timeout; disarm the timer. */
			is.it_value.tv_sec = 0;
			is.it_value.tv_nsec = 0;
		} else {
			if (tv->tv_sec == 0 && tv->tv_usec == 0) {
				/* we need to exit immediately; timerfd can't
				 * do that. */
				timeout = 0;
			}
			is.it_value.tv_sec = tv->tv_sec;
			is.it_value.tv_nsec = tv->tv_usec * 1000;
		}
		/* TODO: we could avoid unnecessary syscalls here by only
		   calling timerfd_settime when the top timeout changes, or
		   when we're called with a different timeval.
		*/
		if (timerfd_settime(epollop->timerfd, 0, &is, NULL) < 0) {
			event_warn("timerfd_settime");
		}
	} else
#endif
	if (tv != NULL) {
		timeout = evutil_tv_to_msec_(tv);
		if (timeout < 0 || timeout > MAX_EPOLL_TIMEOUT_MSEC) {
			/* Linux kernels can wait forever if the timeout is
			 * too big; see comment on MAX_EPOLL_TIMEOUT_MSEC. */
			timeout = MAX_EPOLL_TIMEOUT_MSEC;
		}
	}

	epoll_apply_changes(base);
	event_changelist_remove_all_(&base->changelist, base);

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	res = epoll_wait(epollop->epfd, events, epollop->nevents, timeout);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (res == -1) {
		if (errno != EINTR) {
			event_warn("epoll_wait");
			return (-1);
		}

		return (0);
	}

	event_debug(("%s: epoll_wait reports %d", __func__, res));
	EVUTIL_ASSERT(res <= epollop->nevents);

	for (i = 0; i < res; i++) {
		int what = events[i].events;
		short ev = 0;
#ifdef USING_TIMERFD
		if (events[i].data.fd == epollop->timerfd)
			continue;
#endif

		if (what & (EPOLLHUP|EPOLLERR)) {
			ev = EV_READ | EV_WRITE;
		} else {
			if (what & EPOLLIN)
				ev |= EV_READ;
			if (what & EPOLLOUT)
				ev |= EV_WRITE;
		}

		if (!ev)
			continue;

		evmap_io_active_(base, events[i].data.fd, ev | EV_ET);
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


static void
epoll_dealloc(struct event_base *base)
{
	struct epollop *epollop = base->evbase;

	evsig_dealloc_(base);
	if (epollop->events)
		mm_free(epollop->events);
	if (epollop->epfd >= 0)
		close(epollop->epfd);
#ifdef USING_TIMERFD
	if (epollop->timerfd >= 0)
		close(epollop->timerfd);
#endif

	memset(epollop, 0, sizeof(struct epollop));
	mm_free(epollop);
}

#endif /* EVENT__HAVE_EPOLL */
