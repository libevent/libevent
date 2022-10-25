/*
 * Signal handling backend based on signalfd(2) system call
 * Written by Dmitry Antipov <dantipov@cloudlinux.com> 2022
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

#include <unistd.h>
#include <sys/signalfd.h>

#include "event2/event.h"
#include "event-internal.h"
#include "evmap-internal.h"
#include "evsignal-internal.h"
#include "evthread-internal.h"

static int sigfd_add(struct event_base *, evutil_socket_t, short, short, void *);
static int sigfd_del(struct event_base *, evutil_socket_t, short, short, void *);

static const struct eventop sigfdops = {
	"signalfd_signal",
	NULL,
	sigfd_add,
	sigfd_del,
	NULL,
	NULL,
	0, 0, 0
};

static void
sigfd_cb(evutil_socket_t fd, short what, void *arg)
{
	struct signalfd_siginfo fdsi;
	struct event_base *base = arg;
	ssize_t ret = read(fd, &fdsi, sizeof(fdsi));

	EVUTIL_ASSERT(ret == sizeof(fdsi));
	EVUTIL_ASSERT(fdsi.ssi_signo > 0 && fdsi.ssi_signo < NSIG);
	EVUTIL_ASSERT(base->sig.ev_sigevent[fdsi.ssi_signo] != NULL);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	evmap_signal_active_(base, fdsi.ssi_signo, 1);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

static void
sigfd_free_sigevent(struct event_base *base, int signo)
{
	int ret;
	struct event* sigev = base->sig.ev_sigevent[signo];

	EVUTIL_ASSERT(sigev != NULL);
	event_del_nolock_(sigev, EVENT_DEL_AUTOBLOCK);
	ret = close(sigev->ev_fd);
	EVUTIL_ASSERT(ret == 0);
	mm_free(sigev);
	base->sig.ev_sigevent[signo] = NULL;
}

static int
sigfd_add(struct event_base *base, int signo, short old, short events, void *p)
{
	int sigfd;
	sigset_t mask;
	struct event* sigev;
	struct evsig_info *sig = &base->sig;

	/* EV_SIGNAL event passed from evmap_signal_add_() when setting
           up and from evmap_signal_reinit_iter_fn() during reinit. */
	EVUTIL_ASSERT(p != NULL);

	EVUTIL_ASSERT(signo > 0 && signo < NSIG);
	sigev = base->sig.ev_sigevent[signo];

	if (sigev != NULL) {
		if (old) {
			/* We're performing reinit after fork(). This is
			   required at least for epoll(2)-based backend
			   because if the process uses fork(2) to create
			   a child process, then the child will be able
			   to read(2) signals that are sent to it using the
			   signalfd(2) file descriptor, but epoll_wait(2)
			   will not indicate that the signalfd file
			   descriptor is ready. */
			sigfd_free_sigevent(base, signo);
		} else {
			/* We have an active signal fd
			   for this signal already. */
			return 0;
		}
	}

	/* Save previous handler just like evsig_set_handler_() does. */
	if (evsig_ensure_saved_(sig, signo) < 0)
		return -1;

	sig->sh_old[signo] = mm_malloc(sizeof *sig->sh_old[signo]);
	if (sig->sh_old[signo] == NULL) {
		event_warn("malloc() failed");
		return -1;
	}

	if (sigaction(signo, NULL, sig->sh_old[signo]) == -1) {
		event_warn("sigaction() failed");
		mm_free(sig->sh_old[signo]);
		sig->sh_old[signo] = NULL;
		return -1;
	}

	/* Block the signal from being handled according to its default
	   disposition so it may be received via the descriptor. */
	sigemptyset(&mask);
	sigaddset(&mask, signo);
	if (sigprocmask(SIG_BLOCK, &mask, NULL)) {
		event_warn("sigprocmask() failed");
		return -1;
	}

	sigfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sigfd < 0) {
		event_warn("signalfd() failed");
		goto unblock;
	}

	/* EV_READ event used to wakeup corresponding EV_SIGNAL ones. */
	sigev = event_new(base, sigfd, EV_READ | EV_PERSIST, sigfd_cb, base);
	if (!sigev)
		goto close_fd;

	/* This was blindly copied from evsig_init_(). */
	sigev->ev_flags |= EVLIST_INTERNAL;
	event_priority_set(sigev, 0);

	if (event_add_nolock_(sigev, NULL, 0) < 0)
		goto free_ev;

	base->sig.ev_sigevent[signo] = sigev;
	return 0;
free_ev:
	mm_free(sigev);
close_fd:
	close(sigfd);
unblock:
	sigprocmask(SIG_UNBLOCK, &mask, NULL);
	return -1;
}

static int
sigfd_del(struct event_base *base, int signo, short old, short events, void *p)
{
	sigset_t mask;
	struct event *sigev;
	struct evsig_info *sig = &base->sig;

	EVUTIL_ASSERT(signo > 0 && signo < NSIG);
	sigev = base->sig.ev_sigevent[signo];
	EVUTIL_ASSERT(sigev != NULL);

	sigemptyset(&mask);
	sigaddset(&mask, signo);
	if (sigprocmask(SIG_UNBLOCK, &mask, NULL)) {
		event_warn("sigprocmask() failed");
		return -1;
	}

	/* Restore previous handler, if any. */
	if (signo < sig->sh_old_max) {
		struct sigaction *sa = sig->sh_old[signo];
		if (sa) {
			if (sigaction(signo, sa, NULL) == -1) {
				event_warn("sigaction() failed");
				return -1;
			}
			mm_free(sa);
			sig->sh_old[signo] = NULL;
		}
	}

	sigfd_free_sigevent(base, signo);
	return 0;
}

int sigfd_init_(struct event_base *base)
{
	EVUTIL_ASSERT(base != NULL);
	if ((base->flags & EVENT_BASE_FLAG_DISALLOW_SIGNALFD) ||
	    getenv("EVENT_DISALLOW_SIGNALFD"))
		return -1;
	base->evsigsel = &sigfdops;
	return 0;
}
