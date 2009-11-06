/*	$OpenBSD: select.c,v 1.2 2002/06/25 15:50:15 mickey Exp $	*/

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

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif
#include <sys/types.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef _EVENT_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "event2/event.h"
#include "event2/event_struct.h"
#include "event-internal.h"
#include "event2/util.h"
#include "evsignal-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"

static int evsig_add(struct event_base *, int, short, short, void *);
static int evsig_del(struct event_base *, int, short, short, void *);

static const struct eventop evsigops = {
	"signal",
	NULL,
	evsig_add,
	evsig_del,
	NULL,
	NULL,
	0, 0, 0
};

struct event_base *evsig_base = NULL;

static void evsig_handler(int sig);

/* Callback for when the signal handler write a byte to our signaling socket */
static void
evsig_cb(evutil_socket_t fd, short what, void *arg)
{
	static char signals[1];
	ev_ssize_t n;

        (void)arg; /* Suppress "unused variable" warning. */

	n = recv(fd, signals, sizeof(signals), 0);
	if (n == -1)
		event_sock_err(1, fd, "%s: read", __func__);
}

#ifdef _EVENT_HAVE_SETFD
#define FD_CLOSEONEXEC(x) do { \
        if (fcntl(x, F_SETFD, 1) == -1) \
                event_warn("fcntl(%d, F_SETFD)", x); \
} while (0)
#else
#define FD_CLOSEONEXEC(x)
#endif

int
evsig_init(struct event_base *base)
{
	/*
	 * Our signal handler is going to write to one end of the socket
	 * pair to wake up our event loop.  The event loop then scans for
	 * signals that got delivered.
	 */
	if (evutil_socketpair(
		    AF_UNIX, SOCK_STREAM, 0, base->sig.ev_signal_pair) == -1) {
#ifdef WIN32
		/* Make this nonfatal on win32, where sometimes people
		   have localhost firewalled. */
		event_sock_warn(-1, "%s: socketpair", __func__);
#else
		event_sock_err(1, -1, "%s: socketpair", __func__);
#endif
		return -1;
	}

	FD_CLOSEONEXEC(base->sig.ev_signal_pair[0]);
	FD_CLOSEONEXEC(base->sig.ev_signal_pair[1]);
	base->sig.sh_old = NULL;
	base->sig.sh_old_max = 0;
	base->sig.evsig_caught = 0;
	memset(&base->sig.evsigcaught, 0, sizeof(sig_atomic_t)*NSIG);

        evutil_make_socket_nonblocking(base->sig.ev_signal_pair[0]);

	event_assign(&base->sig.ev_signal, base, base->sig.ev_signal_pair[1],
		EV_READ | EV_PERSIST, evsig_cb, &base->sig.ev_signal);

	base->sig.ev_signal.ev_flags |= EVLIST_INTERNAL;

	base->evsigsel = &evsigops;
	base->evsigbase = &base->sig;

	return 0;
}

/* Helper: set the signal handler for evsignal to handler in base, so that
 * we can restore the original handler when we clear the current one. */
int
_evsig_set_handler(struct event_base *base,
		      int evsignal, void (*handler)(int))
{
#ifdef _EVENT_HAVE_SIGACTION
	struct sigaction sa;
#else
	ev_sighandler_t sh;
#endif
	struct evsig_info *sig = &base->sig;
	void *p;

	/*
	 * resize saved signal handler array up to the highest signal number.
	 * a dynamic array is used to keep footprint on the low side.
	 */
	if (evsignal >= sig->sh_old_max) {
		int new_max = evsignal + 1;
		event_debug(("%s: evsignal (%d) >= sh_old_max (%d), resizing",
			    __func__, evsignal, sig->sh_old_max));
		p = mm_realloc(sig->sh_old, new_max * sizeof(*sig->sh_old));
		if (p == NULL) {
			event_warn("realloc");
			return (-1);
		}

		memset((char *)p + sig->sh_old_max * sizeof(*sig->sh_old),
		    0, (new_max - sig->sh_old_max) * sizeof(*sig->sh_old));

		sig->sh_old_max = new_max;
		sig->sh_old = p;
	}

	/* allocate space for previous handler out of dynamic array */
	sig->sh_old[evsignal] = mm_malloc(sizeof *sig->sh_old[evsignal]);
	if (sig->sh_old[evsignal] == NULL) {
		event_warn("malloc");
		return (-1);
	}

	/* save previous handler and setup new handler */
#ifdef _EVENT_HAVE_SIGACTION
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = handler;
	sa.sa_flags |= SA_RESTART;
	sigfillset(&sa.sa_mask);

	if (sigaction(evsignal, &sa, sig->sh_old[evsignal]) == -1) {
		event_warn("sigaction");
		mm_free(sig->sh_old[evsignal]);
		return (-1);
	}
#else
	if ((sh = signal(evsignal, handler)) == SIG_ERR) {
		event_warn("signal");
		mm_free(sig->sh_old[evsignal]);
		return (-1);
	}
	*sig->sh_old[evsignal] = sh;
#endif

	return (0);
}

static int
evsig_add(struct event_base *base, int evsignal, short old, short events, void *p)
{
	struct evsig_info *sig = &base->sig;
	(void)p;

	EVUTIL_ASSERT(evsignal >= 0 && evsignal < NSIG);

	event_debug(("%s: %d: changing signal handler", __func__, evsignal));
	if (_evsig_set_handler(base, evsignal, evsig_handler) == -1)
		return (-1);

	/* catch signals if they happen quickly */
	evsig_base = base;

	if (!sig->ev_signal_added) {
		if (event_add(&sig->ev_signal, NULL))
			return (-1);
		sig->ev_signal_added = 1;
	}

	return (0);
}

int
_evsig_restore_handler(struct event_base *base, int evsignal)
{
	int ret = 0;
	struct evsig_info *sig = &base->sig;
#ifdef _EVENT_HAVE_SIGACTION
	struct sigaction *sh;
#else
	ev_sighandler_t *sh;
#endif

	/* restore previous handler */
	sh = sig->sh_old[evsignal];
	sig->sh_old[evsignal] = NULL;
#ifdef _EVENT_HAVE_SIGACTION
	if (sigaction(evsignal, sh, NULL) == -1) {
		event_warn("sigaction");
		ret = -1;
	}
#else
	if (signal(evsignal, *sh) == SIG_ERR) {
		event_warn("signal");
		ret = -1;
	}
#endif

	mm_free(sh);

	return ret;
}

static int
evsig_del(struct event_base *base, int evsignal, short old, short events, void *p)
{
	EVUTIL_ASSERT(evsignal >= 0 && evsignal < NSIG);

	event_debug(("%s: %d: restoring signal handler", __func__, evsignal));

	return (_evsig_restore_handler(base, evsignal));
}

static void
evsig_handler(int sig)
{
	int save_errno = errno;
#ifdef WIN32
	int socket_errno = EVUTIL_SOCKET_ERROR();
#endif

	if (evsig_base == NULL) {
		event_warn(
			"%s: received signal %d, but have no base configured",
			__func__, sig);
		return;
	}

	evsig_base->sig.evsigcaught[sig]++;
	evsig_base->sig.evsig_caught = 1;

#ifndef _EVENT_HAVE_SIGACTION
	signal(sig, evsig_handler);
#endif

	/* Wake up our notification mechanism */
	send(evsig_base->sig.ev_signal_pair[0], "a", 1, 0);
	errno = save_errno;
#ifdef WIN32
	EVUTIL_SET_SOCKET_ERROR(socket_errno);
#endif
}

void
evsig_process(struct event_base *base)
{
	struct evsig_info *sig = &base->sig;
	sig_atomic_t ncalls;
	int i;

	base->sig.evsig_caught = 0;
	for (i = 1; i < NSIG; ++i) {
		ncalls = sig->evsigcaught[i];
		if (ncalls == 0)
			continue;
		sig->evsigcaught[i] -= ncalls;

		evmap_signal_active(base, i, ncalls);
	}
}

void
evsig_dealloc(struct event_base *base)
{
	int i = 0;
	if (base->sig.ev_signal_added) {
		event_del(&base->sig.ev_signal);
		base->sig.ev_signal_added = 0;
	}
	for (i = 0; i < NSIG; ++i) {
		if (i < base->sig.sh_old_max && base->sig.sh_old[i] != NULL)
			_evsig_restore_handler(base, i);
	}

	EVUTIL_CLOSESOCKET(base->sig.ev_signal_pair[0]);
	base->sig.ev_signal_pair[0] = -1;
	EVUTIL_CLOSESOCKET(base->sig.ev_signal_pair[1]);
	base->sig.ev_signal_pair[1] = -1;
	base->sig.sh_old_max = 0;

	/* per index frees are handled in evsig_del() */
	if (base->sig.sh_old)
		mm_free(base->sig.sh_old);
}
