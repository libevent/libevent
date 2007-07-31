/*	$OpenBSD: select.c,v 1.2 2002/06/25 15:50:15 mickey Exp $	*/

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

#include <sys/types.h>
#include <sys/tree.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <assert.h>

#include "event.h"
#include "event-internal.h"
#include "evsignal.h"
#include "log.h"

struct event_base *evsignal_base = NULL;

static void evsignal_handler(int sig);

/* Callback for when the signal handler write a byte to our signaling socket */
static void
evsignal_cb(int fd, short what, void *arg)
{
	static char signals[100];
	struct event *ev = arg;
	ssize_t n;

	n = read(fd, signals, sizeof(signals));
	if (n == -1)
		event_err(1, "%s: read", __func__);
	event_add(ev, NULL);
}

#ifdef HAVE_SETFD
#define FD_CLOSEONEXEC(x) do { \
        if (fcntl(x, F_SETFD, 1) == -1) \
                event_warn("fcntl(%d, F_SETFD)", x); \
} while (0)
#else
#define FD_CLOSEONEXEC(x)
#endif

void
evsignal_init(struct event_base *base)
{
	/* 
	 * Our signal handler is going to write to one end of the socket
	 * pair to wake up our event loop.  The event loop then scans for
	 * signals that got delivered.
	 */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, base->sig.ev_signal_pair) == -1)
		event_err(1, "%s: socketpair", __func__);

	FD_CLOSEONEXEC(base->sig.ev_signal_pair[0]);
	FD_CLOSEONEXEC(base->sig.ev_signal_pair[1]);
	base->sig.evsignal_caught = 0;
	memset(&base->sig.evsigcaught, 0, sizeof(sig_atomic_t)*NSIG);

	fcntl(base->sig.ev_signal_pair[0], F_SETFL, O_NONBLOCK);

	event_set(&base->sig.ev_signal, base->sig.ev_signal_pair[1], EV_READ,
	    evsignal_cb, &base->sig.ev_signal);
	base->sig.ev_signal.ev_base = base;
	base->sig.ev_signal.ev_flags |= EVLIST_INTERNAL;
}

int
evsignal_add(struct event *ev)
{
	int evsignal;
	struct sigaction sa;
	struct event_base *base = ev->ev_base;

	if (ev->ev_events & (EV_READ|EV_WRITE))
		event_errx(1, "%s: EV_SIGNAL incompatible use", __func__);
	evsignal = EVENT_SIGNAL(ev);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = evsignal_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags |= SA_RESTART;
	/* catch signals if they happen quickly */
	evsignal_base = base;

	if (sigaction(evsignal, &sa, NULL) == -1)
		return (-1);

	if (!base->sig.ev_signal_added) {
		base->sig.ev_signal_added = 1;
		event_add(&base->sig.ev_signal, NULL);
	}

	return (0);
}

int
evsignal_del(struct event *ev)
{
	return (sigaction(EVENT_SIGNAL(ev),(struct sigaction *)SIG_DFL, NULL));
}

static void
evsignal_handler(int sig)
{
	int save_errno = errno;

	if(evsignal_base == NULL) {
		event_warn(
			"%s: received signal %s, but have no base configured",
			__func__, sig);
		return;
	}

	evsignal_base->sig.evsigcaught[sig]++;
	evsignal_base->sig.evsignal_caught = 1;

	/* Wake up our notification mechanism */
	write(evsignal_base->sig.ev_signal_pair[0], "a", 1);
	errno = save_errno;
}

void
evsignal_process(struct event_base *base)
{
	struct event *ev;
	sig_atomic_t ncalls;

	base->sig.evsignal_caught = 0;
	TAILQ_FOREACH(ev, &base->sig.signalqueue, ev_signal_next) {
		ncalls = base->sig.evsigcaught[EVENT_SIGNAL(ev)];
		if (ncalls) {
			if (!(ev->ev_events & EV_PERSIST))
				event_del(ev);
			event_active(ev, EV_SIGNAL, ncalls);
			base->sig.evsigcaught[EVENT_SIGNAL(ev)] = 0;
		}
	}
}

void
evsignal_dealloc(struct event_base *base)
{
	if(base->sig.ev_signal_added) {
		event_del(&base->sig.ev_signal);
		base->sig.ev_signal_added = 0;
	}
	assert(TAILQ_EMPTY(&base->sig.signalqueue));

	close(base->sig.ev_signal_pair[0]);
	base->sig.ev_signal_pair[0] = -1;
	close(base->sig.ev_signal_pair[1]);
	base->sig.ev_signal_pair[1] = -1;
}
