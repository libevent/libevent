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
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>

#ifdef USE_LOG
#include "log.h"
#else
#define LOG_DBG(x)
#define log_error(x)	perror(x)
#endif

#include "event.h"

extern struct event_list signalqueue;

static short evsigcaught[NSIG];
static int needrecalc;
volatile sig_atomic_t evsignal_caught = 0;

void evsignal_process(void);
int evsignal_recalc(sigset_t *);
int evsignal_deliver(sigset_t *);

void
evsignal_init(sigset_t *evsigmask)
{
	sigemptyset(evsigmask);
}

int
evsignal_add(sigset_t *evsigmask, struct event *ev)
{
	int signal;
	
	if (ev->ev_events & (EV_READ|EV_WRITE))
		errx(1, "%s: EV_SIGNAL incompatible use", __func__);
	signal = EVENT_SIGNAL(ev);
	sigaddset(evsigmask, signal);
	
	return (0);
}

/*
 * Nothing to be done here.
 */

int
evsignal_del(sigset_t *evsigmask, struct event *ev)
{
	int signal;

	signal = EVENT_SIGNAL(ev);
	sigdelset(evsigmask, signal);
	needrecalc = 1;

	return (sigaction(EVENT_SIGNAL(ev),(struct sigaction *)SIG_DFL, NULL));
}

static void
evsignal_handler(int sig)
{
	evsigcaught[sig]++;
	evsignal_caught = 1;
}

int
evsignal_recalc(sigset_t *evsigmask)
{
	struct sigaction sa;
	struct event *ev;

	if (TAILQ_FIRST(&signalqueue) == NULL && !needrecalc)
		return (0);
	needrecalc = 0;

	if (sigprocmask(SIG_BLOCK, evsigmask, NULL) == -1)
		return (-1);
	
	/* Reinstall our signal handler. */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = evsignal_handler;
	sa.sa_mask = *evsigmask;
	sa.sa_flags |= SA_RESTART;
	
	TAILQ_FOREACH(ev, &signalqueue, ev_signal_next) {
		if (sigaction(EVENT_SIGNAL(ev), &sa, NULL) == -1)
			return (-1);
	}
	return (0);
}

int
evsignal_deliver(sigset_t *evsigmask)
{
	if (TAILQ_FIRST(&signalqueue) == NULL)
		return (0);

	return (sigprocmask(SIG_UNBLOCK, evsigmask, NULL));
	/* XXX - pending signals handled here */
}

void
evsignal_process(void)
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
	evsignal_caught = 0;
}

