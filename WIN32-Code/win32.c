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
#include "config.h"

#include <windows.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#ifdef USE_LOG
#include "log.h"
#else
#define LOG_DBG(x)
#define log_error(x)	perror(x)
#endif

#include "event.h"

extern struct event_list timequeue;
extern struct event_list eventqueue;
extern struct event_list addqueue;
extern struct event_list signalqueue;

#define NEVENT		64

int evsigcaught[NSIG];
volatile sig_atomic_t signal_caught = 0;
/* MSDN says this is required to handle SIGFPE */
volatile double SIGFPE_REQ = 0.0f; 

int signal_handler(int sig);
void signal_process(void);
int signal_recalc(void);

void *win32_init	(void);
int win32_insert	(void *, struct event *);
int win32_del	(void *, struct event *);
int win32_recalc	(void *, int);
int win32_dispatch	(void *, struct timeval *);

struct eventop win32ops = {
	"win32",
	win32_init,
	win32_insert,
	win32_del,
	win32_recalc,
	win32_dispatch
};

static int timeval_to_ms(struct timeval *tv)
{
	return ((tv->tv_sec * 1000) + (tv->tv_usec / 1000));
}

void *
win32_init(void)
{
	return (&win32ops);
}

int
win32_recalc(void *arg, int max)
{
	return (signal_recalc());
}

int
win32_insert(struct win32op *wop, struct event *ev)
{
	if (ev->ev_events & EV_SIGNAL) {
		if (ev->ev_events & (EV_READ|EV_WRITE))
			errx(1, "%s: EV_SIGNAL incompatible use",
			    __func__);
		if((int)signal(EVENT_SIGNAL(ev), signal_handler) == -1)
			return (-1);

		return (0);
	}

	return (0);
}

int
win32_dispatch(void *arg, struct timeval *tv)
{
	int res = 0;
	struct win32op *wop = arg;
	struct event *ev;
	int evres;

	TAILQ_FOREACH(ev, &eventqueue, ev_next) {
		res = WaitForSingleObject(ev->ev_fd, timeval_to_ms(tv));

		if(res == WAIT_TIMEOUT || res == WAIT_FAILED) {
			signal_process();
			return (0);
		} else if (signal_caught)
			signal_process();

		evres = 0;
		if(ev->ev_events & EV_READ)
			evres |= EV_READ;

		if(ev->ev_events & EV_WRITE)
			evres |= EV_WRITE;
		if(evres) {
			if(!(ev->ev_events & EV_PERSIST))
				event_del(ev);
			event_active(ev, evres, 1);
		}
	}

	if (signal_recalc() == -1)
		return (-1);

	return (0);
}

int
win32_del(struct win32op *arg, struct event *ev)
{
	return ((int)signal(EVENT_SIGNAL(ev), SIG_IGN));
}

static int signal_handler(int sig)
{
	evsigcaught[sig]++;
	signal_caught = 1;

	return 0;
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
