/*	$OpenBSD: poll.c,v 1.2 2002/06/25 15:50:15 mickey Exp $	*/

/*
 * Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>
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
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <poll.h>
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
#include "evsignal.h"

extern struct event_list eventqueue;

extern volatile sig_atomic_t evsignal_caught;

struct pollop {
	int event_count;		/* Highest number alloc */
	struct pollfd *event_set;
	struct event **event_back;
	sigset_t evsigmask;
} pollop;

void *poll_init	(void);
int poll_add		(void *, struct event *);
int poll_del		(void *, struct event *);
int poll_recalc	(void *, int);
int poll_dispatch	(void *, struct timeval *);

struct eventop pollops = {
	"poll",
	poll_init,
	poll_add,
	poll_del,
	poll_recalc,
	poll_dispatch
};

void *
poll_init(void)
{
	/* Disable kqueue when this environment variable is set */
	if (getenv("EVENT_NOPOLL"))
		return (NULL);

	memset(&pollop, 0, sizeof(pollop));

	evsignal_init(&pollop.evsigmask);

	return (&pollop);
}

/*
 * Called with the highest fd that we know about.  If it is 0, completely
 * recalculate everything.
 */

int
poll_recalc(void *arg, int max)
{
	struct pollop *pop = arg;

	return (evsignal_recalc(&pop->evsigmask));
}

int
poll_dispatch(void *arg, struct timeval *tv)
{
	int res, i, count, sec, nfds;
	struct event *ev;
	struct pollop *pop = arg;

	count = pop->event_count;
	nfds = 0;
	TAILQ_FOREACH(ev, &eventqueue, ev_next) {
		if (nfds + 1 >= count) {
			if (count < 32)
				count = 32;
			else
				count *= 2;

			/* We need more file descriptors */
			pop->event_set = realloc(pop->event_set,
			    count * sizeof(struct pollfd));
			if (pop->event_set == NULL) {
				log_error("realloc");
				return (-1);
			}
			pop->event_back = realloc(pop->event_back,
			    count * sizeof(struct event *));
			if (pop->event_back == NULL) {
				log_error("realloc");
				return (-1);
			}
			pop->event_count = count;
		}
		if (ev->ev_events & EV_WRITE) {
			struct pollfd *pfd = &pop->event_set[nfds];
			pfd->fd = ev->ev_fd;
			pfd->events = POLLOUT;
			pfd->revents = 0;

			pop->event_back[nfds] = ev;

			nfds++;
		}
		if (ev->ev_events & EV_READ) {
			struct pollfd *pfd = &pop->event_set[nfds];

			pfd->fd = ev->ev_fd;
			pfd->events = POLLIN;
			pfd->revents = 0;

			pop->event_back[nfds] = ev;

			nfds++;
		}
	}

	if (evsignal_deliver(&pop->evsigmask) == -1)
		return (-1);

	sec = tv->tv_sec * 1000 + tv->tv_usec / 1000;
	res = poll(pop->event_set, nfds, sec);

	if (evsignal_recalc(&pop->evsigmask) == -1)
		return (-1);

	if (res == -1) {
		if (errno != EINTR) {
			log_error("poll");
			return (-1);
		}

		evsignal_process();
		return (0);
	} else if (evsignal_caught)
		evsignal_process();

	LOG_DBG((LOG_MISC, 80, "%s: poll reports %d", __func__, res));

	if (res == 0)
		return (0);

	for (i = 0; i < nfds; i++) {
                int what = pop->event_set[i].revents;
		
		res = 0;

		/* If the file gets closed notify */
		if (what & POLLHUP)
			what |= POLLIN|POLLOUT;
                if (what & POLLERR) 
                        what |= POLLIN|POLLOUT;
		if (what & POLLIN)
			res |= EV_READ;
		if (what & POLLOUT)
			res |= EV_WRITE;
		if (res == 0)
			continue;

		ev = pop->event_back[i];
		res &= ev->ev_events;

		if (res) {
			if (!(ev->ev_events & EV_PERSIST))
				event_del(ev);
			event_active(ev, res, 1);
		}	
	}

	return (0);
}

int
poll_add(void *arg, struct event *ev)
{
	struct pollop *pop = arg;

	if (ev->ev_events & EV_SIGNAL)
		return (evsignal_add(&pop->evsigmask, ev));

	return (0);
}

/*
 * Nothing to be done here.
 */

int
poll_del(void *arg, struct event *ev)
{
	struct pollop *pop = arg;

	if (!(ev->ev_events & EV_SIGNAL))
		return (0);

	return (evsignal_del(&pop->evsigmask, ev));
}
