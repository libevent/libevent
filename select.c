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
#include <sys/time.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

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

#ifndef howmany
#define        howmany(x, y)   (((x)+((y)-1))/(y))
#endif

struct selectop {
	int event_fds;		/* Highest fd in fd set */
	int event_fdsz;
	fd_set *event_readset;
	fd_set *event_writeset;
} sop;

void *select_init	(void);
int select_add		(void *, struct event *);
int select_del		(void *, struct event *);
int select_recalc	(void *, int);
int select_dispatch	(void *, struct timeval *);

struct eventop selectops = {
	"select",
	select_init,
	select_add,
	select_del,
	select_recalc,
	select_dispatch
};

void *
select_init(void)
{
	memset(&sop, 0, sizeof(sop));

	return (&sop);
}

/*
 * Called with the highest fd that we know about.  If it is 0, completely
 * recalculate everything.
 */

int
select_recalc(void *arg, int max)
{
	struct selectop *sop = arg;
	fd_set *readset, *writeset;
	struct event *ev;
	int fdsz;

	if (sop->event_fds < max)
		sop->event_fds = max;

	if (!sop->event_fds) {
		TAILQ_FOREACH(ev, &eventqueue, ev_next)
			if (ev->ev_fd > sop->event_fds)
				sop->event_fds = ev->ev_fd;
	}

	fdsz = howmany(sop->event_fds + 1, NFDBITS) * sizeof(fd_mask);
	if (fdsz > sop->event_fdsz) {
		if ((readset = realloc(sop->event_readset, fdsz)) == NULL) {
			log_error("malloc");
			return (-1);
		}

		if ((writeset = realloc(sop->event_writeset, fdsz)) == NULL) {
			log_error("malloc");
			free(readset);
			return (-1);
		}

		memset((char *)readset + sop->event_fdsz, 0,
		    fdsz - sop->event_fdsz);
		memset((char *)writeset + sop->event_fdsz, 0,
		    fdsz - sop->event_fdsz);

		sop->event_readset = readset;
		sop->event_writeset = writeset;
		sop->event_fdsz = fdsz;
	}

	return (0);
}

int
select_dispatch(void *arg, struct timeval *tv)
{
	int maxfd, res;
	struct event *ev, *next;
	struct selectop *sop = arg;

	memset(sop->event_readset, 0, sop->event_fdsz);
	memset(sop->event_writeset, 0, sop->event_fdsz);

	TAILQ_FOREACH(ev, &eventqueue, ev_next) {
		if (ev->ev_events & EV_WRITE)
			FD_SET(ev->ev_fd, sop->event_writeset);
		if (ev->ev_events & EV_READ)
			FD_SET(ev->ev_fd, sop->event_readset);
	}


	if ((res = select(sop->event_fds + 1, sop->event_readset, 
		 sop->event_writeset, NULL, tv)) == -1) {
		if (errno != EINTR) {
			log_error("select");
			return (-1);
		}
		
		return (0);
	}

	LOG_DBG((LOG_MISC, 80, __FUNCTION__": select reports %d",
		 res));

	maxfd = 0;
	for (ev = TAILQ_FIRST(&eventqueue); ev != NULL; ev = next) {
		next = TAILQ_NEXT(ev, ev_next);

		res = 0;
		if (FD_ISSET(ev->ev_fd, sop->event_readset))
			res |= EV_READ;
		if (FD_ISSET(ev->ev_fd, sop->event_writeset))
			res |= EV_WRITE;
		res &= ev->ev_events;

		if (res) {
			event_del(ev);
			event_active(ev, res);
		} else if (ev->ev_fd > maxfd)
			maxfd = ev->ev_fd;
	}

	sop->event_fds = maxfd;

	return (0);
}

int
select_add(void *arg, struct event *ev)
{
	struct selectop *sop = arg;

	/* 
	 * Keep track of the highest fd, so that we can calculate the size
	 * of the fd_sets for select(2)
	 */
	if (sop->event_fds < ev->ev_fd)
		sop->event_fds = ev->ev_fd;

	return (0);
}

/*
 * Nothing to be done here.
 */

int
select_del(void *arg, struct event *ev)
{
	return (0);
}
