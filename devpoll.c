/*
 * Copyright 2000-2004 Niels Provos <provos@citi.umich.edu>
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
#include <sys/resource.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <sys/devpoll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <assert.h>

#ifdef USE_LOG
#include "log.h"
#else
#define LOG_DBG(x)
#define log_error	warn
#endif

#include "event.h"
#include "evsignal.h"

extern struct event_list eventqueue;

extern volatile sig_atomic_t evsignal_caught;

/* due to limitations in the devpoll interface, we need to keep track of
 * all file descriptors outself.
 */
struct evdevpoll {
	struct event *evread;
	struct event *evwrite;
};

struct devpollop {
	struct evdevpoll *fds;
	int nfds;
	struct pollfd *events;
	int nevents;
	int dpfd;
	sigset_t evsigmask;
} devpollop;

void *devpoll_init	(void);
int devpoll_add	(void *, struct event *);
int devpoll_del	(void *, struct event *);
int devpoll_recalc	(void *, int);
int devpoll_dispatch	(void *, struct timeval *);

struct eventop devpollops = {
	"devpoll",
	devpoll_init,
	devpoll_add,
	devpoll_del,
	devpoll_recalc,
	devpoll_dispatch
};

#define NEVENT	32000

void *
devpoll_init(void)
{
	int dpfd, nfiles = NEVENT;
	struct rlimit rl;

	/* Disable devpollueue when this environment variable is set */
	if (getenv("EVENT_NODEVPOLL"))
		return (NULL);

	memset(&devpollop, 0, sizeof(devpollop));

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
	    rl.rlim_cur != RLIM_INFINITY)
		nfiles = rl.rlim_cur;

	/* Initalize the kernel queue */

	if ((dpfd = open("/dev/poll", O_RDWR)) == -1) {
		log_error("open: /dev/poll");
		return (NULL);
	}

	devpollop.dpfd = dpfd;

	/* Initalize fields */
	devpollop.events = malloc(nfiles * sizeof(struct pollfd));
	if (devpollop.events == NULL)
		return (NULL);
	devpollop.nevents = nfiles;

	devpollop.fds = calloc(nfiles, sizeof(struct evdevpoll));
	if (devpollop.fds == NULL) {
		free(devpollop.events);
		return (NULL);
	}
	devpollop.nfds = nfiles;

	evsignal_init(&devpollop.evsigmask);

	return (&devpollop);
}

int
devpoll_recalc(void *arg, int max)
{
	struct devpollop *devpollop = arg;

	if (max > devpollop->nfds) {
		struct evdevpoll *fds;
		int nfds;

		nfds = devpollop->nfds;
		while (nfds < max)
			nfds <<= 1;

		fds = realloc(devpollop->fds, nfds * sizeof(struct evdevpoll));
		if (fds == NULL) {
			log_error("realloc");
			return (-1);
		}
		devpollop->fds = fds;
		memset(fds + devpollop->nfds, 0,
		    (nfds - devpollop->nfds) * sizeof(struct evdevpoll));
		devpollop->nfds = nfds;
	}

	return (evsignal_recalc(&devpollop->evsigmask));
}

int
devpoll_dispatch(void *arg, struct timeval *tv)
{
	struct devpollop *devpollop = arg;
	struct pollfd *events = devpollop->events;
	struct dvpoll dvp;
	struct evdevpoll *evdp;
	int i, res, timeout;

	if (evsignal_deliver(&devpollop->evsigmask) == -1)
		return (-1);

	timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;

	dvp.dp_fds = devpollop->events;
	dvp.dp_nfds = devpollop->nevents;
	dvp.dp_timeout = timeout;

	res = ioctl(devpollop->dpfd, DP_POLL, &dvp);

	if (evsignal_recalc(&devpollop->evsigmask) == -1)
		return (-1);

	if (res == -1) {
		if (errno != EINTR) {
			log_error("ioctl: DP_POLL");
			return (-1);
		}

		evsignal_process();
		return (0);
	} else if (evsignal_caught)
		evsignal_process();

	LOG_DBG((LOG_MISC, 80, "%s: devpoll_wait reports %d", __func__, res));

	for (i = 0; i < res; i++) {
		int which = 0;
		int what = events[i].revents;
		struct event *evread = NULL, *evwrite = NULL;

		assert(events[i].fd < devpollop->nfds);
		evdp = &devpollop->fds[events[i].fd];
   
                if (what & POLLHUP)
                        what |= POLLIN | POLLOUT;
                else if (what & POLLERR)
                        what |= POLLIN | POLLOUT;

		if (what & POLLIN) {
			evread = evdp->evread;
			which |= EV_READ;
		}

		if (what & POLLOUT) {
			evwrite = evdp->evwrite;
			which |= EV_WRITE;
		}

		if (!which)
			continue;

		if (evread != NULL && !(evread->ev_events & EV_PERSIST))
			event_del(evread);
		if (evwrite != NULL && evwrite != evread &&
		    !(evwrite->ev_events & EV_PERSIST))
			event_del(evwrite);

		if (evread != NULL)
			event_active(evread, EV_READ, 1);
		if (evwrite != NULL)
			event_active(evwrite, EV_WRITE, 1);
	}

	return (0);
}


int
devpoll_add(void *arg, struct event *ev)
{
	struct devpollop *devpollop = arg;
	struct pollfd dpev;
	struct evdevpoll *evdp;
	int fd, events;

	if (ev->ev_events & EV_SIGNAL)
		return (evsignal_add(&devpollop->evsigmask, ev));

	fd = ev->ev_fd;
	if (fd >= devpollop->nfds) {
		/* Extent the file descriptor array as necessary */
		if (devpoll_recalc(devpollop, fd) == -1)
			return (-1);
	}
	evdp = &devpollop->fds[fd];

	events = 0;
	if (evdp->evread != NULL) {
		events |= POLLIN;
	}
	if (evdp->evwrite != NULL) {
		events |= POLLOUT;
	}

	if (ev->ev_events & EV_READ)
		events |= POLLIN;
	if (ev->ev_events & EV_WRITE)
		events |= POLLOUT;

	dpev.fd = fd;
	dpev.events = events;
	dpev.revents = 0;
	/*
	 * Due to a bug in Solaris, we have to use pwrite with an offset of 0.
	 * Write is limited to 2GB of data, until it will fail.
	 */
	if (pwrite(devpollop->dpfd, &dpev, sizeof(dpev), 0) == -1)
			return (-1);

	/* Update events responsible */
	if (ev->ev_events & EV_READ)
		evdp->evread = ev;
	if (ev->ev_events & EV_WRITE)
		evdp->evwrite = ev;

	return (0);
}

int
devpoll_del(void *arg, struct event *ev)
{
	struct devpollop *devpollop = arg;
	struct pollfd dpev;
	struct evdevpoll *evdp;
	int fd, events, op;
	int needwritedelete = 1, needreaddelete = 1;

	if (ev->ev_events & EV_SIGNAL)
		return (evsignal_del(&devpollop->evsigmask, ev));

	fd = ev->ev_fd;
	if (fd >= devpollop->nfds)
		return (0);
	evdp = &devpollop->fds[fd];

	events = 0;
	if (ev->ev_events & EV_READ)
		events |= POLLIN;
	if (ev->ev_events & EV_WRITE)
		events |= POLLOUT;

	if ((events & (POLLIN|POLLOUT)) != (POLLIN|POLLOUT)) {
		if ((events & POLLIN) && evdp->evwrite != NULL) {
			needwritedelete = 0;
			events = POLLOUT;
		} else if ((events & POLLOUT) && evdp->evread != NULL) {
			needreaddelete = 0;
			events = POLLIN;
		}
	}

	dpev.fd = fd;
	dpev.events = events | POLLREMOVE;
	dpev.revents = 0;

	if (pwrite(devpollop->dpfd, &dpev, sizeof(dpev), 0) == -1)
		return (-1);

	if (needreaddelete)
		evdp->evread = NULL;
	if (needwritedelete)
		evdp->evwrite = NULL;

	return (0);
}
