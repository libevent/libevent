#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Enable F_SETSIG and F_SETOWN */
#define _GNU_SOURCE

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else
#include <sys/_time.h>
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/queue.h>
#ifndef HAVE_WORKING_RTSIG
#include <sys/stat.h>
#endif
#include <unistd.h>

#define EVLIST_X_NORT	0x1000	/* Skip RT signals (internal) */

#include "event.h"
extern struct event_list eventqueue;
extern struct event_list signalqueue;

struct rtsigop {
    sigset_t sigs;
    struct pollfd *poll;
    struct event **toev;
    int cur, max, total;
#ifndef HAVE_WORKING_RTSIG
    int pollmode;
#endif
};

#define INIT_MAX 16

static int
poll_add(struct rtsigop *op, struct event *ev)
{
    struct pollfd *pfd;

    if (op->poll == NULL) return 0;

    if (op->cur == op->max) {
        void *p;

        p = realloc(op->poll, sizeof(*op->poll) * (op->max << 1));
        if (!p) {
            errno = ENOMEM;
            return -1;
        }
        op->poll = p;
        p = realloc(op->toev, sizeof(*op->toev) * (op->max << 1));
        if (!p) {
            op->poll = realloc(op->poll, sizeof(*op->poll) * op->max);
            errno = ENOMEM;
            return -1;
        }
        op->toev = p;
        op->max <<= 1;
    }

    pfd = &op->poll[op->cur];
    pfd->fd = ev->ev_fd;
    pfd->events = 0;
    if (ev->ev_events & EV_READ) pfd->events |= POLLIN;
    if (ev->ev_events & EV_WRITE) pfd->events |= POLLOUT;
    pfd->revents = 0;

    op->toev[op->cur] = ev;
    op->cur++;

    return 0;
}

static void
poll_free(struct rtsigop *op, int n)
{
    if (op->poll == NULL) return;

    op->cur--;
    if (n < op->cur) {
        memcpy(&op->poll[n], &op->poll[op->cur], sizeof(*op->poll));
        op->toev[n] = op->toev[op->cur];
    }
    if (op->max > INIT_MAX && op->cur < op->max >> 1) {
        op->max >>= 1;
        op->poll = realloc(op->poll, sizeof(*op->poll) * op->max);
        op->toev = realloc(op->toev, sizeof(*op->toev) * op->max);
    }
}

static void
poll_remove(struct rtsigop *op, struct event *ev)
{
    int i;

    for (i = 0; i < op->cur; i++) {
        if (op->toev[i] == ev) {
            poll_free(op, i);
            break;
        }
    }
}

static void
activate(struct event *ev, int flags)
{
    if (!(ev->ev_events & EV_PERSIST)) event_del(ev);
    event_active(ev, flags, 1);
}

void *rtsig_init(void);
int rtsig_add(void *, struct event *);
int rtsig_del(void *, struct event *);
int rtsig_recalc(void *, int);
int rtsig_dispatch(void *, struct timeval *);

struct eventop rtsigops = {
    "rtsig",
    rtsig_init,
    rtsig_add,
    rtsig_del,
    rtsig_recalc,
    rtsig_dispatch
};

void *
rtsig_init(void)
{
	struct rtsigop *op;

	if (getenv("EVENT_NORTSIG"))
		return (NULL);

	op = malloc(sizeof(*op));
	if (op == NULL) return (NULL);

	memset(op, 0, sizeof(*op));

	op->max = INIT_MAX;
	op->poll = malloc(sizeof(*op->poll) * op->max);
	if (op->poll == NULL) {
		free(op);
		return (NULL);
	}
	op->toev = malloc(sizeof(*op->toev) * op->max);
	if (op->toev == NULL) {
		free(op->poll);
		free(op);
		return (NULL);
	}

	sigemptyset(&op->sigs);
	sigaddset(&op->sigs, SIGIO);
	sigaddset(&op->sigs, SIGRTMIN);
	sigprocmask(SIG_BLOCK, &op->sigs, NULL);

	return (op);
}

int
rtsig_add(void *arg, struct event *ev)
{
	struct rtsigop *op = (struct rtsigop *) arg;
	int flags, i;
#ifndef HAVE_WORKING_RTSIG
	struct stat st;
#endif

	if (ev->ev_events & EV_SIGNAL) {
		sigaddset(&op->sigs, EVENT_SIGNAL(ev));
		return sigprocmask(SIG_BLOCK, &op->sigs, NULL);
	}

	if (!(ev->ev_events & (EV_READ | EV_WRITE))) return 0;

#ifndef HAVE_WORKING_RTSIG
	if (fstat(ev->ev_fd, &st) == -1) return -1;
	if (S_ISFIFO(st.st_mode)) {
		ev->ev_flags |= EVLIST_X_NORT;
		op->pollmode++;
	}
#endif

	flags = fcntl(ev->ev_fd, F_GETFL);
	if (flags == -1)
		return (-1);

	if (!(flags & O_ASYNC)) {
		if (fcntl(ev->ev_fd, F_SETSIG, SIGRTMIN) == -1
		    || fcntl(ev->ev_fd, F_SETOWN, (int) getpid()) == -1)
			return (-1);

		if (fcntl(ev->ev_fd, F_SETFL, flags | O_ASYNC))
			return (-1);
	}

#ifdef O_ONESIGFD
	fcntl(ev->ev_fd, F_SETAUXFL, O_ONESIGFD);
#endif

	op->total++;
	if (poll_add(op, ev) == -1)
		goto err;

	return (0);

 err:
	i = errno;
	fcntl(ev->ev_fd, F_SETFL, flags);
	errno = i;
	return (-1);
}

int
rtsig_del(void *arg, struct event *ev)
{
	struct rtsigop *op = (struct rtsigop *) arg;

	if (ev->ev_events & EV_SIGNAL) {
		sigset_t sigs;

		sigdelset(&op->sigs, EVENT_SIGNAL(ev));

		sigemptyset(&sigs);
		sigaddset(&sigs, EVENT_SIGNAL(ev));
		return (sigprocmask(SIG_UNBLOCK, &sigs, NULL));
	}

	if (!(ev->ev_events & (EV_READ | EV_WRITE)))
		return (0);

#ifndef HAVE_WORKING_RTSIG
	if (ev->ev_flags & EVLIST_X_NORT)
		op->pollmode--;
#endif
	poll_remove(op, ev);
	op->total--;

	return (0);
}

int
rtsig_recalc(void *arg, int max)
{
    return (0);
}

int
rtsig_dispatch(void *arg, struct timeval *tv)
{
	struct rtsigop *op = (struct rtsigop *) arg;
	struct timespec ts;
	int res, i;

	if (op->poll == NULL)
		goto retry_poll;
#ifndef HAVE_WORKING_RTSIG
	if (op->pollmode)
		goto poll_all;
#endif

	if (op->cur) {
		ts.tv_sec = ts.tv_nsec = 0;
	} else {
		ts.tv_sec = tv->tv_sec;
		ts.tv_nsec = tv->tv_usec * 1000;
	}

	for (;;) {
		siginfo_t info;
		struct event *ev;
		int signum;

		signum = sigtimedwait(&op->sigs, &info, &ts);

		if (signum == -1) {
			if (errno == EAGAIN)
				break;
			return (errno == EINTR ? 0 : -1);
		}

		ts.tv_sec = ts.tv_nsec = 0;

		if (signum == SIGIO) {
#ifndef HAVE_WORKING_RTSIG
		poll_all:
#endif
			free(op->poll);
			free(op->toev);
		retry_poll:
			op->cur = 0;
			op->max = op->total;
			op->poll = malloc(sizeof(*op->poll) * op->total);
			if (op->poll == NULL)
				return (-1);
			op->toev = malloc(sizeof(*op->toev) * op->total);
			if (op->toev == NULL) {
				free(op->poll);
				op->poll = NULL;
				return (-1);
			}

			TAILQ_FOREACH(ev, &eventqueue, ev_next)
			    if (!(ev->ev_flags & EVLIST_X_NORT))
				    poll_add(op, ev);

			break;
		}

		if (signum == SIGRTMIN) {
			int flags, i, sigok = 0;

			if (info.si_band <= 0) { /* SI_SIGIO */
				flags = EV_READ | EV_WRITE;
			} else {
				flags = 0;
				if (info.si_band & POLLIN) flags |= EV_READ;
				if (info.si_band & POLLOUT) flags |= EV_WRITE;
				if (!flags) continue;
			}

			for (i = 0; flags && i < op->cur; i++) {
				ev = op->toev[i];

				if (ev->ev_fd == info.si_fd) {
					flags &= ~ev->ev_events;
					sigok = 1;
				}
			}

			for (ev = TAILQ_FIRST(&eventqueue);
			    flags && ev != TAILQ_END(&eventqueue);
			    ev = TAILQ_NEXT(ev, ev_next)) {
				if (ev->ev_fd == info.si_fd) {
					if (flags & ev->ev_events) {
						i = poll_add(op, ev);
						if (i == -1) return -1;
						flags &= ~ev->ev_events;
					}
					sigok = 1;
				}
			}

			if (!sigok) {
				flags = fcntl(info.si_fd, F_GETFL);
				if (flags == -1) return -1;
				fcntl(info.si_fd, F_SETFL, flags & ~O_ASYNC);
			}
		} else {
			TAILQ_FOREACH(ev, &signalqueue, ev_signal_next) {
				if (EVENT_SIGNAL(ev) == signum)
					activate(ev, EV_SIGNAL);
			}
		}
	}

	if (!op->cur)
		return (0);

	res = poll(op->poll, op->cur, tv->tv_sec * 1000 + tv->tv_usec / 1000);
	if (res < 0)
		return (-1);

	i = 0;
#ifdef HAVE_WORKING_RTSIG
	while (i < res) {
#else
	while (i < op->cur) {
#endif
		if (op->poll[i].revents) {
			int flags = 0;
			struct event *ev = op->toev[i];

			if (op->poll[i].revents & POLLIN)
				flags |= EV_READ;
			if (op->poll[i].revents & POLLOUT)
				flags |= EV_WRITE;

			if (!(ev->ev_events & EV_PERSIST)) {
				event_del(ev);
				res--;
			} else {
				i++;
			}
			event_active(ev, flags, 1);
		} else {
#ifndef HAVE_WORKING_RTSIG
			if (op->toev[i]->ev_flags & EVLIST_X_NORT) {
				i++;
				res++;
				continue;
			}
#endif
			for (;;) {
				op->cur--;
				if (i == op->cur)
					break;
				if (op->poll[op->cur].revents) {
					memcpy(&op->poll[i], &op->poll[op->cur], sizeof(*op->poll));
					op->toev[i] = op->toev[op->cur];
					break;
				}
			}
		}
	}
#ifdef HAVE_WORKING_RTSIG
	op->cur = res;
#endif

	if (!op->cur) {
		op->max = INIT_MAX;
		free(op->poll);
		free(op->toev);
		/* We just freed it, we shouldn't have a problem getting it back. */
		op->poll = malloc(sizeof(*op->poll) * op->max);
		op->toev = malloc(sizeof(*op->toev) * op->max);

		if (op->poll == NULL || op->toev == NULL)
			err(1, "%s: malloc");
	}

	return (0);
}
