/*
 * Copyright (c) 2006 Mathew Mills <mathewmills@mac.com>
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
/*
 * Meta-level comments: You know that a kernel interface is wrong if
 * supporting it requires three times more code than any of the other
 * kernel interfaces supported in libevent.  Niels - 2006-02-22
 */
/**

   "RTSIG" is a shorthand for using O_ASYNC to make descriptors send
   signals when readable/writable and to use POSIX real-time signals
   witch are queued unlike normal signals.  At first blush this may
   seem like a alternative to epoll, but a number of problems arise
   when attempting to build an eventloop entirely out of rtsig.
   Still, we can use rtsig in combination with poll() to
   provide an eventloop that allows for many thousands of sockets
   without huge overheads implicit with using select() or poll()
   alone.  epoll and kqueue are far superior to rtsig and should be
   used where available, but rtsig has been in standard Linux kernels
   for a long time and have a huge installation base.  epoll requires
   special patches for 2.4 kernels and 2.6 kernels are not yet nearly
   so ubiquitous.

   rtsig problems:
    - O_ASYNC mechanisms work only on sockets - not pipes or tty's

    - O_ASYNC signals are edge-triggered, POLLIN on packet arriving
   or socket close; POLLOUT when a socket transitions from
   non-writable to writable.  Being edge-triggered means the
   event-handler callbacks must transition the level ( reading
   completely the socket buffer contents ) or it will be unable to
   reliably receive notification again.

   - rtsig implementations must be intimately involved in how a
   process dispatches signals.

   - delivering signals per-event can be expensive, CPU-wise, but
     sigtimedwait() blocks on signals only and means non-sockets
     cannot be serviced.

   Theory of operation:
    This libevent module uses rtsig to allow us to manage a set of
    poll-event descriptors.  We can drop uninteresting fd's from the
    pollset if the fd will send a signal when it becomes interesting
    again.

    poll() offers us level-triggering and, when we have verified the
    level of a socket, we can trust the edge-trigger nature of the
    ASYNC signal.

    As an eventloop we must poll for external events but leverage
    kernel functionality to sleep between events ( until the loop's
    next scheduled timed event ).

    If we are polling on any non-sockets then we simply have no choice
    about blocking on the poll() call.  If we blocked on the
    sigtimedwait() call as rtsig papers recommend we will not wake on
    non-socket state transitions.  As part of libevent, this module
    must support non-socket polling.

    Many applications, however, do not need to poll on non-sockets and
    so this module should be able to optimize this case by using
    sigtimedwait().  For this reason this module can actually trigger
    events in each of three different ways:
      - poll() returning ready events from descriptors in the pollset

      - real-time signals dequeued via sigtimedwait()

      - real-time signals that call an installed signal handler which in
    turn writes the contents of siginfo to one end of a socketpair
    DGRAM socket.  The other end of the socket is always in the
    pollset so poll will be guaranteed to return even if the signal is
    received before entering poll().

    non-socket descriptors force us to block on the poll() for the
    duration of a dispatch.  In this case we unblock (w/ sigprocmask)
    the managed signals just before polling.  Each managed signal is
    handled by signal_handler() which send()'s the contents of siginfo
    over the socketpair.  Otherwise, we call poll() with a timeout of
    0ms so it checks the levels of the fd's in the pollset and returns
    immediately.  Any fd that is a socket and has no active state is
    removed from the pollset for the next pass -- we will rely on
    getting a signal for events on these fd's.

    The receiving end of the siginfo socketpair is in the pollset
    (permanently) so if we are polling on non-sockets, the delivery of
    signals immediately following sigprocmask( SIG_UNBLOCK...) will
    result in a readable op->signal_recv_fd which ensures the poll()
    will return immediately.  If the poll() call is blocking and a
    signal arrives ( possibly a real-time signal from a socket not in
    the pollset ) its handler will write the data to the socketpair
    and interrupt the poll().

    After every poll call we attempt a non-blocking recv from the
    signal_recv_fd and continue to recv and dispatch the events until
    recv indicates the socket buffer is empty.

    One might raise concerns about receiving event activations from
    both poll() and from the rtsig data in the signal_recv_fd.
    Fortunately, libevent is already structured for event coalescing,
    so this issue is mitigated ( though we do some work twice for the
    same event making us less efficient ).  I suspect that the cost of
    turning off the O_ASYNC flag on fd's in the pollset is more
    expensive than handling some events twice.  Looking at the
    kernel's source code for setting O_ASYNC, it looks like it takes a
    global kernel lock...

    After a poll and recv-loop for the signal_recv_fd, we finally do a
    sigtimedwait().  sigtimedwait will only block if we haven't
    blocked in poll() and we have not enqueued events from either the
    poll or the recv-loop.  Because sigtimedwait blocks all signals
    that are not in the set of signals to be dequeued, we need to
    dequeue almost all signals and make sure we dispatch them
    correctly.  We dequeue any signal that is not blocked as well as
    all libevent-managed signals.  If we get a signal that is not
    managed by libevent we lookup the sigaction for the specific
    signal and call that function ourselves.

    Finally, I should mention that getting a SIGIO signal indicates
    that the rtsig buffer has overflowed and we have lost events.
    This forces us to add _every_ descriptor to the pollset to recover.

*/


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
#include <unistd.h>
#include <sys/socket.h>

#include "event.h"
#include "event-internal.h"
#include "log.h"
extern struct event_list signalqueue;

#include <linux/unistd.h>
#ifndef __NR_gettid
#define gettid() getpid()
#else

#if ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 3)))
_syscall0(pid_t,gettid)
#endif

#endif

#define EVLIST_NONSOCK   0x1000 /* event is for a non-socket file-descriptor */
#define EVLIST_DONTDEL   0x2000 /* event should always be in the pollset */
#define MAXBUFFERSIZE (1024 * 1024 * 2) /* max socketbuffer for signal-spair */
#define INIT_MAX 16     /* init/min # of fd positions in our pollset */

static int signal_send_fd[_NSIG]; /* the globalend of the signal socketpair */
static int trouble[_NSIG]; /* 1 when signal-handler cant send to signal_send_fd */

struct rtdata;
TAILQ_HEAD(rtdata_list, rtdata);

struct rtsigop {
	sigset_t sigs;        /* signal mask for all _managed_ signals */
	struct pollfd *poll;  /* poll structures */
	struct rtdata **ptodat;  /* map poll_position to rtdata */
	int cur;              /* cur # fd's in a poll set */
	int max;              /* max # fd's in a poll set, start at 16 and grow as needed */
	int total;            /* count of fd's we are watching now */
	int signo;            /* the signo we use for ASYNC fd notifications */
	int nonsock;          /* number of non-socket fd's we are watching */
	int highestfd;        /* highest fd accomodated by fdtodat */
	struct rtdata_list **fdtodat; /* map fd to rtdata ( and thus to event ) */
	int signal_recv_fd;   /* recv side of the signal_send_fd */
	int signal_send_fd;   /* recv side of the signal_send_fd */
	struct event sigfdev; /* our own event structure for the signal fd */
};

struct rtdata {
	/* rtdata holds rtsig-private state on each event */
	TAILQ_ENTRY (rtdata) next;
	struct event *ev;
	int poll_position;
};

void *rtsig_init(struct event_base *);
int rtsig_add(void *, struct event *);
int rtsig_del(void *, struct event *);
int rtsig_recalc(struct event_base *, void *, int);
int rtsig_dispatch(struct event_base *, void *, struct timeval *);

struct eventop rtsigops = {
	"rtsig",
	rtsig_init,
	rtsig_add,
	rtsig_del,
	rtsig_recalc,
	rtsig_dispatch
};

static void
signal_handler(int sig, siginfo_t *info, void *ctx)
{
	/*
	 * the signal handler for all libevent-managed signals only
	 * used if we need to do a blocking poll() call due to
	 * non-socket fd's in the pollset.
	 */
  
	siginfo_t *i = info;
	siginfo_t i_local;

	if (trouble[sig - 1]) {
		i_local.si_signo = SIGIO;
		i_local.si_errno = 0;
		i_local.si_code = 0;
		i = &i_local;
		trouble[sig - 1] = 0;
	}

	if (send(signal_send_fd[sig - 1], i, sizeof(*i),
		MSG_DONTWAIT|MSG_NOSIGNAL) == -1)
		trouble[sig - 1] = 1;
}

static void
donothing(int fd, short event, void *arg)
{
	/*
	 * callback for our signal_recv_fd event structure
	 * we don't want to act on these events, we just want to wake the poll()
	 */
};

static void
signotset(sigset_t *set)
{
	int i, l;
	l = sizeof(*set) / 4;
	for (i = 0; i < l; i++) {
		((unsigned *)set)[i] = ~((unsigned *)set)[i];
	}
}

/*  The next three functions manage our private data about each event struct */

static int
grow_fdset(struct rtsigop *op, int newhigh)
{
	/*
	 * grow the fd -> rtdata array because we have encountered a
	 * new fd too high to fit in the existing array
	 */

	struct rtdata_list **p;
	struct rtdata_list *datset;
	int i,x;
	int newcnt = (newhigh + 1) << 1;

	if (newhigh <= op->highestfd)
		return (0);

	p = op->fdtodat;
	p = realloc(op->fdtodat, sizeof(struct rtdata_list *) * newcnt);
	if (p == NULL)
		return (-1);
	op->fdtodat = p;

	datset = calloc(newcnt - (op->highestfd + 1),
	    sizeof(struct rtdata_list));
	if (datset == NULL)
		return (-1);

	for (i = op->highestfd + 1, x = 0; i < newcnt; i++, x++) {
		op->fdtodat[i] = &(datset[x]);
		TAILQ_INIT(op->fdtodat[i]);
	}

	op->highestfd = newcnt - 1;
	return (0);
}

static struct rtdata *
ev2dat(struct rtsigop *op, struct event *ev, int create)
{
	/*
	 * given an event struct, find the dat structure that
	 * corresponds to it if create is non-zero and the rtdata
	 * structure does not exist, create it return NULL if not
	 * found
	 */

	int found = 0;
	int fd = ev->ev_fd;
	struct rtdata *ret = NULL;

	if (op->highestfd < fd && create)
		if (grow_fdset(op, fd) == -1)
			return (NULL);
  
	TAILQ_FOREACH(ret, op->fdtodat[fd], next) {
		if (ret->ev == ev) {
			found = 1;
			break;
		}
	}

	if (!found) {
		if (!create)
			return (NULL);

		ret = calloc(1, sizeof(struct rtdata));
		if (ret == NULL)
			return (NULL);
		ret->ev = ev;
		ret->poll_position = -1;
		TAILQ_INSERT_TAIL(op->fdtodat[fd], ret, next);
	}

	return (ret);
}

static void
dat_del(struct rtsigop *op, struct rtdata *dat)
{
	/*
	 * delete our private notes about a given event struct
	 * called from rtsig_del() only
	 */
	int fd;
	if (dat == NULL)
		return;
	fd = dat->ev->ev_fd;

	TAILQ_REMOVE(op->fdtodat[fd], dat, next);
	memset(dat, 0, sizeof(*dat));
	free(dat);
}


static void
set_sigaction(int sig)
{
	/*
	 * set the standard handler for any libevent-managed signal,
	 * including the rtsig used for O_ASYNC notifications
	 */
	struct sigaction act;

	act.sa_flags = SA_RESTART | SA_SIGINFO;
	sigfillset(&(act.sa_mask));
	act.sa_sigaction = &signal_handler;
	sigaction(sig, &act, NULL);
}

static int
find_rt_signal()
{
	/* find an unused rtsignal */
	struct sigaction act;
	int sig = SIGRTMIN;

	while (sig <= SIGRTMAX) {
		if (sigaction(sig, NULL, &act) != 0) {
			if (errno == EINTR)
				continue;
		} else {
			if (act.sa_flags & SA_SIGINFO) {
				if (act.sa_sigaction == NULL)
					return (sig);
			} else {
				if (act.sa_handler == SIG_DFL)
					return (sig);
			}
		}
		sig++;
	}
	return (0);
}

/*
 * the next three functions manage our pollset and the memory management for 
 * fd -> rtdata -> event -> poll_position maps
 */

static int
poll_add(struct rtsigop *op, struct event *ev, struct rtdata *dat)
{
	struct pollfd *pfd;
	int newmax = op->max << 1;
	int pp;

	if (op->poll == NULL)
		return (0);

	if (dat == NULL)
		dat = ev2dat(op, ev, 0);

	if (dat == NULL)
		return (0);

	pp = dat->poll_position;

	if (pp != -1) {
		pfd = &op->poll[pp];
		if (ev->ev_events & EV_READ)
			pfd->events |= POLLIN;
    
		if (ev->ev_events & EV_WRITE)
			pfd->events |= POLLOUT;
    
		return (0);
	}

	if (op->cur == op->max) {
		void *p = realloc(op->poll, sizeof(*op->poll) * newmax);
		if (p == NULL) {
			errno = ENOMEM;
			return (-1);
		}
		op->poll = p;

		p = realloc(op->ptodat, sizeof(*op->ptodat) * newmax);
		if (p == NULL) {
			/* shrink the pollset back down */
			op->poll = realloc(op->poll,
			    sizeof(*op->poll) * op->max);
			errno = ENOMEM;
			return (-1);
		}
		op->ptodat = p;
		op->max = newmax;
	}

	pfd = &op->poll[op->cur];
	pfd->fd = ev->ev_fd;
	pfd->revents = 0;
	pfd->events = 0;

	if (ev->ev_events & EV_READ)
		pfd->events |= POLLIN;
  
	if (ev->ev_events & EV_WRITE)
		pfd->events |= POLLOUT;
  
	op->ptodat[op->cur] = dat;
	dat->poll_position = op->cur;
	op->cur++;

	return (0);
}

static void
poll_free(struct rtsigop *op, int n)
{
  if (op->poll == NULL)
	  return;

  op->cur--;

  if (n < op->cur) {
    memcpy(&op->poll[n], &op->poll[op->cur], sizeof(*op->poll));
    op->ptodat[n] = op->ptodat[op->cur];
    op->ptodat[n]->poll_position = n;
  }


  /* less then half the max in use causes us to shrink */
  if (op->max > INIT_MAX && op->cur < op->max >> 1) {
    op->max >>= 1;
    op->poll = realloc(op->poll, sizeof(*op->poll) * op->max);
    op->ptodat = realloc(op->ptodat, sizeof(*op->ptodat) * op->max);
  }
}

static void
poll_remove(struct rtsigop *op, struct event *ev, struct rtdata *dat)
{
  int pp;
  if (dat == NULL)
    dat = ev2dat(op, ev, 0);

  if (dat == NULL) return;

  pp = dat->poll_position;
  if (pp != -1) {
    poll_free(op, pp);
    dat->poll_position = -1;
  }
}

static void
activate(struct event *ev, int flags)
{
	/* activate an event, possibly removing one-shot events */
	if (!(ev->ev_events & EV_PERSIST))
		event_del(ev);
	event_active(ev, flags, 1);
}

#define FD_CLOSEONEXEC(x) do { \
        if (fcntl(x, F_SETFD, 1) == -1) \
                event_warn("fcntl(%d, F_SETFD)", x); \
} while (0)

void *
rtsig_init(struct event_base *)
{
	struct rtsigop *op;
	int sockets[2];
	int optarg;
	struct rtdata *dat;
	int flags;

	if (getenv("EVENT_NORTSIG"))
		goto err;

	op = calloc(1, sizeof(*op));
	if (op == NULL)
		goto err;

	op->max = INIT_MAX;
	op->poll = malloc(sizeof(*op->poll) * op->max);
	if (op->poll == NULL) 
		goto err_free_op;

	op->signo = find_rt_signal();
	if (op->signo == 0)
		goto err_free_poll;
  
	op->nonsock = 0;

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, sockets) != 0)
		goto err_free_poll;

	FD_CLOSEONEXEC(sockets[0]);
	FD_CLOSEONEXEC(sockets[1]);

	signal_send_fd[op->signo - 1] = sockets[0];
	trouble[op->signo - 1] = 0;
	op->signal_send_fd = sockets[0];
	op->signal_recv_fd = sockets[1];
	flags = fcntl(op->signal_recv_fd, F_GETFL);
	fcntl(op->signal_recv_fd, F_SETFL, flags | O_NONBLOCK);

	optarg = MAXBUFFERSIZE;
	setsockopt(signal_send_fd[op->signo - 1],
	    SOL_SOCKET, SO_SNDBUF, 
	    &optarg, sizeof(optarg));
  
	optarg = MAXBUFFERSIZE;
	setsockopt(op->signal_recv_fd,
	    SOL_SOCKET, SO_RCVBUF,
	    &optarg, sizeof(optarg));

	op->highestfd = -1;
	op->fdtodat = NULL;
	if (grow_fdset(op, 1) == -1)
		goto err_close_pair;

	op->ptodat = malloc(sizeof(*op->ptodat) * op->max);
	if (op->ptodat == NULL)
		goto err_close_pair;

	sigemptyset(&op->sigs);
	sigaddset(&op->sigs, SIGIO);
	sigaddset(&op->sigs, op->signo);
	sigprocmask(SIG_BLOCK, &op->sigs, NULL);
	set_sigaction(SIGIO);
	set_sigaction(op->signo);

	event_set(&(op->sigfdev), op->signal_recv_fd, EV_READ|EV_PERSIST,
	    donothing, NULL);
	op->sigfdev.ev_flags |= EVLIST_DONTDEL;
	dat = ev2dat(op, &(op->sigfdev), 1);
	poll_add(op, &(op->sigfdev), dat);

	return (op);

 err_close_pair:
	close(op->signal_recv_fd);
	close(signal_send_fd[op->signo - 1]);

 err_free_poll:
	free(op->poll);
 
 err_free_op:
	free(op);
 err:
	return (NULL);
}

int
rtsig_add(void *arg, struct event *ev)
{
	struct rtsigop *op = (struct rtsigop *) arg;
	int flags, i;
	struct stat statbuf;
	struct rtdata *dat;

	if (ev->ev_events & EV_SIGNAL) {
		int signo = EVENT_SIGNAL(ev);
  
		sigaddset(&op->sigs, EVENT_SIGNAL(ev));
		if (sigprocmask(SIG_BLOCK, &op->sigs, NULL) == -1)
			return (-1);
    
		set_sigaction(signo);
    
		signal_send_fd[signo - 1] = op->signal_send_fd;
		trouble[signo - 1] = 0;

		return (0);
	}

	if (!(ev->ev_events & (EV_READ|EV_WRITE))) 
		return (0);

	if (-1 == fstat(ev->ev_fd, &statbuf))
		return (-1);

	if (!S_ISSOCK(statbuf.st_mode))
		ev->ev_flags |= EVLIST_NONSOCK;

	flags = fcntl(ev->ev_fd, F_GETFL);
	if (flags == -1)
		return (-1);

	if (!(flags & O_ASYNC)) {
		if (fcntl(ev->ev_fd, F_SETSIG, op->signo) == -1 ||
		    fcntl(ev->ev_fd, F_SETOWN, (int) gettid()) == -1)
			return (-1);
    
		/*
		 * the overhead of always handling writeable edges
		 * isn't going to be that bad...
		 */
		if (fcntl(ev->ev_fd, F_SETFL, flags | O_ASYNC|O_RDWR)) 
			return (-1);
	}

#ifdef O_ONESIGFD
	/*
	 * F_SETAUXFL and O_ONESIGFD are defined in a non-standard
	 * linux kernel patch to coalesce events for fds
	 */
	fcntl(ev->ev_fd, F_SETAUXFL, O_ONESIGFD);
#endif

	dat = ev2dat(op, ev, 1);
	if (dat == NULL)
		return (-1);

	op->total++;
	if (ev->ev_flags & EVLIST_NONSOCK)
		op->nonsock++;

	if (poll_add(op, ev, dat) == -1) {
		/* must check the level of new fd's */
		i = errno;
		fcntl(ev->ev_fd, F_SETFL, flags);
		errno = i;
		return (-1);
	}

	return (0);
}

int
rtsig_del(void *arg, struct event *ev)
{
	struct rtdata *dat;
	struct rtsigop *op = (struct rtsigop *) arg;

	if (ev->ev_events & EV_SIGNAL) {
		sigset_t sigs;

		sigdelset(&op->sigs, EVENT_SIGNAL(ev));
    
		sigemptyset(&sigs);
		sigaddset(&sigs, EVENT_SIGNAL(ev));
		return (sigprocmask(SIG_UNBLOCK, &sigs, NULL));
	}

	if (!(ev->ev_events & (EV_READ|EV_WRITE)))
		return (0);

	dat = ev2dat(op, ev, 0);
	poll_remove(op, ev, dat);
	dat_del(op, dat);
	op->total--;
	if (ev->ev_flags & EVLIST_NONSOCK)
		op->nonsock--;

	return (0);
}

int
rtsig_recalc(struct event_base *base, void *arg, int max)
{
	return (0);
}

/*
 * the following do_X functions implement the different stages of a single
 * eventloop pass: poll(), recv(sigsock), sigtimedwait()
 *
 * do_siginfo_dispatch() is a common factor to both do_sigwait() and
 * do_signals_from_socket().
 */

static inline int
do_poll(struct rtsigop *op, struct timespec *ts, struct timespec **ts_p)
{
	int res = 0;
	int i = 0;
  
	if (op->cur > 1) {
		/* non-empty poll set (modulo the signalfd) */
		if (op->nonsock) {
			int timeout = -1;
			
			if (*ts_p != NULL)
				timeout = (*ts_p)->tv_nsec / 1000000
					  + (*ts_p)->tv_sec * 1000;
			
			sigprocmask(SIG_UNBLOCK, &(op->sigs), NULL);

			res = poll(op->poll, op->cur, timeout);
			
			sigprocmask(SIG_BLOCK, &(op->sigs), NULL);
			
			ts->tv_sec = 0;
			ts->tv_nsec = 0;
			*ts_p = ts;
		} else {
			res = poll(op->poll, op->cur, 0);
		}

		if (res < 0) {
			return (errno == EINTR ? 0 : -1);
		} else if (res) {
			ts->tv_sec = 0;
			ts->tv_nsec = 0;
			*ts_p = ts;
		}

		i = 0;
		while (i < op->cur) {
			struct rtdata *dat = op->ptodat[i];
			struct event *ev = dat->ev;

			if (op->poll[i].revents) {
				int flags = 0;
	
				if (op->poll[i].revents & (POLLIN | POLLERR))
					flags |= EV_READ;
	
				if (op->poll[i].revents & POLLOUT)
					flags |= EV_WRITE;
	
				if (!(ev->ev_events & EV_PERSIST)) {
					poll_remove(op, ev, op->ptodat[i]);
					event_del(ev);
				} else {
					i++;
				}
	
				event_active(ev, flags, 1);
			} else {
				if (ev->ev_flags & (EVLIST_NONSOCK|EVLIST_DONTDEL)) {
					i++;
				} else {
					poll_remove(op, ev, op->ptodat[i]);
				}
			}
		}
	}
	return (res);
}

static inline int
do_siginfo_dispatch(struct event_base *base, struct rtsigop *op,
    siginfo_t *info)
{
	int signum;
	struct rtdata *dat, *next_dat;
	struct event *ev, *next_ev;

	if (info == NULL)
		return (-1);

	signum = info->si_signo;
	if (signum == op->signo) {
		int flags, sigok = 0;
		flags = 0;

		if (info->si_band & (POLLIN|POLLERR))
			flags |= EV_READ;
		if (info->si_band & POLLOUT)
			flags |= EV_WRITE;

		if (!flags)
			return (0);

		if (info->si_fd > op->highestfd)
			return (-1);

		dat = TAILQ_FIRST(op->fdtodat[info->si_fd]);
		while (dat != TAILQ_END(op->fdtodat[info->si_fd])) {
			next_dat = TAILQ_NEXT(dat, next);
			if (flags & dat->ev->ev_events) {
				ev = dat->ev;
				poll_add(op, ev, dat);
				activate(ev, flags & ev->ev_events);
				sigok = 1;
			}
			dat = next_dat;
		}
	} else if (signum == SIGIO) {
		TAILQ_FOREACH(ev, &base->eventqueue, ev_next) {
			if (ev->ev_events & (EV_READ|EV_WRITE))
				poll_add(op, ev, NULL);
		}
		return (1); /* 1 means the caller should poll() again */
    
	} else if (sigismember(&op->sigs, signum)) {
		/* managed signals are queued */
		ev = TAILQ_FIRST(&signalqueue);
		while (ev != TAILQ_END(&signalqueue)) {
			next_ev = TAILQ_NEXT(ev, ev_signal_next);
			if (EVENT_SIGNAL(ev) == signum)
				activate(ev, EV_SIGNAL);
			ev = next_ev;
		}
	} else {
		/* dispatch unmanaged signals immediately */
		struct sigaction sa;
		if (sigaction(signum, NULL, &sa) == 0) {
			if ((sa.sa_flags & SA_SIGINFO) && sa.sa_sigaction) {
				(*sa.sa_sigaction)(signum, info, NULL);
			} else if (sa.sa_handler) {
				if ((int)sa.sa_handler != 1)
					(*sa.sa_handler)(signum);
			} else {
				if (signum != SIGCHLD) {
					/* non-blocked SIG_DFL */
					kill(gettid(), signum);
				}
			}
		}
	}

	return (0);
}

/*
 * return 1 if we should poll again
 * return 0 if we are all set
 * return -1 on error
 */
static inline int
do_sigwait(struct event_base *base, struct rtsigop *op,
    struct timespec *ts, struct timespec **ts_p, sigset_t *sigs)
{
	for (;;) {
		siginfo_t info;
		int signum;

		signum = sigtimedwait(sigs, &info, *ts_p);

		ts->tv_sec = 0;
		ts->tv_nsec = 0;
		*ts_p = ts;

		if (signum == -1) {
			if (errno == EAGAIN || errno == EINTR)
				return (0);
      			return (-1);
		} else if (1 == do_siginfo_dispatch(base, op, &info)) {
			return (1);
		}
	}

	/* NOTREACHED */
}

static inline int
do_signals_from_socket(struct event_base *base, struct rtsigop *op,
    struct timespec *ts, struct timespec **ts_p)
{
	int fd = op->signal_recv_fd;
	siginfo_t info;
	int res;

	for (;;) {
		res = recv(fd, &info, sizeof(info), MSG_NOSIGNAL);
		if (res == -1) {
			if (errno == EAGAIN)
				return (0);
			if (errno == EINTR)
				continue;
			return (-1);
		} else {
			ts->tv_sec = 0;
			ts->tv_nsec = 0;
			*ts_p = ts;
			if (1 == do_siginfo_dispatch(base, op, &info))
				return (1);
		}
	}
	/* NOTREACHED */
}

int
rtsig_dispatch(struct event_base *base, void *arg, struct timeval *tv)
{
	struct rtsigop *op = (struct rtsigop *) arg;
	struct timespec ts, *ts_p = NULL;
	int res;
	sigset_t sigs;

	if (tv != NULL) {
		ts.tv_sec = tv->tv_sec;
		ts.tv_nsec = tv->tv_usec * 1000;
		*ts_p = ts;
	}

 poll_for_level:
	/* ts and ts_p can be modified in do_XXX() */
	res = do_poll(op, &ts, &ts_p);

	res = do_signals_from_socket(base, op, &ts, &ts_p);
	if (res == 1)
		goto poll_for_level;
	else if (res == -1)
		return (-1);

	/*
	 * the mask = managed_signals | unblocked-signals
	 * MM - if this is not blocking do we need to cast the net this wide?
	 */
	sigemptyset(&sigs);
	sigprocmask(SIG_BLOCK, &sigs, &sigs);
	signotset(&sigs);
	sigorset(&sigs, &sigs, &op->sigs);

	res = do_sigwait(base, op, &ts, &ts_p, &sigs);

	if (res == 1)
		goto poll_for_level;
	else if (res == -1)
		return (-1);

	return (0);
}

