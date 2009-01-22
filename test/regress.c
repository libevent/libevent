/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/event_compat.h"
#include "event2/tag.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/util.h"
#include "event-internal.h"
#include "evbuffer-internal.h"
#include "log-internal.h"

#include "regress.h"

#ifndef WIN32
#include "regress.gen.h"
#endif

int pair[2];
int test_ok;
static int called;
static char wbuf[4096];
static char rbuf[4096];
static int woff;
static int roff;
static int usepersist;
static struct timeval tset;
static struct timeval tcalled;
static struct event_base *global_base;

#define TEST1	"this is a test"
#define SECONDS	1

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#ifdef WIN32
#define write(fd,buf,len) send((fd),(buf),(len),0)
#define read(fd,buf,len) recv((fd),(buf),(len),0)
#endif

static void
simple_read_cb(int fd, short event, void *arg)
{
	char buf[256];
	int len;

	len = read(fd, buf, sizeof(buf));

	if (len) {
		if (!called) {
			if (event_add(arg, NULL) == -1)
				exit(1);
		}
	} else if (called == 1)
		test_ok = 1;

	called++;
}

static void
simple_write_cb(int fd, short event, void *arg)
{
	int len;

	len = write(fd, TEST1, strlen(TEST1) + 1);
	if (len == -1)
		test_ok = 0;
	else
		test_ok = 1;
}

static void
multiple_write_cb(int fd, short event, void *arg)
{
	struct event *ev = arg;
	int len;

	len = 128;
	if (woff + len >= sizeof(wbuf))
		len = sizeof(wbuf) - woff;

	len = write(fd, wbuf + woff, len);
	if (len == -1) {
		fprintf(stderr, "%s: write\n", __func__);
		if (usepersist)
			event_del(ev);
		return;
	}

	woff += len;

	if (woff >= sizeof(wbuf)) {
		shutdown(fd, SHUT_WR);
		if (usepersist)
			event_del(ev);
		return;
	}

	if (!usepersist) {
		if (event_add(ev, NULL) == -1)
			exit(1);
	}
}

static void
multiple_read_cb(int fd, short event, void *arg)
{
	struct event *ev = arg;
	int len;

	len = read(fd, rbuf + roff, sizeof(rbuf) - roff);
	if (len == -1)
		fprintf(stderr, "%s: read\n", __func__);
	if (len <= 0) {
		if (usepersist)
			event_del(ev);
		return;
	}

	roff += len;
	if (!usepersist) {
		if (event_add(ev, NULL) == -1) 
			exit(1);
	}
}

static void
timeout_cb(int fd, short event, void *arg)
{
	struct timeval tv;
	int diff;

	evutil_gettimeofday(&tcalled, NULL);
	if (evutil_timercmp(&tcalled, &tset, >))
		evutil_timersub(&tcalled, &tset, &tv);
	else
		evutil_timersub(&tset, &tcalled, &tv);

	diff = tv.tv_sec*1000 + tv.tv_usec/1000 - SECONDS * 1000;
	if (diff < 0)
		diff = -diff;

	if (diff < 100)
		test_ok = 1;
}

struct both {
	struct event ev;
	int nread;
};

static void
combined_read_cb(int fd, short event, void *arg)
{
	struct both *both = arg;
	char buf[128];
	int len;

	len = read(fd, buf, sizeof(buf));
	if (len == -1)
		fprintf(stderr, "%s: read\n", __func__);
	if (len <= 0)
		return;

	both->nread += len;
	if (event_add(&both->ev, NULL) == -1)
		exit(1);
}

static void
combined_write_cb(int fd, short event, void *arg)
{
	struct both *both = arg;
	char buf[128];
	int len;

	len = sizeof(buf);
	if (len > both->nread)
		len = both->nread;

	len = write(fd, buf, len);
	if (len == -1)
		fprintf(stderr, "%s: write\n", __func__);
	if (len <= 0) {
		shutdown(fd, SHUT_WR);
		return;
	}

	both->nread -= len;
	if (event_add(&both->ev, NULL) == -1)
		exit(1);
}

/* Test infrastructure */

static int
setup_test(const char *name)
{

	fprintf(stdout, "%s", name);

	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		fprintf(stderr, "%s: socketpair\n", __func__);
		exit(1);
	}

        if (evutil_make_socket_nonblocking(pair[0]) == -1)
		fprintf(stderr, "fcntl(O_NONBLOCK)");

        if (evutil_make_socket_nonblocking(pair[1]) == -1)
		fprintf(stderr, "fcntl(O_NONBLOCK)");

	test_ok = 0;
	called = 0;
	return (0);
}

static int
cleanup_test(void)
{
#ifndef WIN32
	close(pair[0]);
	close(pair[1]);
#else
	CloseHandle((HANDLE)pair[0]);
	CloseHandle((HANDLE)pair[1]);
#endif
	if (test_ok)
		fprintf(stdout, "OK\n");
	else {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}
        test_ok = 0;
	return (0);
}

static void
test_simpleread(void)
{
	struct event ev;

	/* Very simple read test */
	setup_test("Simple read: ");
	
	write(pair[0], TEST1, strlen(TEST1)+1);
	shutdown(pair[0], SHUT_WR);

	event_set(&ev, pair[1], EV_READ, simple_read_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);
	event_dispatch();

	cleanup_test();
}

static void
test_simplewrite(void)
{
	struct event ev;

	/* Very simple write test */
	setup_test("Simple write: ");
	
	event_set(&ev, pair[0], EV_WRITE, simple_write_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);
	event_dispatch();

	cleanup_test();
}

static void
simpleread_multiple_cb(int fd, short event, void *arg)
{
	if (++called == 2)
		test_ok = 1;
}

static void
test_simpleread_multiple(void)
{
	struct event one, two;

	/* Very simple read test */
	setup_test("Simple read to multiple evens: ");
	
	write(pair[0], TEST1, strlen(TEST1)+1);
	shutdown(pair[0], SHUT_WR);

	event_set(&one, pair[1], EV_READ, simpleread_multiple_cb, NULL);
	if (event_add(&one, NULL) == -1)
		exit(1);
	event_set(&two, pair[1], EV_READ, simpleread_multiple_cb, NULL);
	if (event_add(&two, NULL) == -1)
		exit(1);
	event_dispatch();

	cleanup_test();
}

static void
test_multiple(void)
{
	struct event ev, ev2;
	int i;

	/* Multiple read and write test */
	setup_test("Multiple read/write: ");
	memset(rbuf, 0, sizeof(rbuf));
	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = i;

	roff = woff = 0;
	usepersist = 0;

	event_set(&ev, pair[0], EV_WRITE, multiple_write_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);
	event_set(&ev2, pair[1], EV_READ, multiple_read_cb, &ev2);
	if (event_add(&ev2, NULL) == -1)
		exit(1);
	event_dispatch();

	if (roff == woff)
		test_ok = memcmp(rbuf, wbuf, sizeof(wbuf)) == 0;

	cleanup_test();
}

static void
test_persistent(void)
{
	struct event ev, ev2;
	int i;

	/* Multiple read and write test with persist */
	setup_test("Persist read/write: ");
	memset(rbuf, 0, sizeof(rbuf));
	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = i;

	roff = woff = 0;
	usepersist = 1;

	event_set(&ev, pair[0], EV_WRITE|EV_PERSIST, multiple_write_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);
	event_set(&ev2, pair[1], EV_READ|EV_PERSIST, multiple_read_cb, &ev2);
	if (event_add(&ev2, NULL) == -1)
		exit(1);
	event_dispatch();

	if (roff == woff)
		test_ok = memcmp(rbuf, wbuf, sizeof(wbuf)) == 0;

	cleanup_test();
}

static void
test_combined(void)
{
	struct both r1, r2, w1, w2;

	setup_test("Combined read/write: ");
	memset(&r1, 0, sizeof(r1));
	memset(&r2, 0, sizeof(r2));
	memset(&w1, 0, sizeof(w1));
	memset(&w2, 0, sizeof(w2));

	w1.nread = 4096;
	w2.nread = 8192;

	event_set(&r1.ev, pair[0], EV_READ, combined_read_cb, &r1);
	event_set(&w1.ev, pair[0], EV_WRITE, combined_write_cb, &w1);
	event_set(&r2.ev, pair[1], EV_READ, combined_read_cb, &r2);
	event_set(&w2.ev, pair[1], EV_WRITE, combined_write_cb, &w2);
	if (event_add(&r1.ev, NULL) == -1)
		exit(1);
	if (event_add(&w1.ev, NULL))
		exit(1);
	if (event_add(&r2.ev, NULL))
		exit(1);
	if (event_add(&w2.ev, NULL))
		exit(1);

	event_dispatch();

	if (r1.nread == 8192 && r2.nread == 4096)
		test_ok = 1;

	cleanup_test();
}

static void
test_simpletimeout(void)
{
	struct timeval tv;
	struct event ev;

	setup_test("Simple timeout: ");

	tv.tv_usec = 0;
	tv.tv_sec = SECONDS;
	evtimer_set(&ev, timeout_cb, NULL);
	evtimer_add(&ev, &tv);

	evutil_gettimeofday(&tset, NULL);
	event_dispatch();

	cleanup_test();
}

static void
periodic_timeout_cb(int fd, short event, void *arg)
{
	int *count = arg;

	(*count)++;
	if (*count > 5) {
		test_ok = 1;
		event_base_loopexit(global_base, NULL);
	}
}

static void
test_periodictimeout(void)
{
	struct timeval tv, tv_interval;
	struct event ev;
	int count = 0;

	setup_test("Periodic timeout: ");

	timerclear(&tv_interval);
	tv_interval.tv_usec = 10000;

	tv.tv_usec = 0;
	tv.tv_sec = 0;
	evperiodic_assign(&ev, global_base, &tv_interval,
	    periodic_timeout_cb, &count);
	event_add(&ev, &tv);

	event_dispatch();

	event_del(&ev);

	cleanup_test();
}

static void
test_persistent_timeout(void)
{
	struct timeval tv;
	struct event ev;
	int count = 0;

	setup_test("Periodic timeout via EV_PERSIST: ");

	timerclear(&tv);
	tv.tv_usec = 10000;

	event_assign(&ev, global_base, -1, EV_TIMEOUT|EV_PERSIST,
	    periodic_timeout_cb, &count);
	event_add(&ev, &tv);

	event_dispatch();

	event_del(&ev);

	cleanup_test();
}

#ifndef WIN32
static void signal_cb(int fd, short event, void *arg);

extern struct event_base *current_base;

static void
child_signal_cb(int fd, short event, void *arg)
{
	struct timeval tv;
	int *pint = arg;

	*pint = 1;

	tv.tv_usec = 500000;
	tv.tv_sec = 0;
	event_loopexit(&tv);
}

static void
test_fork(void)
{
	int status, got_sigchld = 0;
	struct event ev, sig_ev;
	pid_t pid;

	setup_test("After fork: ");

	write(pair[0], TEST1, strlen(TEST1)+1);

	event_set(&ev, pair[1], EV_READ, simple_read_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);

	evsignal_set(&sig_ev, SIGCHLD, child_signal_cb, &got_sigchld);
	evsignal_add(&sig_ev, NULL);

	if ((pid = fork()) == 0) {
		/* in the child */
		if (event_reinit(current_base) == -1) {
			fprintf(stdout, "FAILED (reinit)\n");
			exit(1);
		}

		evsignal_del(&sig_ev);

		called = 0;

		event_dispatch();

		event_base_free(current_base);

		/* we do not send an EOF; simple_read_cb requires an EOF 
		 * to set test_ok.  we just verify that the callback was
		 * called. */
		exit(test_ok != 0 || called != 2 ? -2 : 76);
	}

	/* wait for the child to read the data */
	sleep(1);

	write(pair[0], TEST1, strlen(TEST1)+1);

	if (waitpid(pid, &status, 0) == -1) {
		fprintf(stdout, "FAILED (fork)\n");
		exit(1);
	}
	
	if (WEXITSTATUS(status) != 76) {
		fprintf(stdout, "FAILED (exit): %d\n", WEXITSTATUS(status));
		exit(1);
	}

	/* test that the current event loop still works */
	write(pair[0], TEST1, strlen(TEST1)+1);
	shutdown(pair[0], SHUT_WR);

	event_dispatch();

	if (!got_sigchld) {
		fprintf(stdout, "FAILED (sigchld)\n");
		exit(1);
	}

	evsignal_del(&sig_ev);

	cleanup_test();
}

static void
signal_cb_sa(int sig)
{
	test_ok = 2;
}

static void
signal_cb(int fd, short event, void *arg)
{
	struct event *ev = arg;

	evsignal_del(ev);
	test_ok = 1;
}

static void
test_simplesignal(void)
{
	struct event ev;
	struct itimerval itv;

	setup_test("Simple signal: ");
	evsignal_set(&ev, SIGALRM, signal_cb, &ev);
	evsignal_add(&ev, NULL);
	/* find bugs in which operations are re-ordered */
	evsignal_del(&ev);
	evsignal_add(&ev, NULL);

	memset(&itv, 0, sizeof(itv));
	itv.it_value.tv_sec = 1;
	if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		goto skip_simplesignal;

	event_dispatch();
 skip_simplesignal:
	if (evsignal_del(&ev) == -1)
		test_ok = 0;

	cleanup_test();
}

static void
test_multiplesignal(void)
{
	struct event ev_one, ev_two;
	struct itimerval itv;

	setup_test("Multiple signal: ");

	evsignal_set(&ev_one, SIGALRM, signal_cb, &ev_one);
	evsignal_add(&ev_one, NULL);

	evsignal_set(&ev_two, SIGALRM, signal_cb, &ev_two);
	evsignal_add(&ev_two, NULL);

	memset(&itv, 0, sizeof(itv));
	itv.it_value.tv_sec = 1;
	if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		goto skip_simplesignal;

	event_dispatch();

 skip_simplesignal:
	if (evsignal_del(&ev_one) == -1)
		test_ok = 0;
	if (evsignal_del(&ev_two) == -1)
		test_ok = 0;

	cleanup_test();
}

static void
test_immediatesignal(void)
{
	struct event ev;

	test_ok = 0;
	printf("Immediate signal: ");
	evsignal_set(&ev, SIGUSR1, signal_cb, &ev);
	evsignal_add(&ev, NULL);
	raise(SIGUSR1);
	event_loop(EVLOOP_NONBLOCK);
	evsignal_del(&ev);
	cleanup_test();
}

static void
test_signal_dealloc(void)
{
	/* make sure that evsignal_event is event_del'ed and pipe closed */
	struct event ev;
	struct event_base *base = event_init();
	printf("Signal dealloc: ");
	evsignal_set(&ev, SIGUSR1, signal_cb, &ev);
	evsignal_add(&ev, NULL);
	evsignal_del(&ev);
	event_base_free(base);
        /* If we got here without asserting, we're fine. */
        test_ok = 1;
	cleanup_test();
}

static void
test_signal_pipeloss(void)
{
	/* make sure that the base1 pipe is closed correctly. */
	struct event_base *base1, *base2;
	int pipe1;
	test_ok = 0;
	printf("Signal pipeloss: ");
	base1 = event_init();
	pipe1 = base1->sig.ev_signal_pair[0];
	base2 = event_init();
	event_base_free(base2);
	event_base_free(base1);
	if (close(pipe1) != -1 || errno!=EBADF) {
		/* fd must be closed, so second close gives -1, EBADF */
		printf("signal pipe not closed. ");
		test_ok = 0;
	} else {
		test_ok = 1;
	}
	cleanup_test();
}

/*
 * make two bases to catch signals, use both of them.  this only works
 * for event mechanisms that use our signal pipe trick.  kqueue handles
 * signals internally, and all interested kqueues get all the signals.
 */
static void
test_signal_switchbase(void)
{
	struct event ev1, ev2;
	struct event_base *base1, *base2;
        int is_kqueue;
	test_ok = 0;
	printf("Signal switchbase: ");
	base1 = event_init();
	base2 = event_init();
        is_kqueue = !strcmp(event_get_method(),"kqueue");
	evsignal_set(&ev1, SIGUSR1, signal_cb, &ev1);
	evsignal_set(&ev2, SIGUSR1, signal_cb, &ev2);
	if (event_base_set(base1, &ev1) ||
	    event_base_set(base2, &ev2) ||
	    event_add(&ev1, NULL) ||
	    event_add(&ev2, NULL)) {
		fprintf(stderr, "%s: cannot set base, add\n", __func__);
		exit(1);
	}

	test_ok = 0;
	/* can handle signal before loop is called */
	raise(SIGUSR1);
	event_base_loop(base2, EVLOOP_NONBLOCK);
        if (is_kqueue) {
                if (!test_ok)
                        goto done;
                test_ok = 0;
        }
	event_base_loop(base1, EVLOOP_NONBLOCK);
	if (test_ok && !is_kqueue) {
		test_ok = 0;

		/* set base1 to handle signals */
		event_base_loop(base1, EVLOOP_NONBLOCK);
		raise(SIGUSR1);
		event_base_loop(base1, EVLOOP_NONBLOCK);
		event_base_loop(base2, EVLOOP_NONBLOCK);
	}
 done:
	event_base_free(base1);
	event_base_free(base2);
	cleanup_test();
}

/*
 * assert that a signal event removed from the event queue really is
 * removed - with no possibility of it's parent handler being fired.
 */
static void
test_signal_assert(void)
{
	struct event ev;
	struct event_base *base = event_init();
	test_ok = 0;
	printf("Signal handler assert: ");
	/* use SIGCONT so we don't kill ourselves when we signal to nowhere */
	evsignal_set(&ev, SIGCONT, signal_cb, &ev);
	evsignal_add(&ev, NULL);
	/*
	 * if evsignal_del() fails to reset the handler, it's current handler
	 * will still point to evsig_handler().
	 */
	evsignal_del(&ev);

	raise(SIGCONT);
	/* only way to verify we were in evsig_handler() */
	if (base->sig.evsig_caught)
		test_ok = 0;
	else
		test_ok = 1;

	event_base_free(base);
	cleanup_test();
	return;
}

/*
 * assert that we restore our previous signal handler properly.
 */
static void
test_signal_restore(void)
{
	struct event ev;
	struct event_base *base = event_init();
#ifdef HAVE_SIGACTION
	struct sigaction sa;
#endif

	test_ok = 0;
	printf("Signal handler restore: ");
#ifdef HAVE_SIGACTION
	sa.sa_handler = signal_cb_sa;
	sa.sa_flags = 0x0;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL) == -1)
		goto out;
#else
	if (signal(SIGUSR1, signal_cb_sa) == SIG_ERR)
		goto out;
#endif
	evsignal_set(&ev, SIGUSR1, signal_cb, &ev);
	evsignal_add(&ev, NULL);
	evsignal_del(&ev);

	raise(SIGUSR1);
	/* 1 == signal_cb, 2 == signal_cb_sa, we want our previous handler */
	if (test_ok != 2)
		test_ok = 0;
out:
	event_base_free(base);
	cleanup_test();
	return;
}
#endif

static void
test_free_active_base(void)
{
	struct event_base *base1;
	struct event ev1;
	setup_test("Free active base: ");
	base1 = event_init();
	event_set(&ev1, pair[1], EV_READ, simple_read_cb, &ev1);
	event_base_set(base1, &ev1);
	event_add(&ev1, NULL);
	/* event_del(&ev1); */
	event_base_free(base1);
	test_ok = 1;
	cleanup_test();
	event_base_free(global_base);
	global_base = event_init();
}

static void
test_event_base_new(void)
{
	struct event_base *base;
	struct event ev1;
	setup_test("Event base new: ");

	write(pair[0], TEST1, strlen(TEST1)+1);
	shutdown(pair[0], SHUT_WR);

	base = event_base_new();
	event_set(&ev1, pair[1], EV_READ, simple_read_cb, &ev1);
	event_base_set(base, &ev1);
	event_add(&ev1, NULL);

	event_base_dispatch(base);

	event_base_free(base);
	test_ok = 1;
	cleanup_test();
}

static void
test_loopexit(void)
{
	struct timeval tv, tv_start, tv_end;
	struct event ev;

	setup_test("Loop exit: ");

	tv.tv_usec = 0;
	tv.tv_sec = 60*60*24;
	evtimer_set(&ev, timeout_cb, NULL);
	evtimer_add(&ev, &tv);

	tv.tv_usec = 0;
	tv.tv_sec = 1;
	event_loopexit(&tv);

	evutil_gettimeofday(&tv_start, NULL);
	event_dispatch();
	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);

	evtimer_del(&ev);

	if (tv.tv_sec < 2)
		test_ok = 1;

	cleanup_test();
}

static void
test_loopexit_multiple(void)
{
	struct timeval tv;
	struct event_base *base;

	setup_test("Loop Multiple exit: ");

	base = event_base_new();
	
	tv.tv_usec = 0;
	tv.tv_sec = 1;
	event_base_loopexit(base, &tv);

	tv.tv_usec = 0;
	tv.tv_sec = 2;
	event_base_loopexit(base, &tv);

	event_base_dispatch(base);

	event_base_free(base);
	
	test_ok = 1;

	cleanup_test();
}

static void
break_cb(int fd, short events, void *arg)
{
	test_ok = 1;
	event_loopbreak();
}

static void
fail_cb(int fd, short events, void *arg)
{
	test_ok = 0;
}

static void
test_loopbreak(void)
{
	struct event ev1, ev2;
	struct timeval tv;

	setup_test("Loop break: ");

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_set(&ev1, break_cb, NULL);
	evtimer_add(&ev1, &tv);
	evtimer_set(&ev2, fail_cb, NULL);
	evtimer_add(&ev2, &tv);

	event_dispatch();

	evtimer_del(&ev1);
	evtimer_del(&ev2);

	cleanup_test();
}

static struct event *readd_test_event_last_added = NULL;
static void
re_add_read_cb(int fd, short event, void *arg)
{
	char buf[256];
	int len;
	struct event *ev_other = arg;
	readd_test_event_last_added = ev_other;
	len = read(fd, buf, sizeof(buf));
	event_add(ev_other, NULL);
	++test_ok;
}

static void
test_nonpersist_readd(void)
{
	struct event ev1, ev2;
	int n, m;

	setup_test("Re-add nonpersistent events: ");
	event_set(&ev1, pair[0], EV_READ, re_add_read_cb, &ev2);
	event_set(&ev2, pair[1], EV_READ, re_add_read_cb, &ev1);
	n = write(pair[0], "Hello", 5);
	m = write(pair[1], "Hello", 5);
	if (event_add(&ev1, NULL) == -1 ||
	    event_add(&ev2, NULL) == -1) {
		test_ok = 0;
	}
	if (test_ok != 0)
		exit(1);
	event_loop(EVLOOP_ONCE);
	if (test_ok != 2)
		exit(1);
	/* At this point, we executed both callbacks.  Whichever one got
	 * called first added the second, but the second then immediately got
	 * deleted before its callback was called.  At this point, though, it
	 * re-added the first.
	 */
	if (!readd_test_event_last_added) {
		test_ok = 0;
	} else if (readd_test_event_last_added == &ev1) {
		if (!event_pending(&ev1, EV_READ, NULL) ||
		    event_pending(&ev2, EV_READ, NULL))
			test_ok = 0;
	} else {
		if (event_pending(&ev1, EV_READ, NULL) ||
		    !event_pending(&ev2, EV_READ, NULL))
			test_ok = 0;
	}

	event_del(&ev1);
	event_del(&ev2);

	cleanup_test();
}

/* validates that an evbuffer is good */
static void
evbuffer_validate(struct evbuffer *buf)
{
	struct evbuffer_chain *chain, *previous = NULL;
	size_t sum = 0;
	
	if (buf->first == NULL) {
		assert(buf->last == NULL);
		assert(buf->previous_to_last == NULL);
		assert(buf->total_len == 0);
	}

	if (buf->previous_to_last == NULL) {
		assert(buf->first == buf->last);
	}

	chain = buf->first;
	while (chain != NULL) {
		sum += chain->off;
		if (chain->next == NULL) {
			assert(buf->previous_to_last == previous);
			assert(buf->last == chain);
		}
		assert(chain->buffer_len >= chain->misalign + chain->off);
		previous = chain;
		chain = chain->next;
	}

	assert(sum == buf->total_len);
}

static void
test_evbuffer(void)
{
	static char buffer[512], *tmp;
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_two = evbuffer_new();
	size_t sz_tmp;
	int i;
	setup_test("Testing Evbuffer: ");

	evbuffer_validate(evb);
	evbuffer_add_printf(evb, "%s/%d", "hello", 1);
	evbuffer_validate(evb);

	if (EVBUFFER_LENGTH(evb) != 7 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "hello/1", 1) != 0)
		goto out;

	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	evbuffer_drain(evb, strlen("hello/"));
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 1 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "1", 1) != 0)
		goto out;

	evbuffer_add_printf(evb_two, "%s", "/hello");
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	if (EVBUFFER_LENGTH(evb_two) != 0 ||
	    EVBUFFER_LENGTH(evb) != 7 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "1/hello", 7) != 0)
		goto out;

	memset(buffer, 0, sizeof(buffer));
	evbuffer_add(evb, buffer, sizeof(buffer));
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 7 + 512)
		goto out;

	tmp = (char *)evbuffer_pullup(evb, 7 + 512);
	if (tmp == NULL)
		goto out;
	if (strncmp(tmp, "1/hello", 7) != 0)
		goto out;
	if (memcmp(tmp + 7, buffer, sizeof(buffer)) != 0)
		goto out;
	evbuffer_validate(evb);

	evbuffer_prepend(evb, "something", 9);
	evbuffer_validate(evb);
	evbuffer_prepend(evb, "else", 4);
	evbuffer_validate(evb);

	tmp = (char *)evbuffer_pullup(evb, 4 + 9 + 7);
	if (strncmp(tmp, "elsesomething1/hello", 4 + 9 + 7) != 0)
		goto out;
	evbuffer_validate(evb);

	evbuffer_drain(evb, -1);
	evbuffer_validate(evb);
	evbuffer_drain(evb_two, -1);
	evbuffer_validate(evb);

	for (i = 0; i < 3; ++i) {
		evbuffer_add(evb_two, buffer, sizeof(buffer));
		evbuffer_validate(evb_two);
		evbuffer_add_buffer(evb, evb_two);
		evbuffer_validate(evb);
		evbuffer_validate(evb_two);
	}

	if (EVBUFFER_LENGTH(evb_two) != 0 ||
	    EVBUFFER_LENGTH(evb) != i * sizeof(buffer))
		goto out;

	/* test remove buffer */
	sz_tmp = sizeof(buffer)*2.5;
	evbuffer_remove_buffer(evb, evb_two, sz_tmp);
	if (EVBUFFER_LENGTH(evb_two) != sz_tmp ||
	    EVBUFFER_LENGTH(evb) != sizeof(buffer) / 2)
		goto out;
	evbuffer_validate(evb);

	if (memcmp(evbuffer_pullup(
			   evb, -1), buffer, sizeof(buffer) / 2) != 0 ||
	    memcmp(evbuffer_pullup(
			   evb_two, -1), buffer, sizeof(buffer) != 0))
		goto out;
	evbuffer_validate(evb);


	/* testing reserve and commit */
	{
		u_char *buf;
		int i, j;

		for (i = 0; i < 3; ++i) {
			buf = evbuffer_reserve_space(evb, 10000);
			assert(buf != NULL);
			evbuffer_validate(evb);
			for (j = 0; j < 10000; ++j) {
				buf[j] = j;
			}
			evbuffer_validate(evb);

			assert(evbuffer_commit_space(evb, 10000) == 0);
			evbuffer_validate(evb);

			assert(evbuffer_get_length(evb) >= 10000);

			evbuffer_drain(evb, j * 5000);
			evbuffer_validate(evb);
		}
	}
	
	test_ok = 1;
	
out:
	evbuffer_free(evb);
	evbuffer_free(evb_two);

	cleanup_test();
}

static void
test_evbuffer_readln(void)
{
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_tmp = evbuffer_new();
	const char *s;
	char *cp = NULL;
	size_t sz;
	setup_test("Testing evbuffer_readln(): ");

	/* Test EOL_ANY. */
	s = "complex silly newline\r\n\n\r\n\n\rmore\0\n";
	evbuffer_add(evb, s, strlen(s)+2);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz != strlen(cp) || strcmp(cp, "complex silly newline"))
		goto done;
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz != 5 || memcmp(cp, "more\0\0", 6))
		goto done;
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);
	s = "\nno newline";
	evbuffer_add(evb, s, strlen(s));
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (cp)
		goto done;
	evbuffer_validate(evb);
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);

	/* Test EOL_CRLF */
	s = "Line with\rin the middle\nLine with good crlf\r\n\nfinal\n";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Line with\rin the middle"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Line with good crlf"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "final"))
		goto done;
	s = "x";
	evbuffer_validate(evb);
	evbuffer_add(evb, s, 1);
	evbuffer_validate(evb);
	free(cp);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (cp)
		goto done;
	evbuffer_validate(evb);

	/* Test CRLF_STRICT */
	s = " and a bad crlf\nand a good one\r\n\r\nMore\r";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) ||
	    strcmp(cp, "x and a bad crlf\nand a good one"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (cp)
		goto done;
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, "More"))
		goto done;
	free(cp);
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);

	/* Test LF */
	s = "An\rand a nl\n\nText";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "An\rand a nl"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (cp)
		goto done;
	free(cp);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Text"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	/* Test CRLF_STRICT - across boundaries*/
	s = " and a bad crlf\nand a good one\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);
	s = "\n\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);
	s = "\nMore\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) ||
	    strcmp(cp, " and a bad crlf\nand a good one"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (cp)
		goto done;
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, "More"))
		goto done;
	free(cp); cp = NULL;
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;


	test_ok = 1;
 done:
	evbuffer_free(evb);
	evbuffer_free(evb_tmp);
	if (cp) free(cp);
	cleanup_test();
}

static void
test_evbuffer_iterative(void)
{
	struct evbuffer *buf = evbuffer_new();
	const char *abc = "abcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyz";
	int i, j, sum;

	setup_test("Testing evbuffer() iterative: ");

	sum = 0;
	for (i = 0; i < 1000; ++i) {
		for (j = 1; j < strlen(abc); ++j) {
			char format[32];

			evutil_snprintf(format, sizeof(format), "%%%d.%ds", j, j);
			evbuffer_add_printf(buf, format, abc);
			evbuffer_validate(buf);

			sum += j;
		}
	}
	
	if (sum == EVBUFFER_LENGTH(buf))
		test_ok = 1;

	evbuffer_free(buf);

	cleanup_test();
}

static void
test_evbuffer_find(void)
{
	u_char* p;
	const char* test1 = "1234567890\r\n";
	const char* test2 = "1234567890\r";
#define EVBUFFER_INITIAL_LENGTH 256
	char test3[EVBUFFER_INITIAL_LENGTH];
	unsigned int i;
	struct evbuffer * buf = evbuffer_new();

	/* make sure evbuffer_find doesn't match past the end of the buffer */
	fprintf(stdout, "Testing evbuffer_find 1: ");
	evbuffer_add(buf, (u_char*)test1, strlen(test1));
	evbuffer_validate(buf);
	evbuffer_drain(buf, strlen(test1));	  
	evbuffer_validate(buf);
	evbuffer_add(buf, (u_char*)test2, strlen(test2));
	evbuffer_validate(buf);
	p = evbuffer_find(buf, (u_char*)"\r\n", 2);
	if (p == NULL) {
		fprintf(stdout, "OK\n");
	} else {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/*
	 * drain the buffer and do another find; in r309 this would
	 * read past the allocated buffer causing a valgrind error.
	 */
	fprintf(stdout, "Testing evbuffer_find 2: ");
	evbuffer_drain(buf, strlen(test2));
	evbuffer_validate(buf);
	for (i = 0; i < EVBUFFER_INITIAL_LENGTH; ++i)
		test3[i] = 'a';
	test3[EVBUFFER_INITIAL_LENGTH - 1] = 'x';
	evbuffer_add(buf, (u_char *)test3, EVBUFFER_INITIAL_LENGTH);
	evbuffer_validate(buf);
	p = evbuffer_find(buf, (u_char *)"xy", 2);
	if (p == NULL) {
		printf("OK\n");
	} else {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	/* simple test for match at end of allocated buffer */
	fprintf(stdout, "Testing evbuffer_find 3: ");
	p = evbuffer_find(buf, (u_char *)"ax", 2);
	if (p != NULL && strncmp((char*)p, "ax", 2) == 0) {
		printf("OK\n");
	} else {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evbuffer_free(buf);
}

/*
 * simple bufferevent test
 */

static void
readcb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->input) == 8333) {
		struct evbuffer *evbuf = evbuffer_new();
		assert(evbuf != NULL);

		/* gratuitous test of bufferevent_read_buffer */
		bufferevent_read_buffer(bev, evbuf);

		bufferevent_disable(bev, EV_READ);

		if (EVBUFFER_LENGTH(evbuf) == 8333)
			test_ok++;

		evbuffer_free(evbuf);
	}
}

static void
writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->output) == 0)
		test_ok++;
}

static void
errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
}

static void
test_bufferevent(void)
{
	struct bufferevent *bev1, *bev2;
	char buffer[8333];
	int i;

	setup_test("Bufferevent: ");

	bev1 = bufferevent_new(pair[0], readcb, writecb, errorcb, NULL);
	bev2 = bufferevent_new(pair[1], readcb, writecb, errorcb, NULL);

	bufferevent_disable(bev1, EV_READ);
	bufferevent_enable(bev2, EV_READ);

	for (i = 0; i < sizeof(buffer); i++)
		buffer[i] = i;

	bufferevent_write(bev1, buffer, sizeof(buffer));

	event_dispatch();

	bufferevent_free(bev1);
	bufferevent_free(bev2);

	if (test_ok != 2)
		test_ok = 0;

	cleanup_test();
}

/*
 * test watermarks and bufferevent
 */

static void
wm_readcb(struct bufferevent *bev, void *arg)
{
	struct evbuffer *evbuf = evbuffer_new();
	int len = EVBUFFER_LENGTH(bev->input);
	static int nread;

	assert(len >= 10 && len <= 20);

	assert(evbuf != NULL);

	/* gratuitous test of bufferevent_read_buffer */
	bufferevent_read_buffer(bev, evbuf);

	nread += len;
	if (nread == 65000) {
		bufferevent_disable(bev, EV_READ);
		test_ok++;
	}

	evbuffer_free(evbuf);
}

static void
wm_writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->output) == 0)
		test_ok++;
}

static void
wm_errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
}

static void
test_bufferevent_watermarks(void)
{
	struct bufferevent *bev1, *bev2;
	char buffer[65000];
	int i;

	setup_test("Bufferevent Watermarks: ");

	bev1 = bufferevent_new(pair[0], NULL, wm_writecb, wm_errorcb, NULL);
	bev2 = bufferevent_new(pair[1], wm_readcb, NULL, wm_errorcb, NULL);

	bufferevent_disable(bev1, EV_READ);
	bufferevent_enable(bev2, EV_READ);

	for (i = 0; i < sizeof(buffer); i++)
		buffer[i] = i;

	bufferevent_write(bev1, buffer, sizeof(buffer));

	/* limit the reading on the receiving bufferevent */
	bufferevent_setwatermark(bev2, EV_READ, 10, 20);

	event_dispatch();

	bufferevent_free(bev1);
	bufferevent_free(bev2);

	if (test_ok != 2)
		test_ok = 0;

	cleanup_test();
}

/*
 * Test bufferevent filters
 */

/* strip an 'x' from each byte */

static enum bufferevent_filter_result
bufferevent_input_filter(struct evbuffer *src, struct evbuffer *dst,
    enum bufferevent_filter_state state, void *ctx)
{
	const unsigned char *buffer;
	int i;

	buffer = evbuffer_pullup(src, EVBUFFER_LENGTH(src));
	for (i = 0; i < EVBUFFER_LENGTH(src); i += 2) {
		assert(buffer[i] == 'x');
		evbuffer_add(dst, buffer + i + 1, 1);

		if (i + 2 > EVBUFFER_LENGTH(src))
			break;
	}

	evbuffer_drain(src, i);
	return (BEV_OK);
}

/* add an 'x' before each byte */

static enum bufferevent_filter_result
bufferevent_output_filter(struct evbuffer *src, struct evbuffer *dst,
    enum bufferevent_filter_state state, void *ctx)
{
	const unsigned char *buffer;
	int i;

	buffer = evbuffer_pullup(src, EVBUFFER_LENGTH(src));
	for (i = 0; i < EVBUFFER_LENGTH(src); ++i) {
		evbuffer_add(dst, "x", 1);
		evbuffer_add(dst, buffer + i, 1);
	}

	evbuffer_drain(src, EVBUFFER_LENGTH(src));
	return (BEV_OK);
}

static void
test_bufferevent_filters(void)
{
	struct bufferevent *bev1, *bev2;
	struct bufferevent_filter *finput, *foutput;
	char buffer[8333];
	int i;

	setup_test("Bufferevent Filters: ");

	bev1 = bufferevent_new(pair[0], NULL, writecb, errorcb, NULL);
	bev2 = bufferevent_new(pair[1], readcb, NULL, errorcb, NULL);

	bufferevent_disable(bev1, EV_READ);
	bufferevent_enable(bev2, EV_READ);

	for (i = 0; i < sizeof(buffer); i++)
		buffer[i] = i;

	/* insert some filters */
	finput = bufferevent_filter_new(
		NULL, NULL,bufferevent_input_filter, NULL);
	foutput = bufferevent_filter_new(
		NULL, NULL, bufferevent_output_filter, NULL);

	bufferevent_filter_insert(bev1, BEV_OUTPUT, foutput);
	bufferevent_filter_insert(bev2, BEV_INPUT, finput);

	bufferevent_write(bev1, buffer, sizeof(buffer));

	event_dispatch();

	bufferevent_filter_remove(bev1, BEV_OUTPUT, foutput);
	bufferevent_filter_free(foutput);

	bufferevent_free(bev1);
	bufferevent_free(bev2);

	if (test_ok != 2)
		test_ok = 0;

	cleanup_test();
}

struct test_pri_event {
	struct event ev;
	int count;
};

static void
test_priorities_cb(int fd, short what, void *arg)
{
	struct test_pri_event *pri = arg;
	struct timeval tv;

	if (pri->count == 3) {
		event_loopexit(NULL);
		return;
	}

	pri->count++;

	evutil_timerclear(&tv);
	event_add(&pri->ev, &tv);
}

static void
test_priorities(int npriorities)
{
	char buf[32];
	struct test_pri_event one, two;
	struct timeval tv;

	evutil_snprintf(buf, sizeof(buf), "Testing Priorities %d: ", npriorities);
	setup_test(buf);

	event_base_priority_init(global_base, npriorities);

	memset(&one, 0, sizeof(one));
	memset(&two, 0, sizeof(two));

	timeout_set(&one.ev, test_priorities_cb, &one);
	if (event_priority_set(&one.ev, 0) == -1) {
		fprintf(stderr, "%s: failed to set priority", __func__);
		exit(1);
	}

	timeout_set(&two.ev, test_priorities_cb, &two);
	if (event_priority_set(&two.ev, npriorities - 1) == -1) {
		fprintf(stderr, "%s: failed to set priority", __func__);
		exit(1);
	}

	evutil_timerclear(&tv);

	if (event_add(&one.ev, &tv) == -1)
		exit(1);
	if (event_add(&two.ev, &tv) == -1)
		exit(1);

	event_dispatch();

	event_del(&one.ev);
	event_del(&two.ev);

	if (npriorities == 1) {
		if (one.count == 3 && two.count == 3)
			test_ok = 1;
	} else if (npriorities == 2) {
		/* Two is called once because event_loopexit is priority 1 */
		if (one.count == 3 && two.count == 1)
			test_ok = 1;
	} else {
		if (one.count == 3 && two.count == 0)
			test_ok = 1;
	}

	cleanup_test();
}

static void
test_multiple_cb(int fd, short event, void *arg)
{
	if (event & EV_READ)
		test_ok |= 1;
	else if (event & EV_WRITE)
		test_ok |= 2;
}

static void
test_multiple_events_for_same_fd(void)
{
   struct event e1, e2;

   setup_test("Multiple events for same fd: ");

   event_set(&e1, pair[0], EV_READ, test_multiple_cb, NULL);
   event_add(&e1, NULL);
   event_set(&e2, pair[0], EV_WRITE, test_multiple_cb, NULL);
   event_add(&e2, NULL);
   event_loop(EVLOOP_ONCE);
   event_del(&e2);
   write(pair[1], TEST1, strlen(TEST1)+1);
   event_loop(EVLOOP_ONCE);
   event_del(&e1);
   
   if (test_ok != 3)
	   test_ok = 0;

   cleanup_test();
}

int evtag_decode_int(ev_uint32_t *pnumber, struct evbuffer *evbuf);
int evtag_encode_tag(struct evbuffer *evbuf, ev_uint32_t number);
int evtag_decode_tag(ev_uint32_t *pnumber, struct evbuffer *evbuf);

static void
read_once_cb(int fd, short event, void *arg)
{
	char buf[256];
	int len;

	len = read(fd, buf, sizeof(buf));

	if (called) {
		test_ok = 0;
	} else if (len) {
		/* Assumes global pair[0] can be used for writing */
		write(pair[0], TEST1, strlen(TEST1)+1);
		test_ok = 1;
	}

	called++;
}

static void
test_want_only_once(void)
{
	struct event ev;
	struct timeval tv;

	/* Very simple read test */
	setup_test("Want read only once: ");
	
	write(pair[0], TEST1, strlen(TEST1)+1);

	/* Setup the loop termination */
	evutil_timerclear(&tv);
	tv.tv_sec = 1;
	event_loopexit(&tv);
	
	event_set(&ev, pair[1], EV_READ, read_once_cb, &ev);
	if (event_add(&ev, NULL) == -1)
		exit(1);
	event_dispatch();

	cleanup_test();
}

#define TEST_MAX_INT	6

static void
evtag_int_test(void)
{
	struct evbuffer *tmp = evbuffer_new();
	ev_uint32_t integers[TEST_MAX_INT] = {
		0xaf0, 0x1000, 0x1, 0xdeadbeef, 0x00, 0xbef000
	};
	ev_uint32_t integer;
	int i;

	for (i = 0; i < TEST_MAX_INT; i++) {
		int oldlen, newlen;
		oldlen = EVBUFFER_LENGTH(tmp);
		encode_int(tmp, integers[i]);
		newlen = EVBUFFER_LENGTH(tmp);
		fprintf(stdout, "\t\tencoded 0x%08x with %d bytes\n",
				(unsigned)integers[i], newlen - oldlen);
	}

	for (i = 0; i < TEST_MAX_INT; i++) {
		if (evtag_decode_int(&integer, tmp) == -1) {
			fprintf(stderr, "decode %d failed", i);
			exit(1);
		}
		if (integer != integers[i]) {
			fprintf(stderr, "got %x, wanted %x",
					(unsigned)integer, (unsigned)integers[i]);
			exit(1);
		}
	}

	if (EVBUFFER_LENGTH(tmp) != 0) {
		fprintf(stderr, "trailing data");
		exit(1);
	}
	evbuffer_free(tmp);

	fprintf(stdout, "\t%s: OK\n", __func__);
}

static void
evtag_fuzz(void)
{
	u_char buffer[4096];
	struct evbuffer *tmp = evbuffer_new();
	struct timeval tv;
	int i, j;

	int not_failed = 0;
	for (j = 0; j < 100; j++) {
		for (i = 0; i < sizeof(buffer); i++)
			buffer[i] = rand();
		evbuffer_drain(tmp, -1);
		evbuffer_add(tmp, buffer, sizeof(buffer));

		if (evtag_unmarshal_timeval(tmp, 0, &tv) != -1)
			not_failed++;
	}

	/* The majority of decodes should fail */
	if (not_failed >= 10) {
		fprintf(stderr, "evtag_unmarshal should have failed");
		exit(1);
	}

	/* Now insert some corruption into the tag length field */
	evbuffer_drain(tmp, -1);
	evutil_timerclear(&tv);
	tv.tv_sec = 1;
	evtag_marshal_timeval(tmp, 0, &tv);
	evbuffer_add(tmp, buffer, sizeof(buffer));

	((char *)EVBUFFER_DATA(tmp))[1] = 0xff;
	if (evtag_unmarshal_timeval(tmp, 0, &tv) != -1) {
		fprintf(stderr, "evtag_unmarshal_timeval should have failed");
		exit(1);
	}

	evbuffer_free(tmp);

	fprintf(stdout, "\t%s: OK\n", __func__);
}

static void
evtag_tag_encoding(void)
{
	struct evbuffer *tmp = evbuffer_new();
	ev_uint32_t integers[TEST_MAX_INT] = {
		0xaf0, 0x1000, 0x1, 0xdeadbeef, 0x00, 0xbef000
	};
	ev_uint32_t integer;
	int i;

	for (i = 0; i < TEST_MAX_INT; i++) {
		int oldlen, newlen;
		oldlen = EVBUFFER_LENGTH(tmp);
		evtag_encode_tag(tmp, integers[i]);
		newlen = EVBUFFER_LENGTH(tmp);
		fprintf(stdout, "\t\tencoded 0x%08x with %d bytes\n",
				(unsigned)integers[i], newlen - oldlen);
	}

	for (i = 0; i < TEST_MAX_INT; i++) {
		if (evtag_decode_tag(&integer, tmp) == -1) {
			fprintf(stderr, "decode %d failed", i);
			exit(1);
		}
		if (integer != integers[i]) {
			fprintf(stderr, "got %x, wanted %x",
					(unsigned)integer, (unsigned)integers[i]);
			exit(1);
		}
	}

	if (EVBUFFER_LENGTH(tmp) != 0) {
		fprintf(stderr, "trailing data");
		exit(1);
	}
	evbuffer_free(tmp);

	fprintf(stdout, "\t%s: OK\n", __func__);
}

static void
evtag_test(void)
{
	fprintf(stdout, "Testing Tagging:\n");

	evtag_init();
	evtag_int_test();
	evtag_fuzz();

	evtag_tag_encoding();

	fprintf(stdout, "OK\n");
}

static void
rpc_test(void)
{
#ifndef WIN32
	struct msg *msg, *msg2;
	struct kill *attack;
	struct run *run;
	struct evbuffer *tmp = evbuffer_new();
	struct timeval tv_start, tv_end;
	ev_uint32_t tag;
	int i;

	fprintf(stdout, "Testing RPC: ");

	msg = msg_new();
	EVTAG_ASSIGN(msg, from_name, "niels");
	EVTAG_ASSIGN(msg, to_name, "phoenix");

	if (EVTAG_GET(msg, attack, &attack) == -1) {
		fprintf(stderr, "Failed to set kill message.\n");
		exit(1);
	}

	EVTAG_ASSIGN(attack, weapon, "feather");
	EVTAG_ASSIGN(attack, action, "tickle");
	for (i = 0; i < 3; ++i) {
		if (EVTAG_ADD(attack, how_often, i) == NULL) {
			fprintf(stderr, "Failed to add how_often.\n");
			exit(1);
		}
	}

	evutil_gettimeofday(&tv_start, NULL);
	for (i = 0; i < 1000; ++i) {
		run = EVTAG_ADD(msg, run);
		if (run == NULL) {
			fprintf(stderr, "Failed to add run message.\n");
			exit(1);
		}
		EVTAG_ASSIGN(run, how, "very fast but with some data in it");
		EVTAG_ASSIGN(run, fixed_bytes,
		    (ev_uint8_t*)"012345678901234567890123");

		if (EVTAG_ADD(run, notes, "this is my note") == NULL) {
			fprintf(stderr, "Failed to add note.\n");
			exit(1);
		}
		if (EVTAG_ADD(run, notes, "pps") == NULL) {
			fprintf(stderr, "Failed to add note.\n");
			exit(1);
		}

		EVTAG_ASSIGN(run, large_number, 0xdead0a0bcafebeefLL);
		EVTAG_ADD(run, other_numbers, 0xdead0a0b);
		EVTAG_ADD(run, other_numbers, 0xbeefcafe);
	}

	if (msg_complete(msg) == -1) {
		fprintf(stderr, "Failed to make complete message.\n");
		exit(1);
	}

	evtag_marshal_msg(tmp, 0xdeaf, msg);

	if (evtag_peek(tmp, &tag) == -1) {
		fprintf(stderr, "Failed to peak tag.\n");
		exit (1);
	}

	if (tag != 0xdeaf) {
		fprintf(stderr, "Got incorrect tag: %0x.\n", (unsigned)tag);
		exit (1);
	}

	msg2 = msg_new();
	if (evtag_unmarshal_msg(tmp, 0xdeaf, msg2) == -1) {
		fprintf(stderr, "Failed to unmarshal message.\n");
		exit(1);
	}

	evutil_gettimeofday(&tv_end, NULL);
	evutil_timersub(&tv_end, &tv_start, &tv_end);
	fprintf(stdout, "(%.1f us/add) ",
	    (float)tv_end.tv_sec/(float)i * 1000000.0 +
	    tv_end.tv_usec / (float)i);

	if (!EVTAG_HAS(msg2, from_name) ||
	    !EVTAG_HAS(msg2, to_name) ||
	    !EVTAG_HAS(msg2, attack)) {
		fprintf(stderr, "Missing data structures.\n");
		exit(1);
	}

	if (EVTAG_GET(msg2, attack, &attack) == -1) {
		fprintf(stderr, "Could not get attack.\n");
		exit(1);
	}

	if (EVTAG_LEN(msg2, run) != i) {
		fprintf(stderr, "Wrong number of run messages.\n");
		exit(1);
	}

	/* get the very first run message */
	if (EVTAG_GET(msg2, run, 0, &run) == -1) {
		fprintf(stderr, "Failed to get run msg.\n");
		exit(1);
	} else {
		/* verify the notes */
		char *note_one, *note_two;
		ev_uint64_t large_number;
		ev_uint32_t short_number;

		if (EVTAG_LEN(run, notes) != 2) {
			fprintf(stderr, "Wrong number of note strings.\n");
			exit(1);
		}

		if (EVTAG_GET(run, notes, 0, &note_one) == -1 ||
		    EVTAG_GET(run, notes, 1, &note_two) == -1) {
			fprintf(stderr, "Could not get note strings.\n");
			exit(1);
		}

		if (strcmp(note_one, "this is my note") ||
		    strcmp(note_two, "pps")) {
			fprintf(stderr, "Incorrect note strings encoded.\n");
			exit(1);
		}
	       
		if (EVTAG_GET(run, large_number, &large_number) == -1 ||
		    large_number != 0xdead0a0bcafebeefLL) {
			fprintf(stderr, "Incorrrect large_number.\n");
			exit(1);
		}

		if (EVTAG_LEN(run, other_numbers) != 2) {
			fprintf(stderr, "Wrong number of other_numbers.\n");
			exit(1);
		}

		if (EVTAG_GET(run, other_numbers, 0, &short_number) == -1) {
			fprintf(stderr, "Could not get short number.\n");
			exit(1);
		}
		assert(short_number == 0xdead0a0b);

	}
	if (EVTAG_LEN(attack, how_often) != 3) {
		fprintf(stderr, "Wrong number of how_often ints.\n");
		exit(1);
	}

	for (i = 0; i < 3; ++i) {
		ev_uint32_t res;
		if (EVTAG_GET(attack, how_often, i, &res) == -1) {
			fprintf(stderr, "Cannot get %dth how_often msg.\n", i);
			exit(1);
		}
		if (res != i) {
			fprintf(stderr, "Wrong message encoded %d != %d\n", i, res);
			exit(1);
		}
	}

	msg_free(msg);
	msg_free(msg2);

	evbuffer_free(tmp);

	fprintf(stdout, "OK\n");
#endif
}

static void
test_evutil_strtoll(void)
{
        const char *s;
        char *endptr;
        setup_test("evutil_stroll: ");
        test_ok = 0;

        if (evutil_strtoll("5000000000", NULL, 10) != ((ev_int64_t)5000000)*1000)
                goto err;
        if (evutil_strtoll("-5000000000", NULL, 10) != ((ev_int64_t)5000000)*-1000)
                goto err;
        s = " 99999stuff";
        if (evutil_strtoll(s, &endptr, 10) != (ev_int64_t)99999)
                goto err;
        if (endptr != s+6)
                goto err;
        if (evutil_strtoll("foo", NULL, 10) != 0)
                goto err;

        test_ok = 1;
 err:
        cleanup_test();
}

static void
test_evutil_snprintf(void)
{
	char buf[16];
	int r;
	setup_test("evutil_snprintf: ");
	test_ok = 0;
	r = evutil_snprintf(buf, sizeof(buf), "%d %d", 50, 100);
	if (strcmp(buf, "50 100")) {
		fprintf(stderr, "buf='%s'\n", buf);
		goto err;
	}
	if (r != 6) {
		fprintf(stderr, "r=%d\n", r);
		goto err;
	}

	r = evutil_snprintf(buf, sizeof(buf), "longish %d", 1234567890);
	if (strcmp(buf, "longish 1234567")) {
		fprintf(stderr, "buf='%s'\n", buf);
		goto err;
	}
	if (r != 18) {
		fprintf(stderr, "r=%d\n", r);
		goto err;
	}

	test_ok = 1;
 err:
	cleanup_test();
}

static void
test_methods(void)
{
	const char **methods = event_get_supported_methods();
	struct event_config *cfg;
	struct event_base *base;
	const char *backend;
	int n_methods = 0;

	fprintf(stdout, "Testing supported methods: ");

	if (methods == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	backend = methods[0];
	while (*methods != NULL) {
		fprintf(stdout, "%s ", *methods);
		++methods;
		++n_methods;
	}

	if (n_methods == 1) {
		/* only one method supported; can't continue. */
		goto done;
	}

	cfg = event_config_new();
	assert(cfg != NULL);

	assert(event_config_avoid_method(cfg, backend) == 0);

	base = event_base_new_with_config(cfg);
	if (base == NULL) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	if (strcmp(backend, event_base_get_method(base)) == 0) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	event_base_free(base);
	event_config_free(cfg);
done:
	fprintf(stdout, "OK\n");
}


int
main (int argc, char **argv)
{
#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int	err;

	wVersionRequested = MAKEWORD( 2, 2 );

	err = WSAStartup( wVersionRequested, &wsaData );
#endif

#ifndef WIN32
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return (1);
#endif
	setvbuf(stdout, NULL, _IONBF, 0);

	test_methods();

	/* Initalize the event library */
	global_base = event_init();

	test_evutil_strtoll();
	test_evutil_snprintf();
	util_suite();

	test_periodictimeout();
	test_persistent_timeout();

	/* use the global event base and need to be called first */
	test_priorities(1);
	test_priorities(2);
	test_priorities(3);

	test_evbuffer();
	test_evbuffer_iterative();
	test_evbuffer_readln();
	test_evbuffer_find();

	test_bufferevent();
	test_bufferevent_watermarks();
	test_bufferevent_filters();

	test_free_active_base();

	test_event_base_new();

#if defined(HAVE_PTHREADS) && !defined(DISABLE_THREAD_SUPPORT)
	regress_pthread();
#endif

#if defined(HAVE_LIBZ)
	regress_zlib();
#endif

	test_simpleread();
	test_simpleread_multiple();

	test_simplewrite();

	test_multiple();

	test_persistent();

	test_combined();

	test_simpletimeout();

#ifndef WIN32
	test_fork();
#endif

#ifndef WIN32
	test_edgetriggered();
	test_simplesignal();
	test_multiplesignal();
	test_immediatesignal();
#endif
	test_loopexit();
	test_loopbreak();

	http_suite();

#ifndef WIN32
	rpc_suite();
#endif

	dns_suite();

	test_loopexit_multiple();

        test_nonpersist_readd();

	test_multiple_events_for_same_fd();

	test_want_only_once();

	evtag_test();

	rpc_test();

#ifndef WIN32
	test_signal_dealloc();
	test_signal_pipeloss();
	test_signal_switchbase();
	test_signal_restore();
	test_signal_assert();
#endif
	
	return (0);
}

