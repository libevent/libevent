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
#ifndef WIN32
#include <sys/socket.h>
#include <sys/signal.h>
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event.h>

static int pair[2];
static int test_ok;
static int called;
static char wbuf[4096];
static char rbuf[4096];
static int woff;
static int roff;
static int usepersist;
static struct timeval tset;
static struct timeval tcalled;
static struct event_base *event_base;

#define TEST1	"this is a test"
#define SECONDS	1

void
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

void
simple_write_cb(int fd, short event, void *arg)
{
	int len;

	len = write(fd, TEST1, strlen(TEST1) + 1);
	if (len == -1)
		test_ok = 0;
	else
		test_ok = 1;
}

void
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

void
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

void
timeout_cb(int fd, short event, void *arg)
{
	struct timeval tv;
	int diff;

	gettimeofday(&tcalled, NULL);
	if (timercmp(&tcalled, &tset, >))
		timersub(&tcalled, &tset, &tv);
	else
		timersub(&tset, &tcalled, &tv);

	diff = tv.tv_sec*1000 + tv.tv_usec/1000 - SECONDS * 1000;
	if (diff < 0)
		diff = -diff;

	if (diff < 100)
		test_ok = 1;
}

void
signal_cb(int fd, short event, void *arg)
{
	struct event *ev = arg;

	signal_del(ev);
	test_ok = 1;
}

struct both {
	struct event ev;
	int nread;
};

void
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

void
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

int
setup_test(char *name)
{

	fprintf(stdout, "%s", name);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		fprintf(stderr, "%s: socketpair\n", __func__);
		exit(1);
	}

#ifdef HAVE_FCNTL
        if (fcntl(pair[0], F_SETFL, O_NONBLOCK) == -1)
		fprintf(stderr, "fcntl(O_NONBLOCK)");

        if (fcntl(pair[1], F_SETFL, O_NONBLOCK) == -1)
		fprintf(stderr, "fcntl(O_NONBLOCK)");
#endif

	test_ok = 0;
	called = 0;
	return (0);
}

int
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

	return (0);
}

void
test1(void)
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

void
test2(void)
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

void
test3(void)
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

void
test4(void)
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

void
test5(void)
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

void
test6(void)
{
	struct timeval tv;
	struct event ev;

	setup_test("Simple timeout: ");

	tv.tv_usec = 0;
	tv.tv_sec = SECONDS;
	evtimer_set(&ev, timeout_cb, NULL);
	evtimer_add(&ev, &tv);

	gettimeofday(&tset, NULL);
	event_dispatch();

	cleanup_test();
}

#ifndef WIN32
void
test7(void)
{
	struct event ev;
	struct itimerval itv;

	setup_test("Simple signal: ");
	signal_set(&ev, SIGALRM, signal_cb, &ev);
	signal_add(&ev, NULL);

	memset(&itv, 0, sizeof(itv));
	itv.it_value.tv_sec = 1;
	if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
		goto skip_simplesignal;

	event_dispatch();
 skip_simplesignal:
	signal_del(&ev);

	cleanup_test();
}
#endif

void
test8(void)
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

	gettimeofday(&tv_start, NULL);
	event_dispatch();
	gettimeofday(&tv_end, NULL);
	timersub(&tv_end, &tv_start, &tv_end);

	evtimer_del(&ev);

	if (tv.tv_sec < 2)
		test_ok = 1;

	cleanup_test();
}

void
readcb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->input) == 8333) {
		bufferevent_disable(bev, EV_READ);
		test_ok++;
	}
}

void
writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->output) == 0)
		test_ok++;
}

void
errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
}

void
test9(void)
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
		buffer[0] = i;

	bufferevent_write(bev1, buffer, sizeof(buffer));

	event_dispatch();

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

void
test_priorities_cb(int fd, short what, void *arg)
{
	struct test_pri_event *pri = arg;
	struct timeval tv;

	if (pri->count == 3) {
		event_loopexit(NULL);
		return;
	}

	pri->count++;

	timerclear(&tv);
	event_add(&pri->ev, &tv);
}

void
test_priorities(int npriorities)
{
	char buf[32];
	struct test_pri_event one, two;
	struct timeval tv;

	snprintf(buf, sizeof(buf), "Priorities %d: ", npriorities);
	setup_test(buf);

	event_base_priority_init(event_base, npriorities);

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

	timerclear(&tv);

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

void
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

	setvbuf(stdout, NULL, _IONBF, 0);

	/* Initalize the event library */
	event_base = event_init();

	test1();

	test2();

	test3();

	test4();

	test5();

	test6();
#ifndef WIN32
	test7();
#endif
	test8();

	test9();

	test_priorities(1);
	test_priorities(2);
	test_priorities(3);

	test_multiple_events_for_same_fd();

	return (0);
}

