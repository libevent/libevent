/*
 * Copyright 2003 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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

#define TEST1	"this is a test"
#define SECONDS	1

void
simple_read_cb(int fd, short event, void *arg)
{
	char buf[256];
	int len;

	len = read(fd, buf, sizeof(buf));

	if (len) {
		if (!called)
			event_add(arg, NULL);
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

	if (!usepersist)
		event_add(ev, NULL);
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
	if (!usepersist)
		event_add(ev, NULL);
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
	event_add(&both->ev, NULL);
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
	event_add(&both->ev, NULL);
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

	test_ok = 0;
	called = 0;
	return (0);
}

int
cleanup_test(void)
{
	close(pair[0]);
	close(pair[1]);

	if (test_ok)
		fprintf(stdout, "OK\n");
	else {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	return (0);
}

int
main (int argc, char **argv)
{
	struct event ev, ev2;
	struct timeval tv;
	struct itimerval itv;
	struct both r1, r2, w1, w2;
	int i;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* Initalize the event library */
	event_init();

	/* Very simple read test */
	setup_test("Simple read: ");
	
	write(pair[0], TEST1, strlen(TEST1)+1);
	shutdown(pair[0], SHUT_WR);

	event_set(&ev, pair[1], EV_READ, simple_read_cb, &ev);
	event_add(&ev, NULL);
	event_dispatch();

	cleanup_test();

	/* Very simple write test */
	setup_test("Simple write: ");
	
	event_set(&ev, pair[0], EV_WRITE, simple_write_cb, &ev);
	event_add(&ev, NULL);
	event_dispatch();

	cleanup_test();

	/* Multiple read and write test */
	setup_test("Multiple read/write: ");
	memset(rbuf, 0, sizeof(rbuf));
	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = i;

	roff = woff = 0;
	usepersist = 0;

	event_set(&ev, pair[0], EV_WRITE, multiple_write_cb, &ev);
	event_add(&ev, NULL);
	event_set(&ev2, pair[1], EV_READ, multiple_read_cb, &ev2);
	event_add(&ev2, NULL);
	event_dispatch();

	if (roff == woff)
		test_ok = memcmp(rbuf, wbuf, sizeof(wbuf)) == 0;

	cleanup_test();

	/* Multiple read and write test with persist */
	setup_test("Persist read/write: ");
	memset(rbuf, 0, sizeof(rbuf));
	for (i = 0; i < sizeof(wbuf); i++)
		wbuf[i] = i;

	roff = woff = 0;
	usepersist = 1;

	event_set(&ev, pair[0], EV_WRITE|EV_PERSIST, multiple_write_cb, &ev);
	event_add(&ev, NULL);
	event_set(&ev2, pair[1], EV_READ|EV_PERSIST, multiple_read_cb, &ev2);
	event_add(&ev2, NULL);
	event_dispatch();

	if (roff == woff)
		test_ok = memcmp(rbuf, wbuf, sizeof(wbuf)) == 0;

	cleanup_test();

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
	event_add(&r1.ev, NULL);
	event_add(&w1.ev, NULL);
	event_add(&r2.ev, NULL);
	event_add(&w2.ev, NULL);

	event_dispatch();

	if (r1.nread == 8192 && r2.nread == 4096)
		test_ok = 1;

	cleanup_test();
	

	setup_test("Simple timeout: ");

	tv.tv_usec = 0;
	tv.tv_sec = SECONDS;
	evtimer_set(&ev, timeout_cb, NULL);
	evtimer_add(&ev, &tv);

	gettimeofday(&tset, NULL);
	event_dispatch();

	cleanup_test();

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

	return (0);
}

