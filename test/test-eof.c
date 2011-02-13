/*
 * Compile with:
 * cc -I/usr/local/include -o time-test time-test.c -L/usr/local/lib -levent
 */
#include "event2/event-config.h"

#ifdef WIN32
#include <winsock2.h>
#else
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <event.h>
#include <evutil.h>

#ifdef _EVENT___func__
#define __func__ _EVENT___func__
#endif

int test_okay = 1;
int called = 0;
struct timeval timeout = {60, 0};

static void
read_cb(evutil_socket_t fd, short event, void *arg)
{
	char buf[256];
	int len;

	if (EV_TIMEOUT & event) {
		printf("%s: Timeout!\n", __func__);
		exit(1);
	}

	len = recv(fd, buf, sizeof(buf), 0);

	printf("%s: read %d%s\n", __func__,
	    len, len ? "" : " - means EOF");

	if (len) {
		if (!called)
			event_add(arg, &timeout);
	} else if (called == 1)
		test_okay = 0;

	called++;
}

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

int
main(int argc, char **argv)
{
	struct event ev;
	const char *test = "test string";
	evutil_socket_t pair[2];

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int	err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
#endif

	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);


	send(pair[0], test, (int)strlen(test)+1, 0);
	shutdown(pair[0], SHUT_WR);

	/* Initalize the event library */
	event_init();

	/* Initalize one event */
	event_set(&ev, pair[1], EV_READ | EV_TIMEOUT, read_cb, &ev);

	event_add(&ev, &timeout);

	event_dispatch();

	return (test_okay);
}

