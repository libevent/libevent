/*
 *  based on test-eof.c
 */

#include "event-config.h"

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

#include <event2/event.h>
#include <event2/util.h>
#include <time.h>


static void
write_cb(evutil_socket_t fd, short event, void *arg)
{  
	printf("write callback. should only see this once\n");
        
	/* got what we want remove the event */
	event_del(*(struct event**)arg);

	/* opps changed my mind add it back again */
	event_add(*(struct event**)arg,NULL);

	/* not a good day for decisiveness, I really didn't want it after all */
	event_del(*(struct event**)arg);

}

static void
timeout_cb(evutil_socket_t fd, short event, void *arg)
{  

	char buf[256];
	int len;

	printf("timeout fired, time to end test\n");
	event_del(*(struct event**)arg);
	return;
}

int
main(int argc, char **argv)
{
	struct event* ev;
	struct event* timeout;
	struct event_base* base;

	int pair[2];
	int res;
	int tickspassed;
	struct timeval timeBegin;
	struct timeval timeEnd;
	struct timeval tv;

	clock_t ticksBegin;
	clock_t ticksEnd;
	double usage;

#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int	err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
#endif
	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	/* Initalize the event library */
	base = event_base_new();

	/* Initalize a timeout to terminate the test */
	timeout = evtimer_new(base,timeout_cb,&timeout);
	/* and watch for writability on one end of the pipe */
	ev = event_new(base,pair[1],EV_WRITE | EV_PERSIST, write_cb, &ev);

	tv.tv_sec  = 5;
	tv.tv_usec = 0;

	evtimer_add(timeout, &tv);

	event_add(ev, NULL);

	ticksBegin = clock();

	evutil_gettimeofday(&timeBegin,NULL);

	res = event_base_dispatch(base);

	evutil_gettimeofday(&timeEnd,NULL);

	ticksEnd = clock();

	/* attempt to calculate our cpu usage over the test should be
	   virtually nil */
	
	tickspassed = ((((timeEnd.tv_sec - timeBegin.tv_sec) * 1000000.0) +
			(timeEnd.tv_usec - timeBegin.tv_usec)) *
		       ((1.0 * CLOCKS_PER_SEC) / 1000000));
	
	usage = 100.0 * (((int)(ticksEnd-ticksBegin) * 1.0) / tickspassed);

	printf("ticks used=%d, ticks passed=%d, cpu usage=%.2f%%\n",
	       (int)(ticksEnd-ticksBegin),
	       tickspassed,
	       usage); 

	if (usage > 50.0) /* way too high */
	  return 1;

	return 0;
}

