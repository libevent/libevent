/*
 * Compile with:
 * cc -I/usr/local/include -o time-test time-test.c -L/usr/local/lib -levent
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>

int lasttime;

void
timeout_cb(int fd, short event, void *arg)
{
	struct timeval tv;
	struct event *timeout = arg;
	int newtime = time(NULL);

	printf("%s: called at %d: %d\n", __FUNCTION__, newtime,
	    newtime - lasttime);
	lasttime = newtime;

	timerclear(&tv);
	tv.tv_sec = 2;
	event_add(timeout, &tv);
}

int
main (int argc, char **argv)
{
	struct event timeout;
	struct timeval tv;
 
	/* Initalize the event library */
	event_init();

	/* Initalize one event */
	timeout_set(&timeout, timeout_cb, &timeout);

	timerclear(&tv);
	tv.tv_sec = 2;
	event_add(&timeout, &tv);

	lasttime = time(NULL);
	
	event_dispatch();

	return (0);
}

