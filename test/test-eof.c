/*
 * Compile with:
 * cc -I/usr/local/include -o time-test time-test.c -L/usr/local/lib -levent
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>

int test_okay = 1;
int called = 0;

void
read_cb(int fd, short event, void *arg)
{
	char buf[256];
	int len;

	len = read(fd, buf, sizeof(buf));

	printf("%s: read %d%s\n", __FUNCTION__,
	    len, len ? "" : " - means EOF");

	if (len) {
		if (!called)
			event_add(arg, NULL);
	} else if (called == 1)
		test_okay = 0;

	called++;
}

int
main (int argc, char **argv)
{
	struct event ev;
	char *test = "test string";
	int pair[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	
	write(pair[0], test, strlen(test)+1);
	shutdown(pair[0], SHUT_WR);

	/* Initalize the event library */
	event_init();

	/* Initalize one event */
	event_set(&ev, pair[1], EV_READ, read_cb, &ev);

	event_add(&ev, NULL);

	event_dispatch();

	return (test_okay);
}

