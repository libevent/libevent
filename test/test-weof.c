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
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>

int pair[2];
int test_okay = 1;
int called = 0;

void
write_cb(int fd, short event, void *arg)
{
	char *test = "test string";
	int len;

	len = write(fd, test, strlen(test) + 1);

	printf("%s: write %d%s\n", __FUNCTION__,
	    len, len ? "" : " - means EOF");

	if (len > 0) {
		if (!called)
			event_add(arg, NULL);
		close(pair[0]);
	} else if (called == 1)
		test_okay = 0;

	called++;
}

int
main (int argc, char **argv)
{
	struct event ev;

	if (signal(SIGPIPE, SIG_IGN) == SIG_IGN)
		return (1);

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1)
		return (1);

	/* Initalize the event library */
	event_init();

	/* Initalize one event */
	event_set(&ev, pair[1], EV_WRITE, write_cb, &ev);

	event_add(&ev, NULL);

	event_dispatch();

	return (test_okay);
}

