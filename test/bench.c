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
#include <sys/resource.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>

static int count;

void
read_cb(int fd, short which, void *arg)
{
	struct event *ev = arg;
	u_char ch;
	
	count += read(fd, &ch, sizeof(ch));
}

struct timeval *
run_once(struct event *events, int *pipes, int num_pipes, int num_active)
{
	int *cp, i, space;
	static struct timeval ts, te;

	for (cp = pipes, i = 0; i < num_pipes; i++, cp += 2) {
		event_del(&events[i]);
		event_set(&events[i], cp[0], EV_READ, read_cb, &events[i]);
		event_add(&events[i], NULL);
	}

	event_loop(EVLOOP_ONCE|EVLOOP_NONBLOCK);

	space = num_pipes/num_active;
	space = space * 2;
	for (i = 0; i < num_active; i++)
		write(pipes[i * space + 1], "e", 1);

	count = 0;

	gettimeofday(&ts, NULL);
	event_loop(EVLOOP_ONCE);
	gettimeofday(&te, NULL);

	timersub(&te, &ts, &te);

	if (count != num_active) {
		fprintf(stderr, "Fired only %d of %d\n", count, num_active);
		return (NULL);
	}

	return (&te);
}

int
main (int argc, char **argv)
{
	struct rlimit rl;
	int num_pipes, num_active, i;
	struct event *events;
	struct timeval *tv;
	int *pipes, *cp;
	extern char *optarg;
	int c;

	num_pipes = 100;
	num_active = 1;
	while ((c = getopt(argc, argv, "n:a:")) != -1) {
		switch (c) {
		case 'n':
			num_pipes = atoi(optarg);
			break;
		case 'a':
			num_active = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Illegal argument \"%c\"\n", c);
			exit(1);
		}
	}

	rl.rlim_cur = rl.rlim_max = num_pipes * 2 + 50;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		perror("setrlimit"); 
		exit(1);
	}

	events = calloc(num_pipes, sizeof(struct event));
	pipes = calloc(num_pipes * 2, sizeof(int));
	if (events == NULL || pipe == NULL) {
		perror("malloc");
		exit(1);
	}

	event_init();

	for (cp = pipes, i = 0; i < num_pipes; i++, cp += 2) {
		if (pipe(cp) == -1) {
			perror("pipe");
			exit(1);
		}
	}

	for (i = 0; i < 25; i++) {
		tv = run_once(events, pipes, num_pipes, num_active);
		if (tv == NULL)
			exit(1);
		fprintf(stdout, "%ld\n",
		    tv->tv_sec * 1000000L + tv->tv_usec);
	}

	exit(0);
}



