/*
 * Copyright (c) 2024 Andy Pan <i@andypan.me>
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

#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/thread.h>
#include "event-internal.h"

struct timeval timeout = {3, 0};
char data[] = "Hello, World!";
int read_called = 0;

#define MAGIC_FD 42 // The old magic number used by kqueue EVFILT_USER

static void
read_cb(evutil_socket_t fd, short event, void *arg)
{
	char buf[16];
	ev_ssize_t n;

	if (EV_TIMEOUT & event) {
		printf("%s: Timeout!\n", __func__);
		exit(1);
	}

	if ((EV_READ & event) == 0) {
		printf("%s: expected EV_READ for pipe but got nothing\n", __func__);
		exit(1);
	}

	n = read(fd, buf, sizeof(buf));
	if (n == -1) {
		printf("%s: read error on pipe\n", __func__);
		exit(1);
	}
	buf[n] = '\0';
	if (strcmp(buf, data) != 0) {
		printf("%s: read unexpected data from pipe: %s\n", __func__, buf);
		exit(1);
	}
	printf("%s: read the expected data from pipe successfully\n", __func__);
	assert(read_called == 0);
	read_called++;
}

static void*
trigger_kq(void *arg)
{
	struct event_base *base = arg;
	/* This function is called to notify the main thread
	 * to scan for new events immediately by issuing a EVFILT_USER event.
	 * We need to do it in a separate thread, otherwise it won't be issued.
	 */
	event_base_loopcontinue(base);
	return NULL;
}

static void
notify_cb(evutil_socket_t fd, short events, void *arg)
{
	/* To ensure that the EVFILT_USER event is issued,
	 * we need to do it in outside the main thread.
	 */
	pthread_t trigger;
	pthread_create(&trigger, NULL, trigger_kq, arg);
	pthread_join(trigger, NULL);
}

static void
write_cb(evutil_socket_t fd, short events, void *arg)
{
	int *wfd = arg;
	/* Write the data to the pipe */
	if (write(*wfd, data, strlen(data)+1) == -1) {
		printf("%s: write data to pipe error\n", __func__);
		exit(1);
	}
	printf("%s: write data to pipe successfully\n", __func__);
}

static void
exit_cb(int sock, short what, void *arg)
{
    struct event_base *base = arg;
    event_base_loopbreak(base);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct event_config *cfg;
	const char **methods;
	struct event *ev_notify, *ev_read, *ev_write, *ev_exit;
	struct timeval tv_notify, tv_write, tv_exit;
	int pipefd[2];

	/* Create a pair of pipe */
	int r;
	do {
		r = pipe(pipefd);
		if (r == -1) {
			printf("pipe error\n");
			return EXIT_FAILURE;
		}
		if (pipefd[0] != MAGIC_FD && pipefd[1] != MAGIC_FD)
			break;
		close(pipefd[0]);
		close(pipefd[1]);
		r = -1;
	} while (r != 0);

	/* Redirect the read end of the pipe to the magic number of EVFILT_USER,
	 * verifying that the EVFILT_READ event is not tampered by the EVFILT_USER event.
	 */
	if (dup2(pipefd[0], MAGIC_FD) == -1) {
		printf("dup2 failed\n");
		return EXIT_FAILURE;
	}
	close(pipefd[0]);
	pipefd[0] = MAGIC_FD;

	/* Sets up Libevent for use with Pthreads locking and thread ID functions.
	 * This is required for event_base_loopcontinue() to work properly.
	 */
	evthread_use_pthreads();

	cfg = event_config_new();
	methods = event_get_supported_methods();
	for (size_t i = 0; methods[i] != NULL; ++i) {
		if (strcmp(methods[i], "kqueue"))
			event_config_avoid_method(cfg, methods[i]);
	}
	base = event_base_new_with_config(cfg);
	event_config_free(cfg);

	/* Triggering a EVFILT_USER event is expected to not tamper EVFILT_READ on the same indent. */
	ev_notify = evtimer_new(base, notify_cb, base);
	tv_notify.tv_sec = 0;
	tv_notify.tv_usec = 0;
	evtimer_add(ev_notify, &tv_notify);
	ev_write = evtimer_new(base, write_cb, &pipefd[1]);
	tv_write.tv_sec = 1;
	tv_write.tv_usec = 0;
	evtimer_add(ev_write, &tv_write);
	ev_exit = evtimer_new(base, exit_cb, base);
	tv_exit.tv_sec = 5; // exit after 5 seconds, after the timeout.
	tv_exit.tv_usec = 0;
	evtimer_add(ev_exit, &tv_exit);

	/* Start dispatching events */
	ev_read = event_new(base, MAGIC_FD, EV_READ | EV_TIMEOUT, read_cb, event_self_cbarg());
	event_add(ev_read, &timeout);
	event_base_dispatch(base);

	// The read_cb is expected to be called once.
	assert(read_called == 1);

	/* Clean up the resources */
	event_free(ev_read);
	event_free(ev_notify);
	event_free(ev_write);
	event_free(ev_exit);
	close(pipefd[0]);
	close(pipefd[1]);
	event_base_free(base);
	return EXIT_SUCCESS;
}
