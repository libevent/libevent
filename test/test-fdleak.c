/*
 * Copyright (c) 2012 Ross Lagerwall <rosslagerwall@gmail.com>
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <signal.h>

#include "event2/event-config.h"
#include "event2/event.h"
#include "event2/bufferevent.h"
#include "event2/listener.h"
#include "event2/event_struct.h"

/* This test opens a server socket, and forks a child which connects to that
   server socket many times. It sets a low number for the max open file limit
   to catch any file descriptor leaks.
   This test will not work on Windows, at least until it gets fork(). */

#define PORT 31456

/* Number of requests to make. Setting this too high might result in the machine
   running out of ephemeral ports */
#define MAX_REQUESTS 2000

/* Pid of the child process */
static pid_t pid;

/* Provide storage for the address, both for the server & the clients */
static struct sockaddr_in sin;

/* Number of sucessful requests so far */
static int num_requests;

static void start_client(struct event_base *base);

/*
===============================================
Server functions
===============================================
*/

/* Read a byte from the client and write it back */
static void
server_read_cb(struct bufferevent *bev, void *ctx)
{
	unsigned char tmp;
	bufferevent_read(bev, &tmp, 1);
	bufferevent_write(bev, &tmp, 1);
}

/* Wait for an EOF and then free the bufferevent */
static void
server_write_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR) {
		perror("Error from bufferevent");
		exit(1);
	} else if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
		bufferevent_free(bev);
	}
}

/* Accept a client socket and set it up to for reading & writing */
static void
listener_accept_cb(struct evconnlistener *listener, evutil_socket_t sock,
                   struct sockaddr *addr, int len, void *ptr)
{
	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, sock,
                                                         BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev, server_read_cb, NULL, server_write_cb, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
}

/* Handle the child exiting. If the child exited with status 0,
   shutdown. Otherwise, exit with status 1 to indicate failure. */
static void
sigchld_handler(evutil_socket_t fd, short event, void *arg)
{
	int status;
	struct event *signal = arg;

	wait(&status);
	if (!WIFEXITED(status) || WEXITSTATUS(status)) {
		exit(1);
	}

	event_base_loopbreak(event_get_base(signal));
}

/* Start the server listening on PORT and set up a signal handler to handle
   the child exiting. */
static void
start_server(void)
{
	struct event sig_chld;
	struct event_base *base;
	struct evconnlistener *listener;

	base = event_base_new();
	if (base == NULL) {
		puts("Could not open event base!");
		exit(1);
	}

	event_assign(&sig_chld, base, SIGCHLD, EV_SIGNAL|EV_PERSIST,
	sigchld_handler, &sig_chld);
	event_add(&sig_chld, NULL);

	listener = evconnlistener_new_bind(base, listener_accept_cb, NULL,
	LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
	-1, (struct sockaddr *)&sin, sizeof(sin));
	if (listener == NULL) {
		perror("Could not create listener!");
		exit(1);
	}

	/* Signal the child to start sending connections. */
	kill(pid, SIGUSR1);

	event_base_dispatch(base);
}

/*
===============================================
Client functions
===============================================
*/

/* Check that the server sends back the same byte that the client sent.
   If MAX_REQUESTS have been reached, exit.
   Otherwise, start another client. */
static void
client_read_cb(struct bufferevent *bev, void *ctx)
{
	unsigned char tmp;
	struct event_base *base = bufferevent_get_base(bev);

	bufferevent_read(bev, &tmp, 1);
	if (tmp != 'A') {
		puts("Incorrect data received!");
		_Exit(1);
	}
	bufferevent_free(bev);

	num_requests++;
	if (num_requests == MAX_REQUESTS) {
		event_base_loopbreak(base);
	} else {
		start_client(base);
	}
}

/* Send a byte to the server. */
static void
client_write_cb(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		unsigned char tmp = 'A';
		bufferevent_write(bev, &tmp, 1);
	} else if (events & BEV_EVENT_ERROR) {
		puts("Client socket got error!");
		_Exit(1);
	}

	bufferevent_enable(bev, EV_READ);
}

/* Open a client socket to connect to localhost on PORT. */
static void
start_client(struct event_base *base)
{
	struct bufferevent *bev = bufferevent_socket_new(base, -1,
                                                         BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev, client_read_cb, NULL, client_write_cb, NULL);

	if (bufferevent_socket_connect(bev, (struct sockaddr *)&sin,
                                       sizeof(sin)) < 0) {
		perror("Could not connect!");
		bufferevent_free(bev);
		_Exit(1);
	}
}

/* Start the client loop. MAX_REQUESTS clients connect sequentially to the
   server, each one making a simple transfer before starting the next client. */
static void
start_client_loop(sigset_t *set)
{
	struct event_base *base = event_base_new();

	/* Wait for SIGUSR1 from the server to indicate that it is ready to
           listen. */
	sigwaitinfo(set, NULL);

	start_client(base);
	event_base_dispatch(base);
}

int
main(int argc, char **argv)
{
	sigset_t set;

	/* Set the fd limit to a low value so that any fd leak is caught without
	making many requests. */
	struct rlimit rl;
	rl.rlim_cur = rl.rlim_max = 20;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		perror("setrlimit");
		exit(1);
	}

	/* Block SIGUSR1 for both the client & the server. The client receives
           the signal using sigwaitinfo. */
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, NULL);

	/* Set up an address, used by both client & server. */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001);
	sin.sin_port = htons(PORT);

	/* Fork. The child starts the client loop and the parent starts the
	   server. */
	pid = fork();
	if (pid == -1) {
		perror("Could not fork!");
		exit(1);
	} else if (pid == 0) {
		start_client_loop(&set);
		_Exit(0);
	}

	start_server();

	return 0;
}
