/*
 * This example program provides a simple multi-threaded server that listens for
 * TCP connections on the address provided.  When a connection arrives, receiver
 * and sender threads are spawned to handle echoing of data. Once a full line
 * (or MSG_CHARS_MAX) has arrived the connection will be closed, and threads
 * cleaned up.
 * It exits cleanly in response to a SIGINT (ctrl-c).
 *
 * Copyright (c) 2019 David Disseldorp
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#include <pthread.h>
#include <sys/queue.h>

#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/listener.h"
#include "event2/util.h"
#include "event2/thread.h"
#include "event2/event.h"

#ifdef NDEBUG
/* hack to avoid -Wunused-but-set-variable breakage */
#define ASSERT(x) do { (void)sizeof(x);} while (0)
#else
#include <assert.h>
#define ASSERT(x) assert(x)
#endif

/* maximum characters to handle in an echo message */
#define MSG_CHARS_MAX 100

struct echo_msg {
	char buf[MSG_CHARS_MAX];
	size_t buf_off;
	size_t buf_remaining;
	struct event *ipc_ev;	/* event for passing msg to sender */
};

/*
 * event_bases don't require locking, as libevent handles it internally
 */
struct recv_state {
	struct event_base *base;
	struct event_base *other_base;	/* sender thread base */
	int fd;
	struct event *exit_ev;	/* notify listener that we're done */
	struct echo_msg *cur_msg;
};

/*
 * sender thread state is stashed via pthread_setspecific() so that it can be
 * obained when the receiver thread triggers its msg_start_write() handler.
 */
static pthread_key_t send_state_key;
struct send_state {
	struct event_base *base;
	int fd;
	struct event *exit_ev;	/* notify listener that we're done */
	struct echo_msg *cur_msg;
	struct bufferevent *send_bev;
};

struct conn_state {
	LIST_ENTRY(conn_state) next;
	pthread_t recv_thread;
	pthread_t send_thread;
	struct recv_state rstate;
	struct send_state sstate;
	struct listener_state *ls;
};

struct listener_state {
	struct event_base *base;
	struct evconnlistener *listener;
	int num_conns;
	LIST_HEAD(cstate_q, conn_state) cstates;
	int exit_pending;
};

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	struct event_base *thread_base = bufferevent_get_base(bev);
	int ret;

	if (events & BEV_EVENT_EOF) {
		printf("connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		printf("connection error: %s\n", strerror(errno));
	}
	/* begin teardown of recv and send threads */
	ret = event_base_loopbreak(thread_base);
	ASSERT(ret == 0);
	/* bev free'd on teardown */
}

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
	struct send_state *sstate = user_data;
	struct evbuffer *output = bufferevent_get_output(bev);
	int ret;

	if (evbuffer_get_length(output) > 0) {
		return;
	}

	printf("sender thread: flushed msg, all done\n");
	ret = event_base_loopbreak(sstate->base);
	ASSERT(ret == 0);
	/* msg cleaned up in sender() exit path */
}

/* called in sender thread context */
static void
msg_start_write(evutil_socket_t fd, short what, void *user_data)
{
	struct echo_msg *msg = user_data;
	struct send_state *sstate = pthread_getspecific(send_state_key);
	struct bufferevent *send_bev;
	int ret;

	printf("sender thread: echoing %.*s\n", (int)msg->buf_off, msg->buf);
	ASSERT(sstate);
	sstate->cur_msg = msg;

	/*
	 * BEV_OPT_THREADSAFE isn't needed here, as this bev is only consumed by
	 * the sender thread.
	 */
	send_bev = bufferevent_socket_new(sstate->base, sstate->fd, 0);
	ASSERT(send_bev);
	bufferevent_setcb(send_bev, NULL, conn_writecb, conn_eventcb, sstate);
	bufferevent_enable(send_bev, EV_WRITE);
	bufferevent_disable(send_bev, EV_READ);

	sstate->send_bev = send_bev;
	ret = bufferevent_write(send_bev, msg->buf, msg->buf_off);
	ASSERT(ret == 0);

	/* recv->send thread IPC all done, cleanup */
	event_free(msg->ipc_ev);
}

/*
 * sender thread
 * - wait for echo_msg to arrive from receiver (via msg_start_write callback)
 * - send mesage to client
 * - free echo_msg
 * - exit
 */
static void *
sender(void *_sstate)
{
	struct send_state *sstate = _sstate;

	printf("sender thread: starting\n");
	pthread_setspecific(send_state_key, sstate);

	/* no events queued, so EVLOOP_NO_EXIT_ON_EMPTY is needed */
	event_base_loop(sstate->base, EVLOOP_NO_EXIT_ON_EMPTY);

	printf("sender thread: exiting\n");
	/* base cleaned up via listener callback */

	if (sstate->send_bev) {
		/* exiting after getting msg from receiver */
		bufferevent_free(sstate->send_bev);
		free(sstate->cur_msg);
	}

	evuser_trigger(sstate->exit_ev);
	pthread_exit(NULL);
}

static void
msg_read_done_cb(struct recv_state *rstate)
{
	struct echo_msg *msg = rstate->cur_msg;
	int ret;

	printf("receiver thread: messaging sender\n");
	rstate->cur_msg = NULL;

	/* caller is receiver thread. msg_start_write will be run by writer */
	msg->ipc_ev = evuser_new(rstate->other_base, msg_start_write, msg);
	ASSERT(msg->ipc_ev);
	evuser_trigger(msg->ipc_ev);

	ret = event_add(msg->ipc_ev, NULL);
	ASSERT(ret >= 0);

	/* tell receiver thread to exit */
	ret = event_base_loopbreak(rstate->base);
	ASSERT(ret == 0);
}

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

static void
conn_readcb(struct bufferevent *bev, void *user_data)
{
	struct recv_state *rstate = user_data;
	struct echo_msg *msg = rstate->cur_msg;
	struct evbuffer *input;
	size_t got_len;
	size_t read_len;
	size_t boff;

	input = bufferevent_get_input(bev);
	got_len = evbuffer_get_length(input);

	read_len = MIN(got_len, msg->buf_remaining);
	ASSERT(read_len > 0);

	got_len = bufferevent_read(bev, &msg->buf[msg->buf_off], read_len);
	/* short reads not accepted! */
	ASSERT(got_len == read_len);
	/* overflow sanity check */
	ASSERT(msg->buf_off < msg->buf_off + read_len);

	/* walk the buffer that we just got and check for newline */
	for (boff = msg->buf_off; boff < msg->buf_off + read_len; boff++) {
		if (msg->buf[boff] == '\n') {
			printf("receiver thread: got newline, finishing\n");
			/* stop after newline to truncate response */
			msg->buf_off = boff + 1;
			msg->buf_remaining = 0;
			msg_read_done_cb(rstate);
			return;
		}
	}

	msg->buf_off += read_len;
	msg->buf_remaining -= read_len;
	if (msg->buf_remaining == 0) {
		printf("receiver thread: got full message, finishing\n");
		msg_read_done_cb(rstate);
	}
}

/*
 * receiver thread:
 * - alloc echo_msg
 * - copy received client data from socket into echo_msg
 * - stop reading on newline or echo_msg full
 * - hand echo_msg to sender thread (via rstate.other_base) when done
 * - exit
 */
static void *
receiver(void *_rstate)
{
	struct recv_state *rstate = _rstate;
	struct bufferevent *recv_bev;
	struct echo_msg *msg;

	printf("receiver thread: starting\n");

	msg = malloc(sizeof(*msg));
	ASSERT(msg);
	memset(msg, 0, sizeof(*msg));
	msg->buf_remaining = MSG_CHARS_MAX;
	rstate->cur_msg = msg;

	/*
	 * BEV_OPT_THREADSAFE isn't needed here, as this bev is only consumed by
	 * the receiver thread.
	 */
	recv_bev = bufferevent_socket_new(rstate->base, rstate->fd, 0);
	ASSERT(recv_bev);
	bufferevent_setcb(recv_bev, conn_readcb, NULL, conn_eventcb, rstate);
	bufferevent_enable(recv_bev, EV_READ);
	bufferevent_disable(recv_bev, EV_WRITE);

	event_base_dispatch(rstate->base);

	printf("receiver thread: exiting\n");

	bufferevent_free(recv_bev);
	/* in case it hasn't been given to sender thread yet */
	free(rstate->cur_msg);
	evuser_trigger(rstate->exit_ev);
	pthread_exit(NULL);
}

static void
conn_exit(struct conn_state *cstate)
{
	struct listener_state *ls = cstate->ls;

	evutil_closesocket(cstate->rstate.fd);
	LIST_REMOVE(cstate, next);
	free(cstate);

	ls->num_conns--;
	printf("listener: cleaning up cstate %d\n", ls->num_conns);
	ASSERT(ls->num_conns >= 0);
	if (ls->exit_pending && (ls->num_conns == 0)) {
		printf("listener: pending exit now ready to proceed\n");
		event_base_loopbreak(ls->base);
	}
}

/* exit callbacks are called from the main process */
static void
recv_exit_cb(evutil_socket_t fd, short what, void *user_data)
{
	struct conn_state *cstate = user_data;
	int ret;

	ret = pthread_join(cstate->recv_thread, NULL);
	ASSERT(ret == 0);
	event_base_free(cstate->rstate.base);
	cstate->rstate.base = NULL;
	event_free(cstate->rstate.exit_ev);
	printf("listener: recv thread exit cb\n");

	if (cstate->sstate.base != NULL) {
		printf("listener: recv exit triggering sender exit\n");
		ret = event_base_loopbreak(cstate->sstate.base);
		ASSERT(ret == 0);
	} else {
		conn_exit(cstate);
	}
}

static void
send_exit_cb(evutil_socket_t fd, short what, void *user_data)
{
	struct conn_state *cstate = user_data;
	int ret;

	ret = pthread_join(cstate->send_thread, NULL);
	ASSERT(ret == 0);
	event_base_free(cstate->sstate.base);
	cstate->sstate.base = NULL;
	event_free(cstate->sstate.exit_ev);
	printf("listener: send thread exit cb\n");

	if (cstate->rstate.base != NULL) {
		printf("listener: send exit triggering receiver exit\n");
		ret = event_base_loopbreak(cstate->rstate.base);
		ASSERT(ret == 0);
	} else {
		conn_exit(cstate);
	}
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
	    struct sockaddr *sa, int socklen, void *user_data)
{
	struct listener_state *ls = user_data;
	struct conn_state *cstate;
	int ret;

	printf("listener: got connection %d\n", ls->num_conns);

	cstate = malloc(sizeof(*cstate));
	ASSERT(cstate);
	memset(cstate, 0, sizeof(*cstate));

	/* sender state */
	cstate->sstate.fd = fd;
	cstate->sstate.exit_ev = evuser_new(ls->base, send_exit_cb, cstate);
	ASSERT(cstate->sstate.exit_ev);
	ret = event_add(cstate->sstate.exit_ev, NULL);
	ASSERT(ret >= 0);
	cstate->sstate.base = event_base_new();
	ASSERT(cstate->sstate.base);

	/* receiver state */
	cstate->rstate.fd = fd;
	cstate->rstate.exit_ev = evuser_new(ls->base, recv_exit_cb, cstate);
	ASSERT(cstate->rstate.exit_ev);
	ret = event_add(cstate->rstate.exit_ev, NULL);
	ASSERT(ret >= 0);
	cstate->rstate.base = event_base_new();
	ASSERT(cstate->rstate.base);
	cstate->rstate.other_base = cstate->sstate.base;

	/* spawn receiver and sender threads to handle this connection */
	ret = pthread_create(&cstate->recv_thread, NULL,
				&receiver, &cstate->rstate);
	ASSERT(ret == 0);

	ret = pthread_create(&cstate->send_thread, NULL,
				&sender, &cstate->sstate);
	ASSERT(ret == 0);

	cstate->ls = ls;
	LIST_INSERT_HEAD(&ls->cstates, cstate, next);
	ls->num_conns++;
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct listener_state *ls = user_data;
	struct conn_state *cs;
	struct timeval delay = { 2, 0 };

	printf("listener: caught an interrupt signal, stopping...\n");
	evconnlistener_disable(ls->listener);

	/* tell conn_exit() to exit the main loop when all connections closed */
	ls->exit_pending = 1;

	if (ls->num_conns == 0) {
		/* no need to wait for connection teardown */
		event_base_loopbreak(ls->base);
		return;
	}

	LIST_FOREACH(cs, &ls->cstates, next) {
		/* receiver will tell sender to stop */
		event_base_loopbreak(cs->rstate.base);
	}

	/* tell the main base loop to exit unconditionally after a delay */
	event_base_loopexit(ls->base, &delay);
}

static void
usage(void)
{
	printf("Usage:\n"
	       "   pthread-echo-server <listen-addr:port>\n"
	       "Example:\n"
	       "   pthread-echo-server 127.0.0.1:9995\n");
}

int
main(int argc, char **argv)
{
	struct sockaddr_storage addr;
	struct sockaddr *sa;
	int len;
	struct event *signal_event;
	struct listener_state ls;
	int ret;

	if (argc != 2) {
		usage();
		exit(1);
	}

	memset(&addr, 0, sizeof(addr));
	len = sizeof(addr);
	ret = evutil_parse_sockaddr_port(argv[1], (struct sockaddr *)&addr,
					 &len);
	if (ret != 0) {
		usage();
		exit(1);
	}

	/* port left zero if unspecified */
	sa = (struct sockaddr *)&addr;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
		if (!sin->sin_port) {
			ret = -EINVAL;
		}
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
		ASSERT(sa->sa_family == AF_INET6);
		if (!sin6->sin6_port) {
			ret = -EINVAL;
		}
	}
	if (ret < 0) {
		printf("address %s missing port\n", argv[1]);
		exit(1);
	}

	pthread_key_create(&send_state_key, NULL);

	/* only pthread based threading currently supported */
	evthread_use_pthreads();

	memset(&ls, 0, sizeof(ls));
	ls.base = event_base_new();
	ASSERT(ls.base);
	LIST_INIT(&ls.cstates);

	/* LEV_OPT_THREADSAFE not needed, as only a single thread listens */
	ls.listener = evconnlistener_new_bind(ls.base, listener_cb, &ls,
				LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
				(struct sockaddr *)&addr, sizeof(addr));
	ASSERT(ls.listener);

	signal_event = evsignal_new(ls.base, SIGINT, signal_cb, &ls);
	ASSERT(signal_event);

	ret = event_add(signal_event, NULL);
	ASSERT(ret >= 0);

	event_base_dispatch(ls.base);

	if (ls.num_conns == 0) {
		printf("listener: all cleaned up and ready for exit...\n");
	} else {
		fprintf(stderr,
			"listener error: %d connections still remain on exit\n",
			ls.num_conns);
	}

	evconnlistener_free(ls.listener);
	event_free(signal_event);
	event_base_free(ls.base);

	return 0;
}
