#include <event2/event-config.h>

#include <stdio.h>
#ifdef EVENT__HAVE_ERROR_H
#include <error.h>
#endif /* error.h */
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>

#include "event2/event.h"
#include "event2/bufferevent.h"

#ifndef IO_URING_SQES
#define IO_URING_SQES 16
#endif

#ifndef PKTSIZE
#define PKTSIZE 4096
#endif

#ifndef EV_WATERMARK
#define EV_WATERMARK 1
#endif

int bflags = -1;

typedef struct {
	int id;
	int tick;
	size_t nread;
	size_t nwrite;
	int sockets[2];
	pthread_t thread;
	struct event *tev;
	char buffer[PKTSIZE];
	struct event_base *base;
	struct bufferevent *bev;
} thread_data_t;

#ifndef EVENT__HAVE_ERROR_H
static void
error(int status, int code, const char *msg)
{
	errno = code;
	perror(msg);
	exit(status);
}
#endif /* no error.h */

static void
client_read(struct bufferevent *bev, void *arg)
{
	char expected[PKTSIZE];
	thread_data_t *td = arg;

	memset(expected, 'b', PKTSIZE);

	if (bufferevent_read(td->bev, td->buffer, PKTSIZE) != PKTSIZE)
		error(1, errno, "client read error");

	if (memcmp(td->buffer, expected, PKTSIZE))
		error(1, ENODATA, "client-side unexpected data");

	td->nread++;
}

static void
client_write(struct bufferevent *bev, void *arg)
{
	thread_data_t *td = arg;

	memset(td->buffer, 'a', PKTSIZE);

	if (bufferevent_write(td->bev, td->buffer, PKTSIZE))
		error(1, errno, "client write error");

	td->nwrite++;
}

static void
client_timer(evutil_socket_t fd, short what, void *arg)
{
	thread_data_t *td = arg;
	size_t delta = (td->nread > td->nwrite ? td->nread - td->nwrite
					   : td->nwrite - td->nread);
	printf("client %d [%d] (thread@%lx): %lu reads, %lu writes, delta %lu\n",
		td->id, ++td->tick, (long)pthread_self(), td->nread, td->nwrite, delta);
}

static void *
client(void *arg)
{
	thread_data_t *td = arg;
	struct timeval tv = {1, 0};
	struct event_config *cfg = event_config_new();

	if (!cfg)
		error(1, ENOMEM, "can't create event base config");

	if (bflags == -1)
		abort();
	if (bflags & BEV_OPT_IO_URING) {
		event_config_set_flag(cfg, EVENT_BASE_FLAG_IO_URING);
		event_config_set_io_uring_parameters(cfg, IO_URING_SQES, &tv);
	}

	td->base = event_base_new_with_config(cfg);
	if (!td->base)
		error(1, errno, "can't create event base");

	td->bev = bufferevent_socket_new(td->base, td->sockets[1], bflags);
	if (!td->bev)
		error(1, errno, "can't create buffer event");

	bufferevent_setcb(td->bev, client_read, client_write, NULL, td);
#ifdef EV_WATERMARK
	bufferevent_setwatermark(td->bev, EV_READ | EV_WRITE, PKTSIZE, PKTSIZE);
#endif /* EV_WATERMARK */
	bufferevent_enable(td->bev, EV_READ | EV_WRITE);

	/* Used to report I/O stats once per second. */
	td->tev = event_new(td->base, -1, EV_PERSIST, client_timer, td);
	if (!td->tev)
		error(1, errno, "can't create timer event");
	event_add(td->tev, &tv);

	/* Run client main loop. */
	event_base_dispatch(td->base);
	return NULL;
}

static void
server_read(struct bufferevent *bev, void *arg)
{
	char expected[PKTSIZE], buffer[PKTSIZE];

	memset(expected, 'a', PKTSIZE);

	if (bufferevent_read(bev, buffer, PKTSIZE) != PKTSIZE)
		error(1, errno, "server read error");

	if (memcmp(buffer, expected, PKTSIZE))
		error(1, ENODATA, "server-side unexpected data");
}

static void
server_write(struct bufferevent *bev, void *arg)
{
	char buffer[PKTSIZE];

	memset(buffer, 'b', PKTSIZE);

	if (bufferevent_write(bev, buffer, PKTSIZE))
		error(1, errno, "server write error");
}

int
main(int argc, char *argv[])
{
	thread_data_t *td;
	struct event_base *base;
	struct bufferevent **bevs;
	struct timeval tv = {1, 0};
	int i, nr = (argc > 1 ? atoi(argv[1]) : 1);
	struct event_config *cfg = event_config_new();

	if (!cfg)
		error(1, ENOMEM, "can't create event base config");

	if (getenv("USE_IO_URING")) {
		event_config_set_flag(cfg, EVENT_BASE_FLAG_IO_URING);
		event_config_set_io_uring_parameters(cfg, IO_URING_SQES, &tv);
		bflags = BEV_OPT_IO_URING;
	} else
		bflags = 0;

	base = event_base_new_with_config(cfg);
	if (!base)
		error(1, errno, "can't create event base");

	td = calloc(nr, sizeof(thread_data_t));
	if (!td)
		error(1, ENOMEM, "can't allocate thread data");

	bevs = calloc(nr, sizeof(struct bufferevent *));
	if (!bevs)
		error(1, ENOMEM, "can't allocate buffer events");

	for (i = 0; i < nr; i++) {
		td[i].id = i;

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, td[i].sockets) < 0)
			error(1, errno, "can't create socket pair");

		bevs[i] = bufferevent_socket_new(base, td[i].sockets[0], bflags);
		if (!bevs[i])
			error(1, errno, "can't create buffer event");

		bufferevent_setcb(bevs[i], server_read, server_write, NULL, NULL);
#ifdef EV_WATERMARK
		bufferevent_setwatermark(bevs[i], EV_READ | EV_WRITE, PKTSIZE, PKTSIZE);
#endif /* EV_WATERMARK */
		bufferevent_enable(bevs[i], EV_READ | EV_WRITE);

		if (pthread_create(&td[i].thread, NULL, client, td + i))
			error(1, errno, "can't create thread");
	}

	/* Run server main loop. */
	event_base_dispatch(base);

	return 0;
}
