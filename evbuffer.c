/*
 * Copyright (c) 2002-2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#include <unistd.h>

#include "event.h"

static int
bufferevent_add(struct event *ev, int timeout)
{
	struct timeval tv, *ptv = NULL;

	if (timeout) {
		timerclear(&tv);
		tv.tv_sec = timeout;
		ptv = &tv;
	}

	return (event_add(ev, ptv));
}

static void
bufferevent_readcb(int fd, short event, void *arg)
{
	struct bufferevent *bufev = arg;
	int res = 0;
	short what = EVBUFFER_READ;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto error;
	}

	res = evbuffer_read(bufev->input, fd, -1);
	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto reschedule;
		/* error case */
		what |= EVBUFFER_ERROR;
	} else if (res == 0) {
		/* eof case */
		what |= EVBUFFER_EOF;
	}

	if (res <= 0)
		goto error;

	bufferevent_add(&bufev->ev_read, bufev->timeout_read);

	/* Invoke the user callback - must always be called last */
	(*bufev->readcb)(bufev, bufev->cbarg);
	return;

 reschedule:
	bufferevent_add(&bufev->ev_read, bufev->timeout_read);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
bufferevent_writecb(int fd, short event, void *arg)
{
	struct bufferevent *bufev = arg;
	int res = 0;
	short what = EVBUFFER_WRITE;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto error;
	}

	if (EVBUFFER_LENGTH(bufev->output)) {
	    res = evbuffer_write(bufev->output, fd);
	    if (res == -1) {
		    if (errno == EAGAIN || errno == EINTR)
			    goto reschedule;
		    /* error case */
		    what |= EVBUFFER_ERROR;
	    } else if (res == 0) {
		    /* eof case */
		    what |= EVBUFFER_EOF;
	    }
	    if (res <= 0)
		    goto error;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0)
		bufferevent_add(&bufev->ev_write, bufev->timeout_write);

	/* Invoke the user callback if our buffer is drained */
	if (EVBUFFER_LENGTH(bufev->output) == 0)
		(*bufev->writecb)(bufev, bufev->cbarg);

	return;

 reschedule:
	if (EVBUFFER_LENGTH(bufev->output) != 0)
		bufferevent_add(&bufev->ev_write, bufev->timeout_write);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

/*
 * Create a new buffered event object.
 *
 * The read callback is invoked whenever we read new data.
 * The write callback is invoked whenever the output buffer is drained.
 * The error callback is invoked on a write/read error or on EOF.
 */

struct bufferevent *
bufferevent_new(int fd, evbuffercb readcb, evbuffercb writecb,
    everrorcb errorcb, void *cbarg)
{
	struct bufferevent *bufev;

	if ((bufev = calloc(1, sizeof(struct bufferevent))) == NULL)
		return (NULL);

	if ((bufev->input = evbuffer_new()) == NULL) {
		free(bufev);
		return (NULL);
	}

	if ((bufev->output = evbuffer_new()) == NULL) {
		evbuffer_free(bufev->input);
		free(bufev);
		return (NULL);
	}

	event_set(&bufev->ev_read, fd, EV_READ, bufferevent_readcb, bufev);
	event_set(&bufev->ev_write, fd, EV_WRITE, bufferevent_writecb, bufev);

	bufev->readcb = readcb;
	bufev->writecb = writecb;
	bufev->errorcb = errorcb;

	bufev->cbarg = cbarg;

	bufev->enabled = EV_READ | EV_WRITE;

	return (bufev);
}

void
bufferevent_free(struct bufferevent *bufev)
{
	event_del(&bufev->ev_read);
	event_del(&bufev->ev_write);

	evbuffer_free(bufev->input);
	evbuffer_free(bufev->output);

	free(bufev);
}

/*
 * Returns 0 on success;
 *        -1 on failure.
 */

int
bufferevent_write(struct bufferevent *bufev, void *data, size_t size)
{
	int res;

	res = evbuffer_add(bufev->output, data, size);

	if (res == -1)
		return (res);

	/* If everything is okay, we need to schedule a write */
	if (size > 0 && (bufev->enabled & EV_WRITE))
		bufferevent_add(&bufev->ev_write, bufev->timeout_write);

	return (res);
}

int
bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
	int res;

	res = bufferevent_write(bufev, buf->buffer, buf->off);
	if (res != -1)
		evbuffer_drain(buf, buf->off);

	return (res);
}

size_t
bufferevent_read(struct bufferevent *bufev, void *data, size_t size)
{
	struct evbuffer *buf = bufev->input;

	if (buf->off < size)
		size = buf->off;

	/* Copy the available data to the user buffer */
	memcpy(data, buf->buffer, size);

	if (size)
		evbuffer_drain(buf, size);

	return (size);
}

int
bufferevent_enable(struct bufferevent *bufev, short event)
{
	if (event & EV_READ) {
		if (bufferevent_add(&bufev->ev_read, bufev->timeout_read) == -1)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (bufferevent_add(&bufev->ev_write, bufev->timeout_write) == -1)
			return (-1);
	}

	bufev->enabled |= event;
	return (0);
}

int
bufferevent_disable(struct bufferevent *bufev, short event)
{
	if (event & EV_READ) {
		if (event_del(&bufev->ev_read) == -1)
			return (-1);
	}
	if (event & EV_WRITE) {
		if (event_del(&bufev->ev_write) == -1)
			return (-1);
	}

	bufev->enabled &= ~event;
	return (0);
}

/*
 * Sets the read and write timeout for a buffered event.
 */

void
bufferevent_settimeout(struct bufferevent *bufev,
    int timeout_read, int timeout_write) {
	bufev->timeout_read = timeout_read;
	bufev->timeout_write = timeout_write;
}
