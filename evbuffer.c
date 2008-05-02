/*
 * Copyright (c) 2002-2004 Niels Provos <provos@citi.umich.edu>
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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#endif

#include "event2/util.h"
#include "event2/bufferevent.h"
#include "event2/buffer.h"
#include "event2/bufferevent_struct.h"
#include "event2/event.h"
#include "log.h"
#include "mm-internal.h"
#include "bufferevent-internal.h"

/* prototypes */

static void bufferevent_read_pressure_cb(
	struct evbuffer *, size_t, size_t, void *);
static int bufferevent_process_filters(
	struct bufferevent_filter *, struct evbuffer *,
	enum bufferevent_filter_state);

static int
bufferevent_add(struct event *ev, int timeout)
{
	struct timeval tv, *ptv = NULL;

	if (timeout) {
		evutil_timerclear(&tv);
		tv.tv_sec = timeout;
		ptv = &tv;
	}

	return (event_add(ev, ptv));
}

/* 
 * This callback is executed when the size of the input buffer changes.
 * We use it to apply back pressure on the reading side.
 */

static void
bufferevent_read_pressure_cb(struct evbuffer *buf, size_t old, size_t now,
    void *arg) {
	struct bufferevent *bufev = arg;
	/* 
	 * If we are below the watermark then reschedule reading if it's
	 * still enabled.
	 */
	if (bufev->wm_read.high == 0 || now < bufev->wm_read.high) {
		evbuffer_setcb(buf, NULL, NULL);

		if (bufev->enabled & EV_READ)
			bufferevent_add(&bufev->ev_read, bufev->timeout_read);
	}
}

static void
bufferevent_read_closure(struct bufferevent *bufev, int progress)
{
	size_t len;

	bufferevent_add(&bufev->ev_read, bufev->timeout_read);

	/* nothing user visible changed? */
	if (!progress)
		return;

	/* See if this callbacks meets the water marks */
	len = EVBUFFER_LENGTH(bufev->input);
	if (bufev->wm_read.low != 0 && len < bufev->wm_read.low)
		return;

	/* For read pressure, we use the buffer exposed to the users.
	 * Filters can arbitrarily change the data that users get to see,
	 * in particular, a user might select a watermark that is smaller
	 * then what a filter needs to make progress.
	 */
	if (bufev->wm_read.high != 0 && len >= bufev->wm_read.high) {
		event_del(&bufev->ev_read);

		/* Now schedule a callback for us when the buffer changes */
		evbuffer_setcb(bufev->input,
		    bufferevent_read_pressure_cb, bufev);
	}

	/* Invoke the user callback - must always be called last */
	if (bufev->readcb != NULL)
		(*bufev->readcb)(bufev, bufev->cbarg);
}

static void
bufferevent_readcb(evutil_socket_t fd, short event, void *arg)
{
	struct bufferevent *bufev = arg;
	struct evbuffer *input;
	int res = 0, progress = 1;
	short what = EVBUFFER_READ;
	int howmuch = -1;

	if (event == EV_TIMEOUT) {
		what |= EVBUFFER_TIMEOUT;
		goto error;
	}

	if (TAILQ_FIRST(&bufev->input_filters) != NULL)
		input = TAILQ_FIRST(&bufev->input_filters)->buffer;
	else
		input = bufev->input;

	/*
	 * If we have a high watermark configured then we don't want to
	 * read more data than would make us reach the watermark.
	 */
	if (bufev->wm_read.high != 0) {
		howmuch = bufev->wm_read.high - EVBUFFER_LENGTH(input);
		/* we might have lowered the watermark, stop reading */
		if (howmuch <= 0) {
			event_del(&bufev->ev_read);
			evbuffer_setcb(input,
			    bufferevent_read_pressure_cb, bufev);
			return;
		}
	}

	res = evbuffer_read(input, fd, howmuch);

	if (res == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto reschedule;
		/* error case */
		what |= EVBUFFER_ERROR;
	} else if (res == 0) {
		/* eof case */
		what |= EVBUFFER_EOF;
	}

	if (TAILQ_FIRST(&bufev->input_filters) != NULL) {
		int state = BEV_NORMAL;
		if (what & EVBUFFER_EOF)
			state = BEV_FLUSH;
		/* XXX(niels): what to do about EVBUFFER_ERROR? */
		progress = bufferevent_process_filters(
			TAILQ_FIRST(&bufev->input_filters),
			bufev->input,
			state);

		/* propagate potential errors to the user */
		if (progress == -1) {
			res = -1;
			what |= EVBUFFER_ERROR;
		}
	}
	
	if (res <= 0)
		goto error;

	bufferevent_read_closure(bufev, progress);
	return;

 reschedule:
	bufferevent_add(&bufev->ev_read, bufev->timeout_read);
	return;

 error:
	(*bufev->errorcb)(bufev, what, bufev->cbarg);
}

static void
bufferevent_writecb(evutil_socket_t fd, short event, void *arg)
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
#ifndef WIN32
/*todo. evbuffer uses WriteFile when WIN32 is set. WIN32 system calls do not
 *set errno. thus this error checking is not portable*/
		    if (errno == EAGAIN ||
			errno == EINTR ||
			errno == EINPROGRESS)
			    goto reschedule;
		    /* error case */
		    what |= EVBUFFER_ERROR;

#else
				goto reschedule;
#endif

	    } else if (res == 0) {
		    /* eof case */
		    what |= EVBUFFER_EOF;
	    }
	    if (res <= 0)
		    goto error;
	}

	if (EVBUFFER_LENGTH(bufev->output) != 0)
		bufferevent_add(&bufev->ev_write, bufev->timeout_write);

	/*
	 * Invoke the user callback if our buffer is drained or below the
	 * low watermark.
	 */
	if (bufev->writecb != NULL &&
	    EVBUFFER_LENGTH(bufev->output) <= bufev->wm_write.low)
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
 *
 * Both read and write callbacks maybe NULL.  The error callback is not
 * allowed to be NULL and have to be provided always.
 */

struct bufferevent *
bufferevent_new(evutil_socket_t fd, evbuffercb readcb, evbuffercb writecb,
    everrorcb errorcb, void *cbarg)
{
	struct bufferevent *bufev;

	if ((bufev = mm_calloc(1, sizeof(struct bufferevent))) == NULL)
		return (NULL);

	if ((bufev->input = evbuffer_new()) == NULL) {
		mm_free(bufev);
		return (NULL);
	}

	if ((bufev->output = evbuffer_new()) == NULL) {
		evbuffer_free(bufev->input);
		mm_free(bufev);
		return (NULL);
	}

	event_set(&bufev->ev_read, fd, EV_READ, bufferevent_readcb, bufev);
	event_set(&bufev->ev_write, fd, EV_WRITE, bufferevent_writecb, bufev);

	bufferevent_setcb(bufev, readcb, writecb, errorcb, cbarg);

	/*
	 * Set to EV_WRITE so that using bufferevent_write is going to
	 * trigger a callback.  Reading needs to be explicitly enabled
	 * because otherwise no data will be available.
	 */
	bufev->enabled = EV_WRITE;

	TAILQ_INIT(&bufev->input_filters);
	TAILQ_INIT(&bufev->output_filters);

	return (bufev);
}

void
bufferevent_setcb(struct bufferevent *bufev,
    evbuffercb readcb, evbuffercb writecb, everrorcb errorcb, void *cbarg)
{
	bufev->readcb = readcb;
	bufev->writecb = writecb;
	bufev->errorcb = errorcb;

	bufev->cbarg = cbarg;
}

void
bufferevent_setfd(struct bufferevent *bufev, evutil_socket_t fd)
{
	struct bufferevent_filter *filter;

	event_del(&bufev->ev_read);
	event_del(&bufev->ev_write);

	event_assign(&bufev->ev_read, bufev->ev_base, fd, EV_READ, bufferevent_readcb, bufev);
	event_assign(&bufev->ev_write, bufev->ev_base, fd, EV_WRITE, bufferevent_writecb, bufev);

	/* we need to free all filter contexts and then init them again */
	TAILQ_FOREACH(filter, &bufev->input_filters, next) {
		if (filter->free_context)
			filter->free_context(filter->ctx);
		if (filter->init_context)
			filter->init_context(filter->ctx);
	}

	TAILQ_FOREACH(filter, &bufev->output_filters, next) {
		if (filter->free_context)
			filter->free_context(filter->ctx);
		if (filter->init_context)
			filter->init_context(filter->ctx);
	}

	/* might have to manually trigger event registration */
}

struct evbuffer *
bufferevent_input(struct bufferevent *bufev)
{
	return (bufev->input);
}

struct evbuffer *
bufferevent_output(struct bufferevent *bufev)
{
	return TAILQ_FIRST(&bufev->output_filters) != NULL ?
	    TAILQ_FIRST(&bufev->output_filters)->buffer :
	    bufev->output;
}

int
bufferevent_priority_set(struct bufferevent *bufev, int priority)
{
	if (event_priority_set(&bufev->ev_read, priority) == -1)
		return (-1);
	if (event_priority_set(&bufev->ev_write, priority) == -1)
		return (-1);

	return (0);
}

/* Closing the file descriptor is the responsibility of the caller */

void
bufferevent_free(struct bufferevent *bufev)
{
	struct bufferevent_filter *filter;

	event_del(&bufev->ev_read);
	event_del(&bufev->ev_write);

	evbuffer_free(bufev->input);
	evbuffer_free(bufev->output);

	/* free input and output filters */
	while ((filter = TAILQ_FIRST(&bufev->input_filters)) != NULL) {
		bufferevent_filter_remove(bufev, BEV_INPUT, filter);

		bufferevent_filter_free(filter);
	}
	
	while ((filter = TAILQ_FIRST(&bufev->output_filters)) != NULL) {
		bufferevent_filter_remove(bufev, BEV_OUTPUT, filter);

		bufferevent_filter_free(filter);
	}

	mm_free(bufev);
}
/*
 * Executes filters on the written data and schedules a network write if
 * necessary.
 */
static inline int
bufferevent_write_closure(struct bufferevent *bufev, int progress)
{
	/* if no data was written, we do not need to do anything */
	if (!progress)
		return (0);

	if (TAILQ_FIRST(&bufev->output_filters) != NULL) {
		progress = bufferevent_process_filters(
			TAILQ_FIRST(&bufev->output_filters),
			bufev->output, BEV_NORMAL);
		if (progress == -1) {
			(*bufev->errorcb)(bufev, EVBUFFER_ERROR, bufev->cbarg);
			return (-1);
		}
	}

	/* If everything is okay, we need to schedule a write */
	if (bufev->enabled & EV_WRITE)
		bufferevent_add(&bufev->ev_write, bufev->timeout_write);

	return (0);
}

/*
 * Returns 0 on success;
 *        -1 on failure.
 */

int
bufferevent_write(struct bufferevent *bufev, const void *data, size_t size)
{
	struct evbuffer *output;

	if (TAILQ_FIRST(&bufev->output_filters) != NULL)
		output = TAILQ_FIRST(&bufev->output_filters)->buffer;
	else
		output = bufev->output;

	if (evbuffer_add(output, data, size) == -1)
		return (-1);

	return (bufferevent_write_closure(bufev, size > 0));
}

int
bufferevent_write_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
	int len = EVBUFFER_LENGTH(buf);
	struct evbuffer *output;

	if (TAILQ_FIRST(&bufev->output_filters) != NULL)
		output = TAILQ_FIRST(&bufev->output_filters)->buffer;
	else
		output = bufev->output;

	if (evbuffer_add_buffer(output, buf) == -1)
		return (-1);
	
	return (bufferevent_write_closure(bufev, len > 0));
}

size_t
bufferevent_read(struct bufferevent *bufev, void *data, size_t size)
{
	return (evbuffer_remove(bufev->input, data, size));
}

int
bufferevent_read_buffer(struct bufferevent *bufev, struct evbuffer *buf)
{
	return (evbuffer_add_buffer(buf, bufev->input));
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

/*
 * Sets the water marks
 */

void
bufferevent_setwatermark(struct bufferevent *bufev, short events,
    size_t lowmark, size_t highmark)
{
	if (events & EV_READ) {
		bufev->wm_read.low = lowmark;
		bufev->wm_read.high = highmark;
	}

	if (events & EV_WRITE) {
		bufev->wm_write.low = lowmark;
		bufev->wm_write.high = highmark;
	}

	/* If the watermarks changed then see if we should call read again */
	bufferevent_read_pressure_cb(bufev->input,
	    0, EVBUFFER_LENGTH(bufev->input), bufev);
}

int
bufferevent_base_set(struct event_base *base, struct bufferevent *bufev)
{
	int res;

	bufev->ev_base = base;

	res = event_base_set(base, &bufev->ev_read);
	if (res == -1)
		return (res);

	res = event_base_set(base, &bufev->ev_write);
	return (res);
}

/*
 * Filtering stuff
 */

struct bufferevent_filter *
bufferevent_filter_new(
	void (*init_context)(void *ctx),
	void (*free_context)(void *ctx),
	enum bufferevent_filter_result (*process)(
		struct evbuffer *src, struct evbuffer *dst,
		enum bufferevent_filter_state flags, void *ctx), void *ctx)
{
	struct bufferevent_filter *filter;

	if ((filter = mm_malloc(sizeof(struct bufferevent_filter))) == NULL)
		return (NULL);

	if ((filter->buffer = evbuffer_new()) == NULL) {
		mm_free(filter);
		return (NULL);
	}

	filter->init_context = init_context;
	filter->free_context = free_context;
	filter->process = process;
	filter->ctx = ctx;

	return (filter);
}

void
bufferevent_filter_free(struct bufferevent_filter *filter)
{
	evbuffer_free(filter->buffer);
	mm_free(filter);
}

void
bufferevent_filter_insert(struct bufferevent *bufev,
    enum bufferevent_filter_type filter_type,
    struct bufferevent_filter *filter)
{
	switch (filter_type) {
	case BEV_INPUT:
		TAILQ_INSERT_TAIL(&bufev->input_filters, filter, next);
		break;
	case BEV_OUTPUT:
		TAILQ_INSERT_HEAD(&bufev->output_filters, filter, next);
		break;
	default:
		event_errx(1, "illegal filter type %d", filter_type);
	}

	if (filter->init_context)
		filter->init_context(filter->ctx);
}

void
bufferevent_filter_remove(struct bufferevent *bufev,
    enum bufferevent_filter_type filter_type,
    struct bufferevent_filter *filter)
{
	switch (filter_type) {
	case BEV_INPUT:
		TAILQ_REMOVE(&bufev->input_filters, filter, next);
		break;
	case BEV_OUTPUT:
		TAILQ_REMOVE(&bufev->output_filters, filter, next);
		break;
	default:
		event_errx(1, "illegal filter type %d", filter_type);
	}

	evbuffer_drain(filter->buffer, -1);

	if (filter->free_context)
		filter->free_context(filter->ctx);
		
}

static int
bufferevent_process_filters(
	struct bufferevent_filter *filter, struct evbuffer *final,
	enum bufferevent_filter_state state)
{
	struct evbuffer *src, *dst;
	struct bufferevent_filter *next;
	int len = EVBUFFER_LENGTH(final);

	for (; filter != NULL; filter = next) {
		int res;

		next = TAILQ_NEXT(filter, next);
		src = filter->buffer;
		dst = next != NULL ? next->buffer : final;

		res = (*filter->process)(src, dst, state, filter->ctx);

		/* an error causes complete termination of the bufferevent */
		if (res == BEV_ERROR)
			return (-1);

		/* a read filter indicated that it cannot produce
		 * further data, we do not need to invoke any
		 * subsequent filters. Unless, a flush or something
		 * similar was specifically requested.
		 */
		if (res == BEV_NEED_MORE && state == BEV_NORMAL)
			return (0);
	}

	/* we made user visible progress if the buffer size changed */
	return (EVBUFFER_LENGTH(final) != len);
}

int
bufferevent_trigger_filter(struct bufferevent *bufev,
    struct bufferevent_filter *filter, int iotype,
    enum bufferevent_filter_state state)
{
	struct evbuffer *dst = iotype == BEV_INPUT ?
	    bufev->input : bufev->output;
	int progress;

	/* trigger all filters if filter is not specified */
	if (filter == NULL) {
		struct bufferevent_filterq *head = BEV_INPUT ?
		    &bufev->input_filters : &bufev->output_filters;
		filter = TAILQ_FIRST(head);
	}

	progress = bufferevent_process_filters(filter, dst, state);
	if (progress == -1) {
		(*bufev->errorcb)(bufev, EVBUFFER_ERROR, bufev->cbarg);
		return (-1);
	}

	switch (iotype) {
	case BEV_INPUT:
		bufferevent_read_closure(bufev, progress);
		break;
	case BEV_OUTPUT:
		if (progress && (bufev->enabled & EV_WRITE))
			bufferevent_add(
				&bufev->ev_write, bufev->timeout_write);
		break;
	default:
		event_errx(1, "Illegal bufferevent iotype: %d", iotype);
	}

	return (0);
}
