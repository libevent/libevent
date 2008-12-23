/*
 * Copyright (c) 2007 Niels Provos <provos@citi.umich.edu>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include "misc.h"
#endif
#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else 
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "event-internal.h"
#include "evmap.h"
#include "mm-internal.h"

#define GET_SLOT(map, slot, msize) (void *)((char *)(map)->entries + (slot)*(msize))

static void *
evmap_get_head(struct event_map *map, int slot, int msize, void (*ctor)(void *))
{
	if (map->nentries <= slot) {
		int i;
		int nentries = map->nentries ? map->nentries : 32;
		void *tmp;

		while (nentries <= slot)
			nentries <<= 1;

		tmp = mm_realloc(map->entries, nentries * msize);
		if (tmp == NULL)
			return (NULL);
		
		for (i = map->nentries; i < nentries; ++i)
			(*ctor)((char *)tmp + i * msize);

		map->nentries = nentries;
		map->entries = tmp;
	}

	return (GET_SLOT(map, slot, msize));
}


void
evmap_clear(struct event_map *ctx)
{
	ctx->nentries = 0;
	if (ctx->entries != NULL) {
		mm_free(ctx->entries);
		ctx->entries = NULL;
	}
}

/* code specific to file descriptors */

struct evmap_io {
	struct event_list events;
	unsigned int nread;
	unsigned int nwrite;
};

static void
evmap_io_init(void *arg)
{
	struct evmap_io *entry = arg;

	TAILQ_INIT(&entry->events);
	entry->nread = 0;
	entry->nwrite = 0;
}


int
evmap_io_add(struct event_base *base, int fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_map *io = &base->io;
	struct evmap_io *ctx = NULL;
	int nread, nwrite;
	short res = 0, old = 0;

	if (fd >= io->nentries) {
		ctx = evmap_get_head(
			io, fd, sizeof(struct evmap_io), evmap_io_init);
		if (ctx == NULL)
			return (-1);
	} else {
		ctx = GET_SLOT(io, fd, sizeof(struct evmap_io));
	}

	nread = ctx->nread;
	nwrite = ctx->nwrite;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;

	if (ev->ev_events & EV_READ) {
		if (++nread == 1)
			res |= EV_READ;
	}
	if (ev->ev_events & EV_WRITE) {
		if (++nwrite == 1)
			res |= EV_WRITE;
	}

	if (res) {
		/* XXX(niels): we cannot mix edge-triggered and
		 * level-triggered, we should probably assert on
		 * this. */
		if (evsel->add(base, ev->ev_fd,
			old, (ev->ev_events & EV_ET) | res) == -1)
			return (-1);
	}

	ctx->nread = nread;
	ctx->nwrite = nwrite;
	TAILQ_INSERT_TAIL(&ctx->events, ev, ev_io_next);

	return (0);
}

int
evmap_io_del(struct event_base *base, int fd, struct event *ev)
{
	const struct eventop *evsel = base->evsel;
	struct event_map *io = &base->io;
	struct evmap_io *ctx;
	int nread, nwrite;
	short res = 0, old = 0;

	if (fd >= io->nentries)
		return (-1);
	
	ctx = GET_SLOT(io, fd, sizeof(struct evmap_io));

	nread = ctx->nread;
	nwrite = ctx->nwrite;

	if (nread)
		old |= EV_READ;
	if (nwrite)
		old |= EV_WRITE;

	if (ev->ev_events & EV_READ) {
		if (--nread == 0)
			res |= EV_READ;
		assert(nread >= 0);
	}
	if (ev->ev_events & EV_WRITE) {
		if (--nwrite == 0)
			res |= EV_WRITE;
		assert(nwrite >= 0);
	}

	if (res) {
		if (evsel->del(base, ev->ev_fd, old, res) == -1)
			return (-1);
	}

	ctx->nread = nread;
	ctx->nwrite = nwrite;
	TAILQ_REMOVE(&ctx->events, ev, ev_io_next);

	return (0);
}

void
evmap_io_active(struct event_base *base, int fd, short events)
{
	struct event_map *io = &base->io;
	struct evmap_io *ctx;
	struct event *ev;

	assert(fd < io->nentries);
	ctx = GET_SLOT(io, fd, sizeof(struct evmap_io));

	TAILQ_FOREACH(ev, &ctx->events, ev_io_next) {
		if (ev->ev_events & events)
			event_active(ev, ev->ev_events & events, 1);
	}
}

/* code specific to signals */

struct evmap_signal {
	struct event_list events;
};

static void
evmap_signal_init(void *arg)
{
	struct evmap_signal *entry = arg;

	TAILQ_INIT(&entry->events);
}


int
evmap_signal_add(struct event_base *base, int sig, struct event *ev)
{
	const struct eventop *evsel = base->evsigsel;
	struct event_map *map = &base->sigmap;
	struct evmap_signal *ctx = NULL;

	if (sig >= map->nentries) {
		ctx = evmap_get_head(
			map, sig, sizeof(struct evmap_signal),
			evmap_signal_init);
		if (ctx == NULL)
			return (-1);
	} else {
		ctx = GET_SLOT(map, sig, sizeof(struct evmap_signal));
	}

	if (TAILQ_EMPTY(&ctx->events)) {
		if (evsel->add(base, EVENT_SIGNAL(ev), 0, EV_SIGNAL) == -1)
			return (-1);
	}

	TAILQ_INSERT_TAIL(&ctx->events, ev, ev_signal_next);

	return (0);
}

int
evmap_signal_del(struct event_base *base, int sig, struct event *ev)
{
	const struct eventop *evsel = base->evsigsel;
	struct event_map *map = &base->sigmap;
	struct evmap_signal *ctx;

	if (sig >= map->nentries)
		return (-1);
	
	ctx = GET_SLOT(map, sig, sizeof(struct evmap_signal));

	if (TAILQ_FIRST(&ctx->events) == TAILQ_LAST(&ctx->events, event_list)) {
		if (evsel->del(base, EVENT_SIGNAL(ev), 0, EV_SIGNAL) == -1)
			return (-1);
	}

	TAILQ_REMOVE(&ctx->events, ev, ev_signal_next);

	return (0);
}

void
evmap_signal_active(struct event_base *base, int sig, int ncalls)
{
	struct event_map *map = &base->sigmap;
	struct evmap_signal *ctx;
	struct event *ev;

	assert(sig < map->nentries);
	ctx = GET_SLOT(map, sig, sizeof(struct evmap_signal));

	TAILQ_FOREACH(ev, &ctx->events, ev_signal_next)
		event_active(ev, EV_SIGNAL, ncalls);
}
