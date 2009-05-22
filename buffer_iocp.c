/*
 * Copyright (c) 2009 Niels Provos and Nick Mathewson
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

/**
   @file buffer_iocp.c

   This module implements overlapped read and write functions for evbuffer
   objects on Windows.
*/

#include "event2/buffer.h"
#include "event2/buffer_compat.h"
#include "event2/util.h"
#include "event2/thread.h"
#include "event-config.h"
#include "util-internal.h"
#include "evthread-internal.h"
#include "evbuffer-internal.h"
#include "iocp-internal.h"
#include "mm-internal.h"

#include <windows.h>
#include <assert.h>
#include <stdio.h>

#define MAX_WSABUFS 16

/** Wrapper for an OVERLAPPED that holds the necessary info to notice
    when an overlapped read or write is done on an evbuffer.
 **/
struct buffer_overlapped {
	struct event_overlapped event_overlapped;

	/** The first pinned chain in the buffer. */
	struct evbuffer_chain *first_pinned;
	/** The buffer itself. */
	struct evbuffer_overlapped *buf;
	/** How many chains are pinned; how many of the fields in buffers
	 * are we using. */
	int n_buffers;
	WSABUF buffers[MAX_WSABUFS];
};

/** An evbuffer that can handle overlapped IO. */
struct evbuffer_overlapped {
	struct evbuffer buffer;
	/** The socket that we're doing overlapped IO on. */
	evutil_socket_t fd;
	/** True iff we have scheduled a write. */
	unsigned write_in_progress : 1;
	/** True iff we have scheduled a read. */
	unsigned read_in_progress : 1;

	struct buffer_overlapped read_info;
	struct buffer_overlapped write_info;
};

/** Given an evbuffer, return the correponding evbuffer structure, or NULL if
 * the evbuffer isn't overlapped. */
static inline struct evbuffer_overlapped *
upcast_evbuffer(struct evbuffer *buf)
{
	if (!buf || !buf->is_overlapped)
		return NULL;
	return EVUTIL_UPCAST(buf, struct evbuffer_overlapped, buffer);
}

static inline struct buffer_overlapped *
upcast_overlapped(struct event_overlapped *o)
{
	return EVUTIL_UPCAST(o, struct buffer_overlapped, event_overlapped);
}

/** Unpin all the chains noted as pinned in 'eo'. */
static void
pin_release(struct event_overlapped *eo, unsigned flag)
{
	int i;
	struct buffer_overlapped *bo = upcast_overlapped(eo);
	struct evbuffer_chain *chain = bo->first_pinned;

	for (i = 0; i < bo->n_buffers; ++i) {
		assert(chain);
		_evbuffer_chain_unpin(chain, flag);
		chain = chain->next;
	}
}

/** IOCP callback invoked when a read operation is finished. */
static void
read_completed(struct event_overlapped *eo, uintptr_t _, ev_ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;
	struct evbuffer *evbuf = &buf->buffer;

	struct evbuffer_iovec iov[2];
	int n_vec;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	buf->read_in_progress = 0;
	evbuffer_unfreeze(evbuf, 0);

	iov[0].iov_base = buf_o->buffers[0].buf;
	if (nBytes <= buf_o->buffers[0].len) {
		iov[0].iov_len = nBytes;
		n_vec = 1;
	} else {
		iov[0].iov_len = buf_o->buffers[0].len;
		iov[1].iov_base = buf_o->buffers[1].buf;
		iov[1].iov_len = nBytes - iov[0].iov_len;
		n_vec = 2;
	}

	if (evbuffer_commit_space(evbuf, iov, n_vec) < 0)
		assert(0); /* XXXX fail nicer. */

	pin_release(eo, EVBUFFER_MEM_PINNED_R);

	_evbuffer_decref_and_unlock(evbuf);
}

/** IOCP callback invoked when a write operation is finished. */
static void
write_completed(struct event_overlapped *eo, uintptr_t _, ev_ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;

	struct evbuffer *evbuf = &buf->buffer;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	buf->write_in_progress = 0;
	evbuffer_unfreeze(evbuf, 1);
	evbuffer_drain(evbuf, nBytes);
	pin_release(eo,EVBUFFER_MEM_PINNED_W);
	_evbuffer_decref_and_unlock(evbuf);
}

struct evbuffer *
evbuffer_overlapped_new(evutil_socket_t fd)
{
	struct evbuffer_overlapped *evo;

	evo = mm_calloc(1, sizeof(struct evbuffer_overlapped));

	TAILQ_INIT(&evo->buffer.callbacks);
	evo->buffer.refcnt = 1;

	evo->buffer.is_overlapped = 1;
	evo->fd = fd;

	return &evo->buffer;
}

int
evbuffer_launch_write(struct evbuffer *buf, ev_ssize_t at_most)
{
	struct evbuffer_overlapped *buf_o = upcast_evbuffer(buf);
	int r = -1;
	int i;
	struct evbuffer_chain *chain;
	DWORD bytesSent;

	if (!buf) {
		/* No buffer, or it isn't overlapped */
		return -1;
	}

	EVBUFFER_LOCK(buf, EVTHREAD_WRITE);
	if (buf->freeze_start || buf_o->write_in_progress)
		goto done;
	if (!buf->total_len) {
		/* Nothing to write */
		r = 0;
		goto done;
	} else if (at_most < 0 || (size_t)at_most > buf->total_len) {
		at_most = buf->total_len;
	}
	evbuffer_freeze(buf, 1);

	/* XXX we could move much of this into the constructor. */
	memset(&buf_o->write_info, 0, sizeof(buf_o->write_info));
	buf_o->write_info.buf = buf_o;
	buf_o->write_info.event_overlapped.cb = write_completed;
	chain = buf_o->write_info.first_pinned = buf->first;

	for (i=0; i < MAX_WSABUFS && chain; ++i, chain=chain->next) {
		WSABUF *b = &buf_o->write_info.buffers[i];
		b->buf = chain->buffer + chain->misalign;
		_evbuffer_chain_pin(chain, EVBUFFER_MEM_PINNED_W);

		if ((size_t)at_most > chain->off) {
			b->len = chain->off;
			at_most -= chain->off;
		} else {
			b->len = at_most;
			++i;
			break;
		}
	}

	buf_o->write_info.n_buffers = i;
	_evbuffer_incref(buf);
	if (WSASend(buf_o->fd, buf_o->write_info.buffers, i, &bytesSent, 0,
		&buf_o->write_info.event_overlapped.overlapped, NULL)) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			/* An actual error. */
			pin_release(&buf_o->write_info.event_overlapped, EVBUFFER_MEM_PINNED_W);
			evbuffer_unfreeze(buf, 1);
			evbuffer_free(buf); /* decref */
			goto done;
		}
	}

	buf_o->write_in_progress = 1;
	r = 0;
done:
	EVBUFFER_UNLOCK(buf, EVTHREAD_WRITE);
	return r;
}

int
evbuffer_launch_read(struct evbuffer *buf, size_t at_most)
{
	struct evbuffer_overlapped *buf_o = upcast_evbuffer(buf);
	int r = -1, i;
	int nvecs;
	int npin=0;
	struct evbuffer_chain *chain=NULL;
	DWORD bytesRead;
	DWORD flags = 0;
	struct evbuffer_iovec vecs[MAX_WSABUFS];

	if (!buf_o)
		return -1;
	EVBUFFER_LOCK(buf, EVTHREAD_WRITE);
	if (buf->freeze_end || buf_o->read_in_progress)
		goto done;

	if (_evbuffer_expand_fast(buf, at_most) == -1)
		goto done;
	evbuffer_freeze(buf, 0);

	/* XXX we could move much of this into the constructor. */
	memset(&buf_o->read_info, 0, sizeof(buf_o->read_info));
	buf_o->read_info.buf = buf_o;
	buf_o->read_info.event_overlapped.cb = read_completed;

	nvecs = _evbuffer_read_setup_vecs(buf, at_most,
	    vecs, &chain, 1);
	for (i=0;i<nvecs;++i) {
		WSABUF_FROM_EVBUFFER_IOV(
			&buf_o->read_info.buffers[i],
			&vecs[i]);
	}

	buf_o->read_info.n_buffers = nvecs;
	buf_o->read_info.first_pinned = chain;
	npin=0;
	for ( ; chain; chain = chain->next) {
		_evbuffer_chain_pin(chain, EVBUFFER_MEM_PINNED_R);
		++npin;
	}
	assert(npin == nvecs);

	_evbuffer_incref(buf);
	if (WSARecv(buf_o->fd, buf_o->read_info.buffers, nvecs, &bytesRead, &flags, &buf_o->read_info.event_overlapped.overlapped, NULL)) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			/* An actual error. */
			pin_release(&buf_o->read_info.event_overlapped, EVBUFFER_MEM_PINNED_R);
			evbuffer_unfreeze(buf, 0);
			evbuffer_free(buf); /* decref */
			goto done;
		}
	}

	buf_o->read_in_progress = 1;
	r = 0;
done:
	EVBUFFER_UNLOCK(buf, EVTHREAD_WRITE);
	return r;
}

evutil_socket_t
_evbuffer_overlapped_get_fd(struct evbuffer *buf)
{
	struct evbuffer_overlapped *buf_o = upcast_evbuffer(buf);
	return buf_o ? buf_o->fd : -1;
}
