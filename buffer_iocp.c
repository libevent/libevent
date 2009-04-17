
#include <windows.h>
#include <assert.h>

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

#define MAX_WSABUFS 16

struct buffer_overlapped {
	struct event_overlapped event_overlapped;

	struct evbuffer_chain *first_pinned;
	struct evbuffer_overlapped *buf;
	int n_buffers;
	WSABUF buffers[MAX_WSABUFS];
};

struct evbuffer_overlapped {
	struct evbuffer buffer;
	evutil_socket_t fd;
	unsigned write_in_progress : 1;
	unsigned read_in_progress : 1;

	struct buffer_overlapped read_info;
	struct buffer_overlapped write_info;
};

static inline struct evbuffer_overlapped *
upcast_evbuffer(struct evbuffer *buf)
{
	if (!buf || buf->is_overlapped)
		return NULL;
	return EVUTIL_UPCAST(buf, struct evbuffer_overlapped, buffer);
}

static inline struct buffer_overlapped *
upcast_overlapped(struct event_overlapped *o)
{
	return EVUTIL_UPCAST(o, struct buffer_overlapped, event_overlapped);
}

static void
pin_release(struct event_overlapped *eo, unsigned flag)
{
	int i;
	struct buffer_overlapped *bo = upcast_overlapped(eo);
	struct evbuffer_chain *chain = bo->first_pinned;

	for (i = 0; i < bo->n_buffers; ++i) {
		_evbuffer_chain_unpin(chain, flag);
		chain = chain->next;
		assert(chain);
	}
}

static void
read_completed(struct event_overlapped *eo, uintptr_t _, ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;
	struct evbuffer *evbuf = &buf->buffer;

	struct evbuffer_chain *chain = buf_o->first_pinned;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	evbuffer_unfreeze(evbuf, 0);

	if (chain == evbuf->previous_to_last) {
		size_t n = chain->buffer_len - (chain->misalign + chain->off);
		if (n>nBytes)
			n=nBytes;
		chain->off += n;
		nBytes -= n;
		evbuf->n_add_for_cb += n;

		evbuffer_commit_space(evbuf, nBytes);
	} else if (chain == evbuf->last) {
		evbuffer_commit_space(evbuf, nBytes);
	} else {
		assert(0);
	}

	pin_release(eo, EVBUFFER_MEM_PINNED_R);

	buf->read_in_progress = 0;
	_evbuffer_decref_and_unlock(evbuf);
}

static void
write_completed(struct event_overlapped *eo, uintptr_t _, ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;

	struct evbuffer *evbuf = &buf->buffer;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	evbuffer_unfreeze(evbuf, 1);
	evbuffer_drain(evbuf, nBytes);
	pin_release(eo,EVBUFFER_MEM_PINNED_W);
	buf->write_in_progress = 0;
	_evbuffer_decref_and_unlock(evbuf);
}

struct evbuffer *
evbuffer_overlapped_new(evutil_socket_t fd)
{
	struct evbuffer_overlapped *evo;

	evo = mm_calloc(1, sizeof(struct evbuffer_overlapped));

	TAILQ_INIT(&evo->buffer.callbacks);

	evo->buffer.is_overlapped = 1;

	return &evo->buffer;
}

int
evbuffer_launch_write(struct evbuffer *buf, ssize_t at_most)
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
	} else if (at_most > buf->total_len || at_most < 0) {
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

		if (at_most > chain->off) {
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
	int r = -1;
	int nvecs;
	struct evbuffer_chain *chain=NULL;
	DWORD bytesRead;
	DWORD flags = 0;

	if (!buf)
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
	    buf_o->read_info.buffers, &chain);
	buf_o->read_info.n_buffers = nvecs;
	buf_o->read_info.first_pinned = chain;
	for ( ; chain; chain = chain->next)
		_evbuffer_chain_pin(chain, EVBUFFER_MEM_PINNED_R);

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

