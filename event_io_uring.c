/*
 * Per-base io_uring(7) lifecycle and completion drain.
 *
 * Copyright (c) 2026 Libevent contributors
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

#include "event2/event-config.h"

#ifdef EVENT__HAVE_LIBURING

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <liburing.h>

#include "event2/event.h"
#include "event-internal.h"
#include "event_io_uring-internal.h"
#include "evthread-internal.h"
#include "log-internal.h"
#include "mm-internal.h"

/* Default submission queue depth. Sized to comfortably absorb bursts from
 * many concurrent bufferevents without forcing the kernel to grow the ring;
 * matches the order of magnitude used by other libraries that have wired
 * up io_uring (e.g. libuv). Future work may make this tunable per-base. */
#define EVENT_IO_URING_QUEUE_DEPTH 256

/* Provided-buffer ring used by multishot recv. The kernel picks a buffer
 * from this ring for every recv completion and reports the buffer id back
 * in the CQE flags. The pool is one large allocation carved into N equal
 * slots. NBUFS must be a power of two (io_uring_buf_ring_mask). */
#define EVENT_IO_URING_BUF_NBUFS    128
#define EVENT_IO_URING_BUF_SIZE     (16 * 1024)
#define EVENT_IO_URING_BUF_GROUP_ID 0

struct event_io_uring {
	struct io_uring ring;
	/* Watcher on the ring's own fd. POLLIN is asserted by the kernel
	 * whenever the CQ has unread entries, and de-asserted as we advance
	 * the CQ head via io_uring_cqe_seen — so we get exactly one wakeup
	 * per drain cycle without any read() syscall to clear an eventfd.
	 * The callback is a no-op: draining happens unconditionally in
	 * event_base_loop's post-dispatch hooks. */
	struct event notify_ev;
	/* Number of SQEs prepped but not yet submitted to the kernel. The
	 * submit_* helpers queue SQEs; event_io_uring_flush_() is called
	 * once per event_base_loop iteration to submit them in a single
	 * io_uring_enter syscall. */
	unsigned pending_sqes;
	/* Provided buffer ring for multishot recv. NULL when the kernel
	 * doesn't support it; submission helpers will then fail and callers
	 * fall back to one-shot readv. */
	struct io_uring_buf_ring *buf_ring;
	void *buf_pool;
	int buf_ring_mask;
};

static void
event_io_uring_notify_cb_(evutil_socket_t fd, short what, void *arg)
{
	(void)fd;
	(void)what;
	(void)arg;
	/* Drain happens in event_base_loop(); nothing to do here. */
}

/* Per-submission record. Lifetime: allocated in submit_*, freed in drain
 * after the user callback returns — except for multishot submissions,
 * where the kernel may produce many CQEs from one SQE; the req is freed
 * only on the final CQE (the one without IORING_CQE_F_MORE). The pointer
 * is stashed in the SQE's user_data so the CQE handler can find it. */
struct event_io_uring_req {
	union {
		event_io_uring_cb single;
		event_io_uring_multishot_cb multi;
	} cb;
	void *arg;
	unsigned is_multishot:1;
};

int
event_io_uring_init_(struct event_base *base)
{
	struct event_io_uring *r;
	int rv;

	if (base->io_uring != NULL)
		return 0;

	r = mm_calloc(1, sizeof(*r));
	if (r == NULL)
		return -1;

	rv = io_uring_queue_init(EVENT_IO_URING_QUEUE_DEPTH, &r->ring, 0);
	if (rv < 0) {
		event_warnx("%s: io_uring_queue_init failed: %s",
		    __func__, strerror(-rv));
		mm_free(r);
		return -1;
	}

	/* Provided buffer ring for multishot recv. Optional: if the kernel
	 * is too old (pre-5.19) the setup call fails; we still bring up the
	 * ring without it, and submit_recv_multishot_ returns -1 so callers
	 * fall back to one-shot readv. */
	{
		int err = 0;
		r->buf_ring = io_uring_setup_buf_ring(&r->ring,
		    EVENT_IO_URING_BUF_NBUFS,
		    EVENT_IO_URING_BUF_GROUP_ID, 0, &err);
		if (r->buf_ring != NULL) {
			unsigned i;
			r->buf_pool = mm_malloc(
			    (size_t)EVENT_IO_URING_BUF_NBUFS *
			    EVENT_IO_URING_BUF_SIZE);
			if (r->buf_pool == NULL) {
				io_uring_free_buf_ring(&r->ring, r->buf_ring,
				    EVENT_IO_URING_BUF_NBUFS,
				    EVENT_IO_URING_BUF_GROUP_ID);
				r->buf_ring = NULL;
			} else {
				r->buf_ring_mask = io_uring_buf_ring_mask(
				    EVENT_IO_URING_BUF_NBUFS);
				for (i = 0; i < EVENT_IO_URING_BUF_NBUFS; ++i) {
					io_uring_buf_ring_add(r->buf_ring,
					    (char *)r->buf_pool +
					    (size_t)i * EVENT_IO_URING_BUF_SIZE,
					    EVENT_IO_URING_BUF_SIZE,
					    (unsigned short)i,
					    r->buf_ring_mask, (int)i);
				}
				io_uring_buf_ring_advance(r->buf_ring,
				    EVENT_IO_URING_BUF_NBUFS);
			}
		} else if (err != -ENOSYS && err != -EINVAL) {
			event_warnx("%s: io_uring_setup_buf_ring: %s",
			    __func__, strerror(-err));
		}
	}

	/* Poll the ring's own fd; the kernel signals POLLIN when the CQ has
	 * entries. No eventfd indirection, no per-iteration read() syscall
	 * to clear a counter — draining the CQ via io_uring_cqe_seen is
	 * what de-asserts POLLIN. */
	event_assign(&r->notify_ev, base, r->ring.ring_fd,
	    EV_READ | EV_PERSIST, event_io_uring_notify_cb_, r);
	if (event_add(&r->notify_ev, NULL) < 0) {
		event_warnx("%s: event_add(notify) failed", __func__);
		if (r->buf_ring) {
			io_uring_free_buf_ring(&r->ring, r->buf_ring,
			    EVENT_IO_URING_BUF_NBUFS,
			    EVENT_IO_URING_BUF_GROUP_ID);
			mm_free(r->buf_pool);
		}
		io_uring_queue_exit(&r->ring);
		mm_free(r);
		return -1;
	}

	base->io_uring = r;
	return 0;
}

void
event_io_uring_free_(struct event_base *base)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_sqe *sqe;
	struct io_uring_cqe *cqe;

	if (r == NULL)
		return;

	event_del(&r->notify_ev);

	/* Cancel anything still in flight and drain the resulting CQEs so
	 * we can free the per-submission req structs we own. A bufferevent
	 * that was freed with a multishot recv pending — or any in-flight
	 * one-shot SQE — would otherwise leak its req allocation (and the
	 * refcount it holds on the bufferevent). */
	sqe = io_uring_get_sqe(&r->ring);
	if (sqe != NULL) {
		io_uring_prep_cancel(sqe, NULL, IORING_ASYNC_CANCEL_ANY);
		io_uring_sqe_set_data(sqe, NULL);
		io_uring_submit(&r->ring);
		r->pending_sqes = 0;
	}
	/* Drain whatever CQEs are ready right now, plus the ones produced
	 * by the cancel — which kick the kernel into completing all the
	 * cancelled SQEs with -ECANCELED. Use a wait loop with a tiny
	 * timeout per drain so we don't block forever on a misbehaving
	 * kernel, but do let ops complete. */
	while (io_uring_peek_cqe(&r->ring, &cqe) == 0) {
		struct event_io_uring_req *req = io_uring_cqe_get_data(cqe);
		unsigned cqe_flags = cqe->flags;
		int result = cqe->res;
		io_uring_cqe_seen(&r->ring, cqe);
		if (req == NULL)
			continue;
		if (req->is_multishot) {
			/* Fire the multishot cb so it can release the
			 * provided buffer (if any) and the bufferevent ref. */
			req->cb.multi(result, cqe_flags, req->arg);
			if (!(cqe_flags & IORING_CQE_F_MORE))
				mm_free(req);
		} else {
			req->cb.single(result, req->arg);
			mm_free(req);
		}
	}

	if (r->buf_ring) {
		io_uring_free_buf_ring(&r->ring, r->buf_ring,
		    EVENT_IO_URING_BUF_NBUFS, EVENT_IO_URING_BUF_GROUP_ID);
		mm_free(r->buf_pool);
	}
	io_uring_queue_exit(&r->ring);
	mm_free(r);
	base->io_uring = NULL;
}

int
event_io_uring_drain_(struct event_base *base)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_cqe *cqe;
	int n = 0;

	if (r == NULL)
		return 0;

	while (io_uring_peek_cqe(&r->ring, &cqe) == 0) {
		struct event_io_uring_req *req = io_uring_cqe_get_data(cqe);
		int result = cqe->res;
		unsigned cqe_flags = cqe->flags;
		io_uring_cqe_seen(&r->ring, cqe);
		if (req != NULL) {
			/* Release the base lock around the user callback so it
			 * can call back into libevent (event_base_loopbreak,
			 * event_active, etc.) without recursing on the lock —
			 * mirrors event_process_active_single_queue's
			 * contract. The callback is responsible for any inner
			 * locking it needs (e.g. BEV_LOCK on a bufferevent). */
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			if (req->is_multishot) {
				req->cb.multi(result, cqe_flags, req->arg);
				/* Free the req only when the kernel signals
				 * that no more CQEs will reference it. */
				if (!(cqe_flags & IORING_CQE_F_MORE))
					mm_free(req);
			} else {
				req->cb.single(result, req->arg);
				mm_free(req);
			}
			EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		}
		++n;
	}
	return n;
}

/* Allocate and prep a request record. Caller fills in the cb union and
 * is_multishot bit, then finishes prepping the SQE. Returns NULL on
 * failure (no SQE or OOM). */
static struct io_uring_sqe *
event_io_uring_alloc_sqe_(struct event_io_uring *r,
    void *arg, struct event_io_uring_req **out_req)
{
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	sqe = io_uring_get_sqe(&r->ring);
	if (sqe == NULL)
		return NULL;

	req = mm_calloc(1, sizeof(*req));
	if (req == NULL)
		return NULL;
	req->arg = arg;
	io_uring_sqe_set_data(sqe, req);
	*out_req = req;
	return sqe;
}

int
event_io_uring_submit_readv_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	if (r == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, arg, &req);
	if (sqe == NULL)
		return -1;
	req->cb.single = cb;

	io_uring_prep_readv(sqe, fd, iov, niov, 0);
	++r->pending_sqes;
	return 0;
}

int
event_io_uring_submit_writev_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	if (r == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, arg, &req);
	if (sqe == NULL)
		return -1;
	req->cb.single = cb;

	io_uring_prep_writev(sqe, fd, iov, niov, 0);
	++r->pending_sqes;
	return 0;
}

int
event_io_uring_submit_recv_multishot_(struct event_base *base, int fd,
    event_io_uring_multishot_cb cb, void *arg)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	if (r == NULL || r->buf_ring == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, arg, &req);
	if (sqe == NULL)
		return -1;
	req->cb.multi = cb;
	req->is_multishot = 1;

	/* NULL/0 buffer; the kernel picks one from the provided buffer ring
	 * named by sqe->buf_group on every completion. */
	io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->buf_group = EVENT_IO_URING_BUF_GROUP_ID;
	++r->pending_sqes;
	return 0;
}

int
event_io_uring_submit_cancel_fd_(struct event_base *base, int fd,
    event_io_uring_cb cb, void *arg)
{
	struct event_io_uring *r = base->io_uring;
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	if (r == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, arg, &req);
	if (sqe == NULL)
		return -1;
	req->cb.single = cb;

	io_uring_prep_cancel_fd(sqe, fd, 0);
	++r->pending_sqes;
	return 0;
}

int
event_io_uring_cqe_more_(unsigned cqe_flags)
{
	return (cqe_flags & IORING_CQE_F_MORE) != 0;
}

int
event_io_uring_cqe_has_buf_(unsigned cqe_flags)
{
	return (cqe_flags & IORING_CQE_F_BUFFER) != 0;
}

unsigned short
event_io_uring_cqe_buf_id_(unsigned cqe_flags)
{
	return (unsigned short)(cqe_flags >> IORING_CQE_BUFFER_SHIFT);
}

void *
event_io_uring_buf_addr_(struct event_base *base, unsigned short bid)
{
	struct event_io_uring *r = base->io_uring;
	if (r == NULL || r->buf_pool == NULL)
		return NULL;
	return (char *)r->buf_pool + (size_t)bid * EVENT_IO_URING_BUF_SIZE;
}

void
event_io_uring_buf_release_(struct event_base *base, unsigned short bid)
{
	struct event_io_uring *r = base->io_uring;
	if (r == NULL || r->buf_ring == NULL)
		return;
	io_uring_buf_ring_add(r->buf_ring,
	    (char *)r->buf_pool + (size_t)bid * EVENT_IO_URING_BUF_SIZE,
	    EVENT_IO_URING_BUF_SIZE, bid, r->buf_ring_mask, 0);
	io_uring_buf_ring_advance(r->buf_ring, 1);
}

void
event_io_uring_flush_(struct event_base *base)
{
	struct event_io_uring *r = base->io_uring;
	int n;

	if (r == NULL || r->pending_sqes == 0)
		return;
	n = io_uring_submit(&r->ring);
	if (n < 0) {
		event_warnx("%s: io_uring_submit failed: %s",
		    __func__, strerror(-n));
		/* Leave pending_sqes nonzero so we retry next iteration;
		 * if the failure is persistent the loop will keep warning. */
		return;
	}
	r->pending_sqes = 0;
}

#endif /* EVENT__HAVE_LIBURING */
