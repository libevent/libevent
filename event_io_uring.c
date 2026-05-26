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

#include <liburing.h>

#include "event-internal.h"
#include "event_io_uring-internal.h"
#include "log-internal.h"
#include "mm-internal.h"

/* Default submission queue depth. Sized to comfortably absorb bursts from
 * many concurrent bufferevents without forcing the kernel to grow the ring;
 * matches the order of magnitude used by other libraries that have wired
 * up io_uring (e.g. libuv). Future work may make this tunable per-base. */
#define EVENT_IO_URING_QUEUE_DEPTH 256

struct event_io_uring {
	struct io_uring ring;
};

/* Per-submission record. Lifetime: allocated in submit_*, freed in drain
 * after the user callback returns. The pointer is stashed in the SQE's
 * user_data so the CQE handler can find it. */
struct event_io_uring_req {
	event_io_uring_cb cb;
	void *arg;
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

	base->io_uring = r;
	return 0;
}

void
event_io_uring_free_(struct event_base *base)
{
	struct event_io_uring *r = base->io_uring;
	if (r == NULL)
		return;

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
		io_uring_cqe_seen(&r->ring, cqe);
		if (req != NULL) {
			req->cb(result, req->arg);
			mm_free(req);
		}
		++n;
	}
	return n;
}

/* Allocate and prep a request record. Caller must finish prepping the SQE
 * and call io_uring_submit(). Returns NULL on failure (no SQE or OOM). */
static struct io_uring_sqe *
event_io_uring_alloc_sqe_(struct event_io_uring *r,
    event_io_uring_cb cb, void *arg, struct event_io_uring_req **out_req)
{
	struct io_uring_sqe *sqe;
	struct event_io_uring_req *req;

	sqe = io_uring_get_sqe(&r->ring);
	if (sqe == NULL)
		return NULL;

	req = mm_malloc(sizeof(*req));
	if (req == NULL)
		return NULL;
	req->cb = cb;
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
	int n;

	if (r == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, cb, arg, &req);
	if (sqe == NULL)
		return -1;

	io_uring_prep_readv(sqe, fd, iov, niov, 0);
	n = io_uring_submit(&r->ring);
	if (n < 0) {
		event_warnx("%s: io_uring_submit failed: %s",
		    __func__, strerror(-n));
		mm_free(req);
		return -1;
	}
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
	int n;

	if (r == NULL)
		return -1;

	sqe = event_io_uring_alloc_sqe_(r, cb, arg, &req);
	if (sqe == NULL)
		return -1;

	io_uring_prep_writev(sqe, fd, iov, niov, 0);
	n = io_uring_submit(&r->ring);
	if (n < 0) {
		event_warnx("%s: io_uring_submit failed: %s",
		    __func__, strerror(-n));
		mm_free(req);
		return -1;
	}
	return 0;
}

#endif /* EVENT__HAVE_LIBURING */
