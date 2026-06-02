/*
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
#ifndef EVENT_IO_URING_INTERNAL_H_INCLUDED_
#define EVENT_IO_URING_INTERNAL_H_INCLUDED_

#include "event2/event-config.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct event_base;
struct event_io_uring;
struct iovec;

/* Per-submission callback invoked from event_io_uring_drain_() once a CQE
 * arrives. `result` is the kernel's return value (positive byte count,
 * 0 for EOF, negative errno on failure). `arg` is the opaque pointer
 * passed at submission time. */
typedef void (*event_io_uring_cb)(int result, void *arg);

/* Multishot CQE callback — the same SQE can fire many CQEs. `cqe_flags`
 * carries the raw flags from the CQE (IORING_CQE_F_MORE, F_BUFFER, ...).
 * The callback must inspect cqe_flags & IORING_CQE_F_MORE to know whether
 * more CQEs will follow; when clear, the multishot has ended and the
 * associated state can be torn down. When CQE_F_BUFFER is set, the
 * buffer id is in the upper 16 bits of cqe_flags. */
typedef void (*event_io_uring_multishot_cb)(int result, unsigned cqe_flags,
    void *arg);

#ifdef EVENT__HAVE_LIBURING

/* Initialise a per-base io_uring instance and attach it to base->io_uring.
 * Returns 0 on success, -1 on failure (kernel too old, ENOMEM, etc.). */
int event_io_uring_init_(struct event_base *base);

/* Tear down and free the per-base io_uring instance, if any. Safe to call
 * unconditionally — base->io_uring may be NULL. */
void event_io_uring_free_(struct event_base *base);

/* Drain any completed CQEs and dispatch their callbacks. Called once per
 * loop iteration from event_base_loop() after the backend dispatch.
 * Returns the number of CQEs processed. */
int event_io_uring_drain_(struct event_base *base);

/* Queue a readv()/writev() SQE in the ring. The iovecs must remain valid
 * until the callback fires. SQEs are batched — event_io_uring_flush_()
 * submits them all to the kernel in a single io_uring_enter syscall.
 * Returns 0 on success, -1 on failure (ring full, OOM, no io_uring). */
int event_io_uring_submit_readv_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg);

int event_io_uring_submit_writev_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg);

/* Submit any queued SQEs to the kernel in one io_uring_enter call.
 * Called once per event_base_loop iteration. No-op when nothing is
 * pending or when the base has no io_uring. */
void event_io_uring_flush_(struct event_base *base);

/* Submit a multishot recv on `fd`, with the kernel selecting buffers
 * from the per-base provided buffer ring. `cb` fires for every CQE
 * (data arrival, EOF, error, cancellation); the callback must read
 * cqe_flags to know whether more CQEs will follow and to retrieve the
 * buffer id when CQE_F_BUFFER is set. Returns 0 on success, -1 if the
 * base has no io_uring or no buffer ring, or the SQ was full. */
int event_io_uring_submit_recv_multishot_(struct event_base *base, int fd,
    event_io_uring_multishot_cb cb, void *arg);

/* Helpers for parsing the cqe_flags passed to a multishot callback.
 * They hide liburing.h from bufferevent code that consumes multishot
 * CQEs. */
int event_io_uring_cqe_more_(unsigned cqe_flags);
int event_io_uring_cqe_has_buf_(unsigned cqe_flags);
unsigned short event_io_uring_cqe_buf_id_(unsigned cqe_flags);

/* Read the data backing a buffer id delivered by a multishot recv CQE. */
void *event_io_uring_buf_addr_(struct event_base *base, unsigned short bid);

/* Return a previously-delivered buffer to the kernel's provided buffer
 * ring so it can be reused for a subsequent recv. Must be called
 * exactly once per CQE that delivered the buffer. */
void event_io_uring_buf_release_(struct event_base *base, unsigned short bid);

/* Submit an async cancellation for all in-flight SQEs targeting `fd`.
 * The cancellation itself completes via its own CQE (with `cb`/`arg`);
 * each cancelled SQE fires its own final CQE separately with
 * res=-ECANCELED. */
int event_io_uring_submit_cancel_fd_(struct event_base *base, int fd,
    event_io_uring_cb cb, void *arg);

#else /* no liburing */

static inline int
event_io_uring_init_(struct event_base *base) { (void)base; return -1; }
static inline void
event_io_uring_free_(struct event_base *base) { (void)base; }
static inline int
event_io_uring_drain_(struct event_base *base) { (void)base; return 0; }
static inline int
event_io_uring_submit_readv_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg)
{
	(void)base; (void)fd; (void)iov; (void)niov; (void)cb; (void)arg;
	return -1;
}
static inline int
event_io_uring_submit_writev_(struct event_base *base, int fd,
    const struct iovec *iov, unsigned niov,
    event_io_uring_cb cb, void *arg)
{
	(void)base; (void)fd; (void)iov; (void)niov; (void)cb; (void)arg;
	return -1;
}
static inline void
event_io_uring_flush_(struct event_base *base) { (void)base; }
static inline int
event_io_uring_submit_recv_multishot_(struct event_base *base, int fd,
    event_io_uring_multishot_cb cb, void *arg)
{
	(void)base; (void)fd; (void)cb; (void)arg;
	return -1;
}
static inline int
event_io_uring_cqe_more_(unsigned cqe_flags) { (void)cqe_flags; return 0; }
static inline int
event_io_uring_cqe_has_buf_(unsigned cqe_flags) { (void)cqe_flags; return 0; }
static inline unsigned short
event_io_uring_cqe_buf_id_(unsigned cqe_flags) { (void)cqe_flags; return 0; }
static inline void *
event_io_uring_buf_addr_(struct event_base *base, unsigned short bid)
{
	(void)base; (void)bid;
	return NULL;
}
static inline void
event_io_uring_buf_release_(struct event_base *base, unsigned short bid)
{
	(void)base; (void)bid;
}
static inline int
event_io_uring_submit_cancel_fd_(struct event_base *base, int fd,
    event_io_uring_cb cb, void *arg)
{
	(void)base; (void)fd; (void)cb; (void)arg;
	return -1;
}

#endif /* EVENT__HAVE_LIBURING */

#ifdef __cplusplus
}
#endif

#endif /* EVENT_IO_URING_INTERNAL_H_INCLUDED_ */
