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

	/* Pop every ready CQE. Submitters land in step 3; until then this
	 * is just a hook that confirms the ring is reachable from the loop. */
	while (io_uring_peek_cqe(&r->ring, &cqe) == 0) {
		io_uring_cqe_seen(&r->ring, cqe);
		++n;
	}
	return n;
}

#endif /* EVENT__HAVE_LIBURING */
