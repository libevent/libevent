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

#ifdef __cplusplus
extern "C" {
#endif

struct event_base;
struct event_io_uring;

#ifdef EVENT__HAVE_LIBURING

/* Initialise a per-base io_uring instance and attach it to base->io_uring.
 * Returns 0 on success, -1 on failure (kernel too old, ENOMEM, etc.). */
int event_io_uring_init_(struct event_base *base);

/* Tear down and free the per-base io_uring instance, if any. Safe to call
 * unconditionally — base->io_uring may be NULL. */
void event_io_uring_free_(struct event_base *base);

/* Drain any completed CQEs and dispatch them. Called once per loop iteration
 * from event_base_loop() after the backend dispatch. Returns the number of
 * CQEs processed. */
int event_io_uring_drain_(struct event_base *base);

#else /* no liburing */

static inline int
event_io_uring_init_(struct event_base *base) { (void)base; return -1; }
static inline void
event_io_uring_free_(struct event_base *base) { (void)base; }
static inline int
event_io_uring_drain_(struct event_base *base) { (void)base; return 0; }

#endif /* EVENT__HAVE_LIBURING */

#ifdef __cplusplus
}
#endif

#endif /* EVENT_IO_URING_INTERNAL_H_INCLUDED_ */
