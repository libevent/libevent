/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
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
#ifndef _EVENT2_EVENT_STRUCT_H_
#define _EVENT2_EVENT_STRUCT_H_

/** @file event_struct.h

  Structures used by event.h.  Using these structures directly may harm
  forward compatibility: be careful!

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

#ifdef WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#define EVLIST_TIMEOUT	0x01
#define EVLIST_INSERTED	0x02
#define EVLIST_SIGNAL	0x04
#define EVLIST_ACTIVE	0x08
#define EVLIST_INTERNAL	0x10
#define EVLIST_INIT	0x80

/* EVLIST_X_ Private space: 0x1000-0xf000 */
#define EVLIST_ALL	(0xf000 | 0x9f)

/* Fix so that people don't have to run with <sys/queue.h> */
#ifndef TAILQ_ENTRY
#define _EVENT_DEFINED_TQENTRY
#define TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}
#endif /* !TAILQ_ENTRY */

struct event_base;
struct event {
	TAILQ_ENTRY (event) (ev_active_next);
	TAILQ_ENTRY (event) (ev_next);
	/* for managing timeouts */
	union {
		TAILQ_ENTRY (event) (ev_next_with_common_timeout);
		int min_heap_idx;
	} ev_timeout_pos;
	evutil_socket_t ev_fd;

	struct event_base *ev_base;

	union {
		/* used for io events */
		struct {
			TAILQ_ENTRY (event) (ev_io_next);
			struct timeval ev_timeout;
		} ev_io;

		/* used by signal events */
		struct {
			TAILQ_ENTRY (event) (ev_signal_next);
			short ev_ncalls;
			/* Allows deletes in callback */
			short *ev_pncalls;
		} ev_signal;
	} _ev;

	short ev_events;
	short ev_res;		/* result passed to event callback */
	short ev_flags;
	ev_uint8_t ev_pri;	/* smaller numbers are higher priority */
	ev_uint8_t ev_closure;
	struct timeval ev_timeout;

	/* allows us to adopt for different types of events */
	void (*ev_callback)(evutil_socket_t, short, void *arg);
	void *ev_arg;
};

#ifdef EVENT_FD
/* This was defined in event.h, but since we're including event_struct.h, we
 * can use the faster versions. */
#undef EVENT_FD
#undef EVENT_SIGNAL
#define EVENT_SIGNAL(ev)	((int)(ev)->ev_fd)
#define EVENT_FD(ev)		((int)(ev)->ev_fd)
#endif

/*
 * Key-Value pairs.  Can be used for HTTP headers but also for
 * query argument parsing.
 */
struct evkeyval {
	TAILQ_ENTRY(evkeyval) next;

	char *key;
	char *value;
};

#ifdef _EVENT_DEFINED_TQENTRY
#undef TAILQ_ENTRY
struct event_list;
struct evkeyvalq;
#undef _EVENT_DEFINED_TQENTRY
#else
TAILQ_HEAD (event_list, event);
TAILQ_HEAD (evkeyvalq, evkeyval);
#endif /* _EVENT_DEFINED_TQENTRY */

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_EVENT_STRUCT_H_ */
