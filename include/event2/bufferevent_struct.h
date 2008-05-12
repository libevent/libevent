/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
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
#ifndef _EVENT2_BUFFEREVENT_STRUCT_H_
#define _EVENT2_BUFFEREVENT_STRUCT_H_

/** @file bufferevent_struct.h

  Data structures for bufferevents.  Using these structures may hurt forward
  compatibility with later versions of libevent: be careful!

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
/* For struct event */
#include <event2/event_struct.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

struct event_watermark {
	size_t low;
	size_t high;
};

struct bufferevent_filter;

/* Fix so that ppl dont have to run with <sys/queue.h> */
#ifndef TAILQ_HEAD
#define _EVENT_DEFINED_TQHEAD
#define TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}
#endif /* !TAILQ_HEAD */

TAILQ_HEAD(bufferevent_filterq, bufferevent_filter);

#ifdef _EVENT_DEFINED_TQHEAD
#undef TAILQ_HEAD
#undef _EVENT_DEFINED_TQHEAD
#endif /* _EVENT_DEFINED_TQHEAD */

struct bufferevent {
	struct event_base *ev_base;

	struct event ev_read;
	struct event ev_write;

	struct evbuffer *input;
	struct evbuffer *output;

	struct event_watermark wm_read;
	struct event_watermark wm_write;

	evbuffercb readcb;
	evbuffercb writecb;
	everrorcb errorcb;
	void *cbarg;

	int timeout_read;	/* in seconds */
	int timeout_write;	/* in seconds */

	short enabled;	/* events that are currently enabled */

	/** the list of input and output filters */
	struct bufferevent_filterq input_filters;
	struct bufferevent_filterq output_filters;
};

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_BUFFEREVENT_STRUCT_H_ */
