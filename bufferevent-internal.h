/*
 * Copyright (c) 2008-2009 Niels Provos and Nick Mathewson
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
#ifndef _BUFFEREVENT_INTERNAL_H_
#define _BUFFEREVENT_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "event-config.h"
#include "evutil.h"
#include "defer-internal.h"
#include "evthread-internal.h"
#include "event2/thread.h"

struct bufferevent_private {
	struct bufferevent bev;

	/** Evbuffer callback to enforce watermarks on input. */
	struct evbuffer_cb_entry *read_watermarks_cb;

	/** If set, read is suspended until evbuffer some. */
	unsigned read_suspended : 1;
	unsigned own_lock : 1;

	enum bufferevent_options options;

	int refcnt;
	void *lock;
};

/**
   Implementation table for a bufferevent: holds function pointers and other
   information to make the various bufferevent types work.
*/
struct bufferevent_ops {
	/** The name of the bufferevent's type. */
	const char *type;
	/** At what offset into the implementation type will we find a
	    bufferevent structure?

	    Example: if the type is implemented as
	    struct bufferevent_x {
	       int extra_data;
	       struct bufferevent bev;
	    }
	    then mem_offset should be offsetof(struct bufferevent_x, bev)
	*/
	off_t mem_offset;

	/** Enables one or more of EV_READ|EV_WRITE on a bufferevent.  Does
	    not need to adjust the 'enabled' field.  Returns 0 on success, -1
	    on failure.
	 */
	int (*enable)(struct bufferevent *, short);

	/** Disables one or more of EV_READ|EV_WRITE on a bufferevent.  Does
	    not need to adjust the 'enabled' field.  Returns 0 on success, -1
	    on failure.
	 */
	int (*disable)(struct bufferevent *, short);

	/** Free any storage and deallocate any extra data or structures used
	    in this implementation.
	 */
	void (*destruct)(struct bufferevent *);

	/** Called when the timeouts on the bufferevent have changed.*/
	void (*adj_timeouts)(struct bufferevent *);

        /** Called to flush data. */
        int (*flush)(struct bufferevent *, short, enum bufferevent_flush_mode);
};

extern const struct bufferevent_ops bufferevent_ops_socket;
extern const struct bufferevent_ops bufferevent_ops_filter;
extern const struct bufferevent_ops bufferevent_ops_pair;

/** Initialize the shared parts of a bufferevent. */
int bufferevent_init_common(struct bufferevent_private *, struct event_base *, const struct bufferevent_ops *, enum bufferevent_options options);

/** For internal use: temporarily stop all reads on bufev, because its
 * read buffer is too full. */
void bufferevent_wm_suspend_read(struct bufferevent *bufev);
/** For internal use: temporarily stop all reads on bufev, because its
 * read buffer is too full. */
void bufferevent_wm_unsuspend_read(struct bufferevent *bufev);

int bufferevent_enable_locking(struct bufferevent *bufev, void *lock);
void bufferevent_incref(struct bufferevent *bufev);
void _bufferevent_decref_and_unlock(struct bufferevent *bufev);

#define BEV_UPCAST(b) EVUTIL_UPCAST((b), struct bufferevent_private, bev)

#define BEV_LOCK(b) do {						\
		struct bufferevent_private *locking =  BEV_UPCAST(b);	\
		if (locking->lock)					\
			EVLOCK_LOCK(locking->lock, EVTHREAD_WRITE);	\
	} while(0)

#define BEV_UNLOCK(b) do {						\
		struct bufferevent_private *locking =  BEV_UPCAST(b);	\
		if (locking->lock)					\
			EVLOCK_UNLOCK(locking->lock, EVTHREAD_WRITE);	\
	} while(0)

#ifdef __cplusplus
}
#endif

#endif /* _BUFFEREVENT_INTERNAL_H_ */
