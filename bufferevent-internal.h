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

/** Parts of the bufferevent structure that are shared among all bufferevent
 * types, but not exposed in bufferevent_struct.h. */
struct bufferevent_private {
	/** The underlying bufferevent structure. */
	struct bufferevent bev;

	/** Evbuffer callback to enforce watermarks on input. */
	struct evbuffer_cb_entry *read_watermarks_cb;

	/** If set, read is suspended until evbuffer some. */
	unsigned read_suspended : 1;
	/** If set, we should free the lock when we free the bufferevent. */
	unsigned own_lock : 1;

	/** Flag: set if we have deferred callbacks and a read callback is
	 * pending. */
	unsigned readcb_pending : 1;
	/** Flag: set if we have deferred callbacks and a write callback is
	 * pending. */
	unsigned writecb_pending : 1;
	/** Flag: set if we are currently busy connecting. */
	unsigned connecting : 1;
	/** Set to the events pending if we have deferred callbacks and
	 * an events callback is pending. */
	short eventcb_pending;
	/** Set to the current socket errno if we have deferred callbacks and
	 * an events callback is pending. */
	int errno_pending;
	/** Used to implement deferred callbacks */
	struct deferred_cb deferred;

	/** The options this bufferevent was constructed with */
	enum bufferevent_options options;

	/** Current reference count for this bufferevent. */
	int refcnt;

	/** Lock for this bufferevent.  Shared by the inbuf and the outbuf.
	 * If NULL, locking is disabled. */
	void *lock;
};

/** Possible operations for a control callback. */
enum bufferevent_ctrl_op {
	BEV_CTRL_SET_FD,
	BEV_CTRL_GET_FD,
	BEV_CTRL_GET_UNDERLYING,
};

/** Possible data types for a control callback */
union bufferevent_ctrl_data {
	void *ptr;
	evutil_socket_t fd;
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

	/** Called to access miscellaneous fields. */
	int (*ctrl)(struct bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);
};

extern const struct bufferevent_ops bufferevent_ops_socket;
extern const struct bufferevent_ops bufferevent_ops_filter;
extern const struct bufferevent_ops bufferevent_ops_pair;

#define BEV_IS_SOCKET(bevp) ((bevp)->be_ops == &bufferevent_ops_socket)
#define BEV_IS_FILTER(bevp) ((bevp)->be_ops == &bufferevent_ops_filter)
#define BEV_IS_PAIR(bevp) ((bevp)->be_ops == &bufferevent_ops_pair)

#ifdef WIN32
extern const struct bufferevent_ops bufferevent_ops_async;
#define BEV_IS_ASYNC(bevp) ((bevp)->be_ops == &bufferevent_ops_async)
#else
#define BEV_IS_ASYNC(bevp) 0
#endif

/** Initialize the shared parts of a bufferevent. */
int bufferevent_init_common(struct bufferevent_private *, struct event_base *, const struct bufferevent_ops *, enum bufferevent_options options);

/** For internal use: temporarily stop all reads on bufev, because its
 * read buffer is too full. */
void bufferevent_wm_suspend_read(struct bufferevent *bufev);
/** For internal use: temporarily stop all reads on bufev, because its
 * read buffer is too full. */
void bufferevent_wm_unsuspend_read(struct bufferevent *bufev);

/** Internal: Set up locking on a bufferevent.  If lock is set, use it.
 * Otherwise, use a new lock. */
int bufferevent_enable_locking(struct bufferevent *bufev, void *lock);
/** Internal: Increment the reference count on bufev. */
void bufferevent_incref(struct bufferevent *bufev);
/** Internal: Lock bufev and increase its reference count.
 * unlocking it otherwise. */
void _bufferevent_incref_and_lock(struct bufferevent *bufev);
/** Internal: Drop the reference count on bufev, freeing as necessary, and
 * unlocking it otherwise. */
void _bufferevent_decref_and_unlock(struct bufferevent *bufev);

/** Internal: If callbacks are deferred and we have a read callback, schedule
 * a readcb.  Otherwise just run the readcb. */
void _bufferevent_run_readcb(struct bufferevent *bufev);
/** Internal: If callbacks are deferred and we have a write callback, schedule
 * a writecb.  Otherwise just run the writecb. */
void _bufferevent_run_writecb(struct bufferevent *bufev);
/** Internal: If callbacks are deferred and we have an eventcb, schedule
 * it to run with events "what".  Otherwise just run the eventcb. */
void _bufferevent_run_eventcb(struct bufferevent *bufev, short what);

/** Internal: Add the event 'ev' with timeout tv, unless tv is set to 0, in
 * which case add ev with no timeout. */
int _bufferevent_add_event(struct event *ev, const struct timeval *tv);

/* =========
 * These next functions implement timeouts for bufferevents that aren't doing
 * anything else with ev_read and ev_write, to handle timeouts.
 * ========= */
/** Internal use: Set up the ev_read and ev_write callbacks so that
 * the other "generic_timeout" functions will work on it.  Call this from
 * the constructor function. */
void _bufferevent_init_generic_timeout_cbs(struct bufferevent *bev);
/** Internal use: Delete the ev_read and ev_write callbacks if they're pending.
 * Call this from the destructor function. */
void _bufferevent_del_generic_timeout_cbs(struct bufferevent *bev);
/** Internal use: Add or delete the generic timeout events as appropriate.
 * (If an event is enabled and a timeout is set, we add the event.  Otherwise
 * we delete it.)  Call this from anything that changes the timeout values,
 * that enabled EV_READ or EV_WRITE, or that disables EV_READ or EV_WRITE. */
void _bufferevent_generic_adj_timeouts(struct bufferevent *bev);

/** Internal use: We have just successfully read data into an inbuf, so
 * reset the read timeout (if any). */
#define BEV_RESET_GENERIC_READ_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_read))		\
			event_add(&(bev)->ev_read, &(bev)->timeout_read); \
	} while (0)
/** Internal use: We have just successfully written data from an inbuf, so
 * reset the read timeout (if any). */
#define BEV_RESET_GENERIC_WRITE_TIMEOUT(bev)				\
	do {								\
		if (evutil_timerisset(&(bev)->timeout_write))		\
			event_add(&(bev)->ev_write, &(bev)->timeout_write); \
	} while (0)

/** Internal: Given a bufferevent, return its corresponding
 * bufferevent_private. */
#define BEV_UPCAST(b) EVUTIL_UPCAST((b), struct bufferevent_private, bev)

/** Internal: Grab the lock (if any) on a bufferevent */
#define BEV_LOCK(b) do {						\
		struct bufferevent_private *locking =  BEV_UPCAST(b);	\
		if (locking->lock)					\
			EVLOCK_LOCK(locking->lock, EVTHREAD_WRITE);	\
	} while(0)

/** Internal: Release the lock (if any) on a bufferevent */
#define BEV_UNLOCK(b) do {						\
		struct bufferevent_private *locking =  BEV_UPCAST(b);	\
		if (locking->lock)					\
			EVLOCK_UNLOCK(locking->lock, EVTHREAD_WRITE);	\
	} while(0)

#ifdef __cplusplus
}
#endif


#endif /* _BUFFEREVENT_INTERNAL_H_ */
