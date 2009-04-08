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
#ifndef _EVBUFFER_INTERNAL_H_
#define _EVBUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "event-config.h"
#include "evutil.h"

#include <sys/queue.h>
/* minimum allocation for a chain. */
#define MIN_BUFFER_SIZE	256

/** A single evbuffer callback for an evbuffer. */
struct evbuffer_cb_entry {
        /** Structures to implement a doubly-linked queue of callbacks */
	TAILQ_ENTRY(evbuffer_cb_entry) next;
        /** The callback function to invoke when this callback is called */
        union {
                evbuffer_cb_func cb_func;
                evbuffer_cb cb_obsolete;
        } cb;
        /** Argument to pass to cb. */
	void *cbarg;
        /** Currently set flags on this callback. */
	ev_uint32_t flags;
#if 0
        /** Size of the evbuffer before this callback was suspended, or 0
            if this callback is not suspended. */
	size_t size_before_suspend;
#endif
};

struct evbuffer_chain;
struct evbuffer {
	struct evbuffer_chain *first;
	struct evbuffer_chain *last;
	struct evbuffer_chain *previous_to_last;

	size_t total_len;	/* total length of all buffers */

	evbuffer_cb cb;
	void *cbarg;

        size_t n_add_for_cb;
        size_t n_del_for_cb;

#ifndef _EVENT_DISABLE_THREAD_SUPPORT
        void *lock;
#endif
	unsigned own_lock : 1;

        int lock_count;

	TAILQ_HEAD(evbuffer_cb_queue, evbuffer_cb_entry) callbacks;
};

struct evbuffer_chain {
	/** points to next buffer in the chain */
	struct evbuffer_chain *next;

	/** total allocation available in the buffer field. */
	size_t buffer_len;

	/** unused space at the beginning of buffer or an offset into a
	 * file for sendfile buffers. */
	off_t misalign;

	/** Offset into buffer + misalign at which to start writing.
	 * In other words, the total number of bytes actually stored
	 * in buffer. */
	size_t off;

	/** Set if special handling is required for this chain */
	unsigned flags;
#define EVBUFFER_MMAP		0x0001  /**< memory in buffer is mmaped */
#define EVBUFFER_SENDFILE	0x0002  /**< a chain used for sendfile */
#define EVBUFFER_REFERENCE	0x0004	/**< a chain with a mem reference */
#define EVBUFFER_IMMUTABLE	0x0008  /**< read-only chain */
	/** a chain that mustn't be reallocated or freed, or have its contents
	 * memmoved, until the chain is un-pinned. */
#define EVBUFFER_MEM_PINNED_R	0x0010
#define EVBUFFER_MEM_PINNED_W	0x0020
#define EVBUFFER_MEM_PINNED_ANY (EVBUFFER_MEM_PINNED_R|EVBUFFER_MEM_PINNED_W)
	/** a chain that should be freed, but can't be freed until it is
	 * un-pinned. */
#define EVBUFFER_DANGLING	0x0040

	/** Usually points to the read-write memory belonging to this
	 * buffer allocated as part of the evbuffer_chain allocation.
	 * For mmap, this can be a read-only buffer and
	 * EVBUFFER_IMMUTABLE will be set in flags.  For sendfile, it
	 * may point to NULL.
	 */
	u_char *buffer;
};

/* this is currently used by both mmap and sendfile */
/* TODO(niels): something strange needs to happen for Windows here, I am not
 * sure what that is, but it needs to get looked into.
 */
struct evbuffer_chain_fd {
	int fd;	/**< the fd associated with this chain */
};

/** callback for a reference buffer; lets us know what to do with it when
 * we're done with it. */
struct evbuffer_chain_reference {
	void (*cleanupfn)(void *extra);
	void *extra;
};

#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)

#define ASSERT_EVBUFFER_LOCKED(buffer)                  \
	do {                                            \
		assert((buffer)->lock_count > 0);       \
	} while (0)
#define ASSERT_EVBUFFER_UNLOCKED(buffer)                  \
	do {                                            \
		assert((buffer)->lock_count == 0);	\
	} while (0)
#define _EVBUFFER_INCREMENT_LOCK_COUNT(buffer)                 \
	do {                                                   \
		((struct evbuffer*)(buffer))->lock_count++;    \
	} while (0)
#define _EVBUFFER_DECREMENT_LOCK_COUNT(buffer)		      \
	do {						      \
		ASSERT_EVBUFFER_LOCKED(buffer);		      \
		((struct evbuffer*)(buffer))->lock_count--;   \
	} while (0)

#define EVBUFFER_LOCK(buffer, mode)					\
	do {								\
		EVLOCK_LOCK((buffer)->lock, (mode));			\
		_EVBUFFER_INCREMENT_LOCK_COUNT(buffer);			\
	} while(0)
#define EVBUFFER_UNLOCK(buffer, mode)					\
	do {								\
		_EVBUFFER_DECREMENT_LOCK_COUNT(buffer);			\
		EVLOCK_UNLOCK((buffer)->lock, (mode));			\
	} while(0)

#define EVBUFFER_LOCK2(buffer1, buffer2)				\
	do {								\
		EVLOCK_LOCK2((buffer1)->lock, (buffer2)->lock,		\
		    EVTHREAD_WRITE, EVTHREAD_WRITE);			\
		_EVBUFFER_INCREMENT_LOCK_COUNT(buffer1);		\
		_EVBUFFER_INCREMENT_LOCK_COUNT(buffer2);		\
	} while(0)
#define EVBUFFER_UNLOCK2(buffer1, buffer2)				\
	do {								\
		_EVBUFFER_DECREMENT_LOCK_COUNT(buffer1);		\
		_EVBUFFER_DECREMENT_LOCK_COUNT(buffer2);		\
		EVLOCK_UNLOCK2((buffer1)->lock, (buffer2)->lock,	\
		    EVTHREAD_WRITE, EVTHREAD_WRITE);			\
	} while(0)

#ifdef __cplusplus
}
#endif

#endif /* _EVBUFFER_INTERNAL_H_ */
