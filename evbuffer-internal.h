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
/* minimum allocation */
#define MIN_BUFFER_SIZE	256

struct evbuffer_cb_entry {
	TAILQ_ENTRY(evbuffer_cb_entry) next;
	evbuffer_cb cb;
	void *cbarg;
	ev_uint32_t flags;
	size_t size_before_suspend;
};

struct evbuffer_chain;
struct evbuffer {
	struct evbuffer_chain *first;
	struct evbuffer_chain *last;
	struct evbuffer_chain *previous_to_last;

	size_t total_len;	/* total length of all buffers */

	evbuffer_cb cb;
	void *cbarg;

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

/* callback for reference buffer */
struct evbuffer_chain_reference {
	void (*cleanupfn)(void *extra);
	void *extra;
};

#define EVBUFFER_CHAIN_SIZE sizeof(struct evbuffer_chain)
#define EVBUFFER_CHAIN_EXTRA(t, c) (t *)((struct evbuffer_chain *)(c) + 1)

#ifdef __cplusplus
}
#endif

#endif /* _EVBUFFER_INTERNAL_H_ */
