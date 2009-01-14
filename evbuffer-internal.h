/*
 * Copyright (c) 2000-2004 Niels Provos <provos@citi.umich.edu>
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
#ifndef _EVBUFFER_INTERNAL_H_
#define _EVBUFFER_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#include "evutil.h"

/* minimum allocation */
#define MIN_BUFFER_SIZE	256

struct evbuffer_chain;
struct evbuffer {
	struct evbuffer_chain *first;
	struct evbuffer_chain *last;
	struct evbuffer_chain *previous_to_last;

	size_t total_len;	/* total length of all buffers */

	void (*cb)(struct evbuffer *, size_t, size_t, void *);
	void *cbarg;
};

struct evbuffer_chain {
	/** points to next buffer in the chain */
	struct evbuffer_chain *next;
	
	size_t buffer_len; /**< total allocation available in the buffer field. */

	size_t misalign; /**< unused space at the beginning of buffer */
	size_t off;	/**< Offset into buffer + misalign at which to start writing.
				 * In other words, the total number of bytes actually stored
				 * in buffer. */

	u_char buffer[1];
};

#define EVBUFFER_CHAIN_SIZE evutil_offsetof(struct evbuffer_chain, buffer[0])

#ifdef __cplusplus
}
#endif

#endif /* _EVBUFFER_INTERNAL_H_ */
