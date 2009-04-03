/*
 * Copyright (c) 2002-2007 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef _EVENT_HAVE_VASPRINTF
/* If we have vasprintf, we need to define this before we include stdio.h. */
#define _GNU_SOURCE
#endif

#include <sys/types.h>

#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef _EVENT_HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef _EVENT_HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#ifdef _EVENT_HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef _EVENT_HAVE_SYS_SENDFILE_H
#include <sys/sendfile.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _EVENT_HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/buffer_compat.h"
#include "event-config.h"
#include "log-internal.h"
#include "mm-internal.h"
#include "util-internal.h"
#include "evbuffer-internal.h"

/* some systems do not have MAP_FAILED */
#ifndef MAP_FAILED
#define MAP_FAILED	((void *)-1)
#endif

/* send file support */
#if defined(_EVENT_HAVE_SYS_SENDFILE_H) && defined(_EVENT_HAVE_SENDFILE) && defined(__linux__)
#define USE_SENDFILE		1
#define SENDFILE_IS_LINUX	1
#elif defined(_EVENT_HAVE_SENDFILE) && (defined(__FreeBSD__) || defined(__APPLE__))
#define USE_SENDFILE		1
#define SENDFILE_IS_FREEBSD	1
#endif

#ifdef USE_SENDFILE
static int use_sendfile = 1;
#endif
#ifdef _EVENT_HAVE_MMAP
static int use_mmap = 1;
#endif


/* Mask of user-selectable callback flags. */
#define EVBUFFER_CB_USER_FLAGS      0xffff
/* Mask of all internal-use-only flags. */
#define EVBUFFER_CB_INTERNAL_FLAGS  0xffff0000
/* Flag set on suspended callbacks. */
#define EVBUFFER_CB_SUSPENDED          0x00010000
/* Flag set if we should invoke the callback on wakeup. */
#define EVBUFFER_CB_CALL_ON_UNSUSPEND  0x00020000

/* evbuffer_chain support */
#define CHAIN_SPACE_PTR(ch) ((ch)->buffer + (ch)->misalign + (ch)->off)
#define CHAIN_SPACE_LEN(ch) ((ch)->flags & EVBUFFER_IMMUTABLE ? \
	    0 : (ch)->buffer_len - ((ch)->misalign + (ch)->off))

static struct evbuffer_chain *
evbuffer_chain_new(size_t size)
{
	struct evbuffer_chain *chain;
	size_t to_alloc;

	size += EVBUFFER_CHAIN_SIZE;

	/* get the next largest memory that can hold the buffer */
	to_alloc = MIN_BUFFER_SIZE;
	while (to_alloc < size)
		to_alloc <<= 1;

	/* we get everything in one chunk */
	if ((chain = mm_malloc(to_alloc)) == NULL)
		return (NULL);

	memset(chain, 0, EVBUFFER_CHAIN_SIZE);

	chain->buffer_len = to_alloc - EVBUFFER_CHAIN_SIZE;

	/* this way we can manipulate the buffer to different addresses,
	 * which is required for mmap for example.
	 */
	chain->buffer = EVBUFFER_CHAIN_EXTRA(u_char, chain);

	return (chain);
}

static inline void
evbuffer_chain_free(struct evbuffer_chain *chain)
{
	if (chain->flags & (EVBUFFER_MMAP|EVBUFFER_SENDFILE|
		EVBUFFER_REFERENCE)) {
		if (chain->flags & EVBUFFER_REFERENCE) {
			struct evbuffer_chain_reference *info =
			    EVBUFFER_CHAIN_EXTRA(
				    struct evbuffer_chain_reference,
				    chain);
			if (info->cleanupfn)
				(*info->cleanupfn)(info->extra);
		}
#ifdef _EVENT_HAVE_MMAP
		if (chain->flags & EVBUFFER_MMAP) {
			struct evbuffer_chain_fd *info =
			    EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_fd,
				chain);
			if (munmap(chain->buffer, chain->buffer_len) == -1)
				event_warn("%s: munmap failed", __func__);
			if (close(info->fd) == -1)
				event_warn("%s: close(%d) failed",
				    __func__, info->fd);
		}
#endif
#ifdef USE_SENDFILE
		if (chain->flags & EVBUFFER_SENDFILE) {
			struct evbuffer_chain_fd *info =
			    EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_fd,
				chain);
			if (close(info->fd) == -1)
				event_warn("%s: close(%d) failed",
				    __func__, info->fd);
		}
#endif
	}
	mm_free(chain);
}

static inline void
evbuffer_chain_insert(struct evbuffer *buf, struct evbuffer_chain *chain)
{
	if (buf->first == NULL) {
		buf->first = buf->last = chain;
		buf->previous_to_last = NULL;
	} else {
		/* the last chain is empty so we can just drop it */
		if (buf->last->off == 0) {
			evbuffer_chain_free(buf->last);
			buf->previous_to_last->next = chain;
			buf->last = chain;
		} else {
			buf->previous_to_last = buf->last;
			buf->last->next = chain;
			buf->last = chain;
		}
	}

	buf->total_len += chain->off;
}

struct evbuffer *
evbuffer_new(void)
{
	struct evbuffer *buffer;

	buffer = mm_calloc(1, sizeof(struct evbuffer));

	TAILQ_INIT(&buffer->callbacks);

	return (buffer);
}

static inline void
evbuffer_invoke_callbacks(struct evbuffer *buffer, size_t old_size)
{
	struct evbuffer_cb_entry *cbent, *next;
	size_t new_size = buffer->total_len;
	if (TAILQ_EMPTY(&buffer->callbacks) || old_size == new_size)
		return;


	for (cbent = TAILQ_FIRST(&buffer->callbacks);
	     cbent != TAILQ_END(&buffer->callbacks);
	     cbent = next) {
		/* Get the 'next' pointer now in case this callback decides
		 * to remove itself or something. */
		next = TAILQ_NEXT(cbent, next);
		if ((cbent->flags & EVBUFFER_CB_ENABLED)) {
			if ((cbent->flags & EVBUFFER_CB_SUSPENDED))
				cbent->flags |= EVBUFFER_CB_CALL_ON_UNSUSPEND;
			else
				cbent->cb(buffer,
					  old_size, new_size, cbent->cbarg);
		}
	}
}

static void
evbuffer_remove_all_callbacks(struct evbuffer *buffer)
{
	struct evbuffer_cb_entry *cbent;
	while ((cbent = TAILQ_FIRST(&buffer->callbacks))) {
	    TAILQ_REMOVE(&buffer->callbacks, cbent, next);
	    mm_free(cbent);
	}
}

void
evbuffer_free(struct evbuffer *buffer)
{
	struct evbuffer_chain *chain, *next;
	for (chain = buffer->first; chain != NULL; chain = next) {
		next = chain->next;
		evbuffer_chain_free(chain);
	}
	evbuffer_remove_all_callbacks(buffer);
	mm_free(buffer);
}

size_t
evbuffer_get_length(const struct evbuffer *buffer)
{
	return (buffer->total_len);
}

size_t
evbuffer_get_contiguous_space(const struct evbuffer *buf)
{
	struct evbuffer_chain *chain = buf->first;

	return (chain != NULL ? chain->off : 0);
}

unsigned char *
evbuffer_reserve_space(struct evbuffer *buf, size_t size)
{
	struct evbuffer_chain *chain;

	if (evbuffer_expand(buf, size) == -1)
		return (NULL);

	chain = buf->last;

	return (chain->buffer + chain->misalign + chain->off);
}

int
evbuffer_commit_space(struct evbuffer *buf, size_t size)
{
	struct evbuffer_chain *chain = buf->last;

	if (chain == NULL ||
	    chain->buffer_len - chain->off - chain->misalign < size)
		return (-1);

	chain->off += size;
	buf->total_len += size;

	return (0);
}

#define ZERO_CHAIN(dst) do { \
		(dst)->first = NULL;		\
		(dst)->last = NULL;		\
		(dst)->previous_to_last = NULL; \
		(dst)->total_len = 0;		\
	} while (0)

#define COPY_CHAIN(dst, src) do { \
		(dst)->first = (src)->first;			   \
		(dst)->previous_to_last = (src)->previous_to_last; \
		(dst)->last = (src)->last;			   \
		(dst)->total_len = (src)->total_len;		   \
	} while (0)

#define APPEND_CHAIN(dst, src) do {					\
		(dst)->last->next = (src)->first;			\
		(dst)->previous_to_last = (src)->previous_to_last ?	\
		    (src)->previous_to_last : (dst)->last;		\
		(dst)->last = (src)->last;				\
		(dst)->total_len += (src)->total_len;			\
	} while (0)

#define PREPEND_CHAIN(dst, src) do {				\
		(src)->last->next = (dst)->first;		\
		(dst)->first = (src)->first;			\
		(dst)->total_len += (src)->total_len;		\
		if ((dst)->previous_to_last == NULL)		\
			(dst)->previous_to_last = (src)->last;	\
	} while (0)


int
evbuffer_add_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	size_t out_total_len = outbuf->total_len;
	size_t in_total_len = inbuf->total_len;

	if (in_total_len == 0 || outbuf == inbuf)
		return (0);

	if (out_total_len == 0) {
		COPY_CHAIN(outbuf, inbuf);
	} else {
		APPEND_CHAIN(outbuf, inbuf);
	}

	/* remove everything from inbuf */
	ZERO_CHAIN(inbuf);

	evbuffer_invoke_callbacks(inbuf, in_total_len);
	evbuffer_invoke_callbacks(outbuf, out_total_len);

	return (0);
}

void
evbuffer_prepend_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	size_t out_total_len = outbuf->total_len;
	size_t in_total_len = inbuf->total_len;

	if (!in_total_len || inbuf == outbuf)
		return;

	if (out_total_len == 0) {
		COPY_CHAIN(outbuf, inbuf);
	} else {
		PREPEND_CHAIN(outbuf, inbuf);
	}

	/* remove everything from inbuf */
	ZERO_CHAIN(inbuf);

	evbuffer_invoke_callbacks(inbuf, in_total_len);
	evbuffer_invoke_callbacks(outbuf, out_total_len);
}

void
evbuffer_drain(struct evbuffer *buf, size_t len)
{
	struct evbuffer_chain *chain, *next;
	size_t old_len = buf->total_len;

	if (old_len == 0)
		return;

	if (len >= old_len) {
		for (chain = buf->first; chain != NULL; chain = next) {
			next = chain->next;

			evbuffer_chain_free(chain);
		}

		ZERO_CHAIN(buf);
	} else {
		buf->total_len -= len;

		for (chain = buf->first; len >= chain->off; chain = next) {
			next = chain->next;
			len -= chain->off;

			evbuffer_chain_free(chain);
		}

		buf->first = chain;
		if (buf->first == buf->last)
			buf->previous_to_last = NULL;
		chain->misalign += len;
		chain->off -= len;
	}

	/* Tell someone about changes in this buffer */
	evbuffer_invoke_callbacks(buf, old_len);
}

/* Reads data from an event buffer and drains the bytes read */

int
evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datlen)
{
        /*XXX fails badly on sendfile case. */
	struct evbuffer_chain *chain = buf->first, *tmp;
	char *data = data_out;
	size_t nread;

	if (datlen >= buf->total_len)
		datlen = buf->total_len;

	if (datlen == 0)
		return (0);

	nread = datlen;

	while (datlen && datlen >= chain->off) {
		memcpy(data, chain->buffer + chain->misalign, chain->off);
		data += chain->off;
		datlen -= chain->off;

		tmp = chain;
		chain = chain->next;
		evbuffer_chain_free(tmp);
	}

	buf->first = chain;
	if (chain == NULL)
		buf->last = NULL;
	if (buf->first == buf->last)
		buf->previous_to_last = NULL;

	if (datlen) {
		memcpy(data, chain->buffer + chain->misalign, datlen);
		chain->misalign += datlen;
		chain->off -= datlen;
	}

	buf->total_len -= nread;

	if (nread)
		evbuffer_invoke_callbacks(buf, buf->total_len + nread);

	return (nread);
}

/* reads data from the src buffer to the dst buffer, avoids memcpy as
 * possible. */
int
evbuffer_remove_buffer(struct evbuffer *src, struct evbuffer *dst,
    size_t datlen)
{
	/*XXX We should have an option to force this to be zero-copy.*/

	/*XXX can fail badly on sendfile case. */
	struct evbuffer_chain *chain = src->first;
	struct evbuffer_chain *previous = chain, *previous_to_previous = NULL;
	size_t nread = 0;

	if (datlen == 0 || dst == src)
		return (0);

	/* short-cut if there is no more data buffered */
	if (datlen >= src->total_len) {
		datlen = src->total_len;
		evbuffer_add_buffer(dst, src);
		return (datlen);
	}

	/* removes chains if possible */
	while (chain->off <= datlen) {
		nread += chain->off;
		datlen -= chain->off;
		previous_to_previous = previous;
		previous = chain;
		chain = chain->next;
	}

	if (nread) {
		/* we can remove the chain */
		if (dst->first == NULL) {
			dst->first = src->first;
		} else {
			dst->last->next = src->first;
		}
		dst->previous_to_last = previous_to_previous;
		dst->last = previous;
		previous->next = NULL;
		src->first = chain;
		if (src->first == src->last)
			src->previous_to_last = NULL;

		dst->total_len += nread;
	}

	/* we know that there is more data in the src buffer than
	 * we want to read, so we manually drain the chain */
	evbuffer_add(dst, chain->buffer + chain->misalign, datlen);
	chain->misalign += datlen;
	chain->off -= datlen;
	nread += datlen;

	src->total_len -= nread;

	if (nread) {
		evbuffer_invoke_callbacks(dst, dst->total_len - nread);
		evbuffer_invoke_callbacks(src, src->total_len + nread);
	}

	return (nread);
}

unsigned char *
evbuffer_pullup(struct evbuffer *buf, ssize_t size)
{
	struct evbuffer_chain *chain = buf->first, *next, *tmp;
	unsigned char *buffer;

	if (size == -1)
		size = buf->total_len;
	/* if size > buf->total_len, we cannot guarantee to the user that she
	 * is going to have a long enough buffer afterwards; so we return
	 * NULL */
	if (size == 0 || size > buf->total_len)
		return (NULL);

	/* No need to pull up anything; the first size bytes are
	 * already here. */
	if (chain->off >= size)
		return chain->buffer + chain->misalign;

	if (chain->buffer_len - chain->misalign >= size) {
		/* already have enough space in the first chain */
		size_t old_off = chain->off;
		buffer = chain->buffer + chain->misalign + chain->off;
		tmp = chain;
		tmp->off = size;
		size -= old_off;
		chain = chain->next;
	} else {
		if ((tmp = evbuffer_chain_new(size)) == NULL) {
			event_warn("%s: out of memory\n", __func__);
			return (NULL);
		}
		buffer = tmp->buffer;
		tmp->off = size;
		buf->first = tmp;
	}

	/* TODO(niels): deal with buffers that point to NULL like sendfile */

	/* Copy and free every chunk that will be entirely pulled into tmp */
	for (; chain != NULL && size >= chain->off; chain = next) {
		next = chain->next;

		memcpy(buffer, chain->buffer + chain->misalign, chain->off);
		size -= chain->off;
		buffer += chain->off;

		evbuffer_chain_free(chain);
	}

	if (chain != NULL) {
		memcpy(buffer, chain->buffer + chain->misalign, size);
		chain->misalign += size;
		chain->off -= size;
		if (chain == buf->last)
			buf->previous_to_last = tmp;
	} else {
		buf->last = tmp;
		/* the last is already the first, so we have no previous */
		buf->previous_to_last = NULL;
	}

	tmp->next = chain;

	return (tmp->buffer + tmp->misalign);
}

/*
 * Reads a line terminated by either '\r\n', '\n\r' or '\r' or '\n'.
 * The returned buffer needs to be freed by the called.
 */
char *
evbuffer_readline(struct evbuffer *buffer)
{
	return evbuffer_readln(buffer, NULL, EVBUFFER_EOL_ANY);
}

struct evbuffer_iterator {
	struct evbuffer_chain *chain;
	int off;
};

static inline int
evbuffer_strchr(struct evbuffer_iterator *it, const char chr)
{
	struct evbuffer_chain *chain = it->chain;
	int i = it->off, count = 0;
	while (chain != NULL) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		for (; i < chain->off; ++i, ++count) {
			if (buffer[i] == chr) {
				it->chain = chain;
				it->off = i;
				return (count);
			}
		}
		i = 0;
		chain = chain->next;
	}

	return (-1);
}

static inline int
evbuffer_strpbrk(struct evbuffer_iterator *it, const char *chrset)
{
	struct evbuffer_chain *chain = it->chain;
	int i = it->off, count = 0;
	while (chain != NULL) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		for (; i < chain->off; ++i, ++count) {
			const char *p = chrset;
			while (*p) {
				if (buffer[i] == *p++) {
					it->chain = chain;
					it->off = i;
					return (count);
				}
			}
		}
		i = 0;
		chain = chain->next;
	}

	return (-1);
}

static inline int
evbuffer_strspn(
	struct evbuffer_chain *chain, int i, const char *chrset)
{
	int count = 0;
	while (chain != NULL) {
		char *buffer = (char *)chain->buffer + chain->misalign;
		for (; i < chain->off; ++i) {
			const char *p = chrset;
			while (*p) {
				if (buffer[i] == *p++)
					goto next;
			}
			return count;
		next:
			++count;
		}
		i = 0;
		chain = chain->next;
	}

	return (count);
}

static inline int
evbuffer_getchr(struct evbuffer_iterator *it, char *pchr)
{
	struct evbuffer_chain *chain = it->chain;
	int off = it->off;

	while (off >= chain->off) {
		off -= chain->off;
		chain = chain->next;
		if (chain == NULL)
			return (-1);
	}

	*pchr = chain->buffer[chain->misalign + off];

	it->chain = chain;
	it->off = off;

	return (0);
}

char *
evbuffer_readln(struct evbuffer *buffer, size_t *n_read_out,
		enum evbuffer_eol_style eol_style)
{
	struct evbuffer_iterator it;
	char *line, chr;
	unsigned int n_to_copy, extra_drain;
	int count = 0;

	it.chain = buffer->first;
	it.off = 0;

	/* the eol_style determines our first stop character and how many
	 * characters we are going to drain afterwards. */
	switch (eol_style) {
	case EVBUFFER_EOL_ANY:
		count = evbuffer_strpbrk(&it, "\r\n");
		if (count == -1)
			return (NULL);

		n_to_copy = count;
		extra_drain = evbuffer_strspn(it.chain, it.off, "\r\n");
		break;
	case EVBUFFER_EOL_CRLF_STRICT: {
		int tmp;
		while ((tmp = evbuffer_strchr(&it, '\r')) != -1) {
			count += tmp;
			++it.off;
			if (evbuffer_getchr(&it, &chr) == -1)
				return (NULL);
			if (chr == '\n') {
				n_to_copy = count;
				break;
			}
			++count;
		}
		if (tmp == -1)
			return (NULL);
		extra_drain = 2;
		break;
	}
	case EVBUFFER_EOL_CRLF:
		/* we might strip a preceding '\r' */
	case EVBUFFER_EOL_LF:
		if ((count = evbuffer_strchr(&it, '\n')) == -1)
			return (NULL);
		n_to_copy = count;
		extra_drain = 1;
		break;
	default:
		return (NULL);
	}

	if ((line = mm_malloc(n_to_copy+1)) == NULL) {
		event_warn("%s: out of memory\n", __func__);
		evbuffer_drain(buffer, n_to_copy + extra_drain);
		return (NULL);
	}

	evbuffer_remove(buffer, line, n_to_copy);
	if (eol_style == EVBUFFER_EOL_CRLF &&
	    n_to_copy && line[n_to_copy-1] == '\r')
		--n_to_copy;
	line[n_to_copy] = '\0';

	evbuffer_drain(buffer, extra_drain);
	if (n_read_out)
		*n_read_out = (size_t)n_to_copy;

	return (line);
}

#define EVBUFFER_CHAIN_MAX_AUTO_SIZE 4096

/* Adds data to an event buffer */

int
evbuffer_add(struct evbuffer *buf, const void *data_in, size_t datlen)
{
	struct evbuffer_chain *chain = buf->last, *tmp;
	const unsigned char *data = data_in;
	size_t old_len = buf->total_len, remain, to_alloc;

	/* If there are no chains allocated for this buffer, allocate one
	 * big enough to hold all the data. */
	if (chain == NULL) {
		if (evbuffer_expand(buf, datlen) == -1)
			return (-1);
		chain = buf->last;
	}

	if ((chain->flags & EVBUFFER_IMMUTABLE) == 0) {
		remain = chain->buffer_len - chain->misalign - chain->off;
		if (remain >= datlen) {
			/* there's enough space to hold all the data in the
			 * current last chain */
			memcpy(chain->buffer + chain->misalign + chain->off,
			    data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			goto out;
		} else if (chain->misalign >= datlen) {
			/* we can fit the data into the misalignment */
			memmove(chain->buffer,
			    chain->buffer + chain->misalign,
			    chain->off);
			chain->misalign = 0;

			memcpy(chain->buffer + chain->off, data, datlen);
			chain->off += datlen;
			buf->total_len += datlen;
			goto out;
		}
	} else {
		/* we cannot write any data to the last chain */
		remain = 0;
	}

	/* we need to add another chain */
	to_alloc = chain->buffer_len;
	if (to_alloc <= EVBUFFER_CHAIN_MAX_AUTO_SIZE/2)
		to_alloc <<= 1;
	if (datlen > to_alloc)
		to_alloc = datlen;
	tmp = evbuffer_chain_new(to_alloc);
	if (tmp == NULL)
		return (-1);

	if (remain) {
		memcpy(chain->buffer + chain->misalign + chain->off,
		    data, remain);
		chain->off += remain;
		buf->total_len += remain;
	}

	data += remain;
	datlen -= remain;

	memcpy(tmp->buffer, data, datlen);
	tmp->off = datlen;
	evbuffer_chain_insert(buf, tmp);

out:
	evbuffer_invoke_callbacks(buf, old_len);

	return (0);
}

int
evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datlen)
{
	struct evbuffer_chain *chain = buf->first, *tmp;
	size_t old_len = buf->total_len;

	if (chain == NULL) {
		if (evbuffer_expand(buf, datlen) == -1)
			return (-1);
		chain = buf->first;
		chain->misalign = chain->buffer_len;
	}

	/* we cannot touch immutable buffers */
	if ((chain->flags & EVBUFFER_IMMUTABLE) == 0) {
		if (chain->misalign >= datlen) {
			/* we have enough space */
			memcpy(chain->buffer + chain->misalign - datlen,
			    data, datlen);
			chain->off += datlen;
			chain->misalign -= datlen;
			buf->total_len += datlen;
			goto out;
		} else if (chain->misalign) {
			memcpy(chain->buffer,
			    (char*)data + datlen - chain->misalign,
			    chain->misalign);
			chain->off += chain->misalign;
			buf->total_len += chain->misalign;
			datlen -= chain->misalign;
			chain->misalign = 0;
		}
	}

	/* we need to add another chain */
	if ((tmp = evbuffer_chain_new(datlen)) == NULL)
		return (-1);
	buf->first = tmp;
	if (buf->previous_to_last == NULL)
		buf->previous_to_last = tmp;
	tmp->next = chain;

	tmp->off = datlen;
	tmp->misalign = tmp->buffer_len - datlen;

	memcpy(tmp->buffer + tmp->misalign, data, datlen);
	buf->total_len += datlen;

out:
	evbuffer_invoke_callbacks(buf, old_len);

	return (0);
}

/** Helper: realigns the memory in chain->buffer so that misalign is 0. */
static void
evbuffer_chain_align(struct evbuffer_chain *chain)
{
	assert(!(chain->flags & EVBUFFER_IMMUTABLE));
	memmove(chain->buffer, chain->buffer + chain->misalign, chain->off);
	chain->misalign = 0;
}

/* Expands the available space in the event buffer to at least datlen */

int
evbuffer_expand(struct evbuffer *buf, size_t datlen)
{
	/* XXX we should either make this function less costly, or call it
	 * less often.  */
	struct evbuffer_chain *chain = buf->last, *tmp;
	size_t need, length;

	if (chain == NULL || (chain->flags & EVBUFFER_IMMUTABLE)) {
		chain = evbuffer_chain_new(datlen);
		if (chain == NULL)
			return (-1);

		evbuffer_chain_insert(buf, chain);
		return (0);
	}

	need = chain->misalign + chain->off + datlen;

	/* If we can fit all the data, then we don't have to do anything */
	if (chain->buffer_len >= need)
		return (0);

	/* If the misalignment plus the remaining space fulfils our
	 * data needs, we just force an alignment to happen.
	 * Afterwards, we have enough space.
	 */
	if (chain->buffer_len - chain->off >= datlen) {
		evbuffer_chain_align(chain);
		return (0);
	}

	/* figure out how much space we need */
	length = chain->buffer_len - chain->misalign + datlen;
	tmp = evbuffer_chain_new(length);
	if (tmp == NULL)
		return (-1);
	/* copy the data over that we had so far */
	tmp->off = chain->off;
	tmp->misalign = 0;
	memcpy(tmp->buffer, chain->buffer + chain->misalign, chain->off);

	/* fix up the chain */
	if (buf->first == chain)
		buf->first = tmp;
	if (buf->previous_to_last)
		buf->previous_to_last->next = tmp;
	buf->last = tmp;

	evbuffer_chain_free(chain);

	return (0);
}

/* Make sure that datlen bytes are available for writing in the last two
 * chains.  Never copies or moves data. */
static int
_evbuffer_expand_fast(struct evbuffer *buf, size_t datlen)
{
	struct evbuffer_chain *chain = buf->last, *tmp;
	size_t avail, avail_in_prev = 0;

	if (chain == NULL || (chain->flags & EVBUFFER_IMMUTABLE)) {
		chain = evbuffer_chain_new(datlen);
		if (chain == NULL)
			return (-1);

		evbuffer_chain_insert(buf, chain);
		return (0);
	}

	/* How many bytes can we stick at the end of chain? */

	if (chain->off) {
		avail = chain->buffer_len - (chain->off + chain->misalign);
		avail_in_prev = 0;
	} else {
		/* No data in chain; realign it. */
		chain->misalign = 0;
		avail = chain->buffer_len;
		/* Can we stick some data in the penultimate chain? */
		if (buf->previous_to_last) {
			struct evbuffer_chain *prev = buf->previous_to_last;
			avail_in_prev = CHAIN_SPACE_LEN(prev);
		}
	}

	/* If we can fit all the data, then we don't have to do anything */
	if (avail+avail_in_prev >= datlen)
		return (0);

	/* Otherwise, we need a bigger chunk. */
	if (chain->off == 0) {
		/* If there are no bytes on this chain, free it and
		   replace it with a better one. */
		/* XXX round up. */
		tmp = evbuffer_chain_new(datlen-avail_in_prev);
		if (tmp == NULL)
			return -1;
		/* XXX write functions to in new chains */
		if (buf->first == chain)
			buf->first = tmp;
		if (buf->previous_to_last)
			buf->previous_to_last->next = tmp;
		buf->last = tmp;
		evbuffer_chain_free(chain);

	} else {
		/* Add a new chunk big enough to hold what won't fit
		 * in chunk. */
		/*XXX round this up. */
		tmp = evbuffer_chain_new(datlen-avail);
		if (tmp == NULL)
			return (-1);

		buf->previous_to_last = chain;
		chain->next = tmp;
		buf->last = tmp;
	}

	return (0);
}

/*
 * Reads data from a file descriptor into a buffer.
 */

#if defined(_EVENT_HAVE_SYS_UIO_H) || defined(WIN32)
#define USE_IOVEC_IMPL
#endif

#ifdef USE_IOVEC_IMPL

#ifdef _EVENT_HAVE_SYS_UIO_H
/* number of iovec we use for writev, fragmentation is going to determine
 * how much we end up writing */
#define NUM_IOVEC 128
#define IOV_TYPE struct iovec
#define IOV_PTR_FIELD iov_base
#define IOV_LEN_FIELD iov_len
#else
#define NUM_IOVEC 16
#define IOV_TYPE WSABUF
#define IOV_PTR_FIELD buf
#define IOV_LEN_FIELD len
#endif
#endif

#define EVBUFFER_MAX_READ	4096

/* TODO(niels): should this function return ssize_t and take ssize_t
 * as howmuch? */
int
evbuffer_read(struct evbuffer *buf, evutil_socket_t fd, int howmuch)
{
	struct evbuffer_chain *chain = buf->last;
	size_t old_len = buf->total_len;
	int n = EVBUFFER_MAX_READ;
#ifdef USE_IOVEC_IMPL
	int nvecs;
#else
	unsigned char *p;
#endif

#if defined(FIONREAD)
#ifdef WIN32
	long lng = n;
	if (ioctlsocket(fd, FIONREAD, &lng) == -1 || (n=lng) == 0) {
#else
	if (ioctl(fd, FIONREAD, &n) == -1 || n == 0) {
#endif
		n = EVBUFFER_MAX_READ;
	} else if (n > EVBUFFER_MAX_READ && n > howmuch) {
		/*
		 * It's possible that a lot of data is available for
		 * reading.  We do not want to exhaust resources
		 * before the reader has a chance to do something
		 * about it.  If the reader does not tell us how much
		 * data we should read, we artifically limit it.
		 */
		if (chain == NULL || n < EVBUFFER_MAX_READ)
			n = EVBUFFER_MAX_READ;
		else if (n > chain->buffer_len << 2)
			n = chain->buffer_len << 2;
	}
#endif
	if (howmuch < 0 || howmuch > n)
		howmuch = n;

#ifdef USE_IOVEC_IMPL
	/* Since we can use iovecs, we're willing to use the last
	 * _two_ chains. */
	if (_evbuffer_expand_fast(buf, howmuch) == -1) {
		return(-1);
	} else {
		IOV_TYPE vecs[2];
		chain = buf->last;
		if (chain->off == 0 && buf->previous_to_last &&
			CHAIN_SPACE_LEN(buf->previous_to_last)) {
			/* The last chain is empty, so it's safe to
			   use the space in the next-to-last chain.
			*/
			struct evbuffer_chain *prev = buf->previous_to_last;
			vecs[0].IOV_PTR_FIELD = CHAIN_SPACE_PTR(prev);
			vecs[0].IOV_LEN_FIELD = CHAIN_SPACE_LEN(prev);
			vecs[1].IOV_PTR_FIELD = CHAIN_SPACE_PTR(chain);
			vecs[1].IOV_LEN_FIELD = CHAIN_SPACE_LEN(chain);
			if (vecs[0].IOV_LEN_FIELD >= howmuch) {
				/* The next-to-last chain has enough
				 * space on its own. */
				nvecs = 1;
			} else {
				/* We'll need both chains. */
				nvecs = 2;
				if (vecs[0].IOV_LEN_FIELD + vecs[1].IOV_LEN_FIELD > howmuch) {
					vecs[1].IOV_LEN_FIELD = howmuch - vecs[0].IOV_LEN_FIELD;
				}
			}
		} else {
			/* There's data in the last chain, so we're
			 * not allowed to use the next-to-last. */
			nvecs = 1;
			vecs[0].IOV_PTR_FIELD = CHAIN_SPACE_PTR(chain);
			vecs[0].IOV_LEN_FIELD = CHAIN_SPACE_LEN(chain);
			if (vecs[0].IOV_LEN_FIELD > howmuch)
				vecs[0].IOV_LEN_FIELD = howmuch;
		}

#ifdef WIN32
		{
			DWORD bytesRead;
			DWORD flags=0;
			if (WSARecv(fd, vecs, nvecs, &bytesRead, &flags, NULL, NULL)) {
				/* The read failed. It might be a close,
				 * or it might be an error. */
				if (WSAGetLastError() == WSAECONNABORTED)
					n = 0;
				else
					n = -1;
			} else
				n = bytesRead;
		}
#else
		n = readv(fd, vecs, nvecs);
#endif
	}

#else /*!USE_IOVEC_IMPL*/
	/* If we don't have FIONREAD, we might waste some space here */
	/* XXX we _will_ waste some space here if there is any space left
	 * over on buf->last. */
	if (evbuffer_expand(buf, howmuch) == -1)
		return (-1);

	chain = buf->last;

	/* We can append new data at this point */
	p = chain->buffer + chain->misalign + chain->off;

#ifndef WIN32
	n = read(fd, p, howmuch);
#else
	n = recv(fd, p, howmuch, 0);
#endif
#endif /* USE_IOVEC_IMPL */

	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

#ifdef USE_IOVEC_IMPL
	if (nvecs == 2) {
		size_t space = CHAIN_SPACE_LEN(buf->previous_to_last);
		if (space < n) {
			buf->previous_to_last->off += space;
			chain->off += n-space;
		} else {
			buf->previous_to_last->off += n;
		}
	} else {
		chain->off += n;
	}
#else
	chain->off += n;
#endif
	buf->total_len += n;

	/* Tell someone about changes in this buffer */
	evbuffer_invoke_callbacks(buf, old_len);

	return (n);
}

#ifdef USE_IOVEC_IMPL
static inline int
evbuffer_write_iovec(struct evbuffer *buffer, evutil_socket_t fd,
ssize_t howmuch)
{
	IOV_TYPE iov[NUM_IOVEC];
	struct evbuffer_chain *chain = buffer->first;
	int n, i = 0;
	/* XXX make this top out at some maximal data length?  if the
	 * buffer has (say) 1MB in it, split over 128 chains, there's
	 * no way it all gets written in one go. */
	while (chain != NULL && i < NUM_IOVEC && howmuch) {
#ifdef USE_SENDFILE
		/* we cannot write the file info via writev */
		if (chain->flags & EVBUFFER_SENDFILE)
			break;
#endif
		iov[i].IOV_PTR_FIELD = chain->buffer + chain->misalign;
		if (howmuch >= chain->off) {
			iov[i++].IOV_LEN_FIELD = chain->off;
			howmuch -= chain->off;
		} else {
			iov[i++].IOV_LEN_FIELD = howmuch;
			break;
		}
		chain = chain->next;
	}
#ifdef WIN32
	{
		DWORD bytesSent;
		if (WSASend(fd, iov, i, &bytesSent, 0, NULL, NULL))
			n = -1;
		else
			n = bytesSent;
	}
#else
	n = writev(fd, iov, i);
#endif
	return (n);
}
#endif

#ifdef USE_SENDFILE
static inline int
evbuffer_write_sendfile(struct evbuffer *buffer, evutil_socket_t fd,
    ssize_t howmuch)
{
	struct evbuffer_chain *chain = buffer->first;
	struct evbuffer_chain_fd *info =
	    EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_fd, chain);
#ifdef SENDFILE_IS_FREEBSD
	int res;
	off_t len = chain->off;
	res = sendfile(info->fd, fd, chain->misalign, &len, NULL, 0);
	if (res == -1 && !EVUTIL_ERR_RW_RETRIABLE(errno))
		return (-1);

	return (len);
#elif SENDFILE_IS_LINUX
	/* TODO(niels): implement splice */
	ssize_t res;
	off_t offset = chain->misalign;
	res = sendfile(fd, info->fd, &offset, chain->off);
	if (res == -1 && EVUTIL_ERR_RW_RETRIABLE(errno)) {
		/* if this is EGAIN or EINTR return 0; otherwise, -1 */
		return (0);
	}
	return (res);
#endif
}
#endif

int
evbuffer_write_atmost(struct evbuffer *buffer, evutil_socket_t fd,
    ssize_t howmuch)
{
	int n;

	if (howmuch < 0)
		howmuch = buffer->total_len;

	{
#ifdef USE_SENDFILE
		struct evbuffer_chain *chain = buffer->first;
		if (chain != NULL && (chain->flags & EVBUFFER_SENDFILE))
			n = evbuffer_write_sendfile(buffer, fd, howmuch);
		else
#endif
#ifdef USE_IOVEC_IMPL
		n = evbuffer_write_iovec(buffer, fd, howmuch);
#elif defined(WIN32)
		/* XXX(nickm) Don't disable this code until we know if
		 * the WSARecv code above works. */
		void *p = evbuffer_pullup(buffer, howmuch);
		n = send(fd, p, howmuch, 0);
#else
		void *p = evbuffer_pullup(buffer, howmuch);
		n = write(fd, p, howmuch);
#endif
	}

	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);
	evbuffer_drain(buffer, n);

	return (n);
}

int
evbuffer_write(struct evbuffer *buffer, evutil_socket_t fd)
{
	return evbuffer_write_atmost(buffer, fd, -1);
}

unsigned char *
evbuffer_find(struct evbuffer *buffer, const unsigned char *what, size_t len)
{
        unsigned char *search;
        struct evbuffer_ptr ptr;

        ptr = evbuffer_search(buffer, (const char *)what, len, NULL);
        if (ptr.pos < 0)
                return (NULL);

        search = evbuffer_pullup(buffer, ptr.pos + len);
        return search + ptr.pos;
}

int
evbuffer_ptr_set(struct evbuffer *buf, struct evbuffer_ptr *pos,
    size_t position, enum evbuffer_ptr_how how)
{
        size_t left = position;
	struct evbuffer_chain *chain = NULL;

	switch (how) {
	case EVBUFFER_PTR_SET:
		chain = buf->first;
		pos->pos = position;
		position = 0;
		break;
	case EVBUFFER_PTR_ADD:
		/* this avoids iterating over all previous chains if
		   we just want to advance the position */
		chain = pos->_internal.chain;
		pos->pos += position;
		position = pos->_internal.pos_in_chain;
		break;
	}

	while (chain && position + left >= chain->off) {
		left -= chain->off - position;
		chain = chain->next;
		position = 0;
	}
	if (chain) {
		pos->_internal.chain = chain;
		pos->_internal.pos_in_chain = position + left;
	} else {
		pos->_internal.chain = NULL;
		pos->pos = -1;
	}

	return chain != NULL ? 0 : -1;
}

/**
   Compare the bytes in buf at position pos to the len bytes in mem.  Return
   less than 0, 0, or greater than 0 as memcmp.
 */
static int
evbuffer_ptr_memcmp(const struct evbuffer *buf, const struct evbuffer_ptr *pos,
    const char *mem, size_t len)
{
        struct evbuffer_chain *chain;
        size_t position;
        int r;

        if (pos->pos + len > buf->total_len)
                return -1;

        chain = pos->_internal.chain;
        position = pos->_internal.pos_in_chain;
        while (len && chain) {
                size_t n_comparable;
                if (len + position > chain->off)
                        n_comparable = chain->off - position;
                else
                        n_comparable = len;
                r = memcmp(chain->buffer + chain->misalign + position, mem,
                    n_comparable);
                if (r)
                        return r;
                mem += n_comparable;
                len -= n_comparable;
                position = 0;
                chain = chain->next;
        }

        return 0;
}

struct evbuffer_ptr
evbuffer_search(struct evbuffer *buffer, const char *what, size_t len, const struct evbuffer_ptr *start)
{
        struct evbuffer_ptr pos;
        struct evbuffer_chain *chain;
	const unsigned char *p;
        char first;

        if (start) {
                memcpy(&pos, start, sizeof(pos));
                chain = pos._internal.chain;
        } else {
                pos.pos = 0;
                chain = pos._internal.chain = buffer->first;
                pos._internal.pos_in_chain = 0;
        }

        if (!len)
                return pos;

        first = what[0];

        while (chain) {
                const unsigned char *start_at =
                    chain->buffer + chain->misalign +
                    pos._internal.pos_in_chain;
                p = memchr(start_at, first,
                    chain->off - pos._internal.pos_in_chain);
                if (p) {
                        pos.pos += p - start_at;
                        pos._internal.pos_in_chain += p - start_at;
                        if (!evbuffer_ptr_memcmp(buffer, &pos, what, len))
                                return pos;
                        ++pos.pos;
                        ++pos._internal.pos_in_chain;
                        if (pos._internal.pos_in_chain == chain->off) {
                                chain = pos._internal.chain = chain->next;
                                pos._internal.pos_in_chain = 0;
                        }
                } else {
                        pos.pos += chain->off - pos._internal.pos_in_chain;
                        chain = pos._internal.chain = chain->next;
                        pos._internal.pos_in_chain = 0;
                }
        }

        pos.pos = -1;
        pos._internal.chain = NULL;
        return pos;
}


int
evbuffer_add_vprintf(struct evbuffer *buf, const char *fmt, va_list ap)
{
	char *buffer;
	size_t space;
	size_t old_len = buf->total_len;
	int sz;
	va_list aq;

	/* make sure that at least some space is available */
	if (evbuffer_expand(buf, 64) == -1)
		return (-1);

	for (;;) {
		struct evbuffer_chain *chain = buf->last;
		size_t used = chain->misalign + chain->off;
		buffer = (char *)chain->buffer + chain->misalign + chain->off;
		assert(chain->buffer_len >= used);
		space = chain->buffer_len - used;

#ifndef va_copy
#define	va_copy(dst, src)	memcpy(&(dst), &(src), sizeof(va_list))
#endif
		va_copy(aq, ap);

		sz = evutil_vsnprintf(buffer, space, fmt, aq);

		va_end(aq);

		if (sz < 0)
			return (-1);
		if (sz < space) {
			chain->off += sz;
			buf->total_len += sz;

			evbuffer_invoke_callbacks(buf, old_len);
			return (sz);
		}
		if (evbuffer_expand(buf, sz + 1) == -1)
			return (-1);

	}
	/* NOTREACHED */
}

int
evbuffer_add_printf(struct evbuffer *buf, const char *fmt, ...)
{
	int res = -1;
	va_list ap;

	va_start(ap, fmt);
	res = evbuffer_add_vprintf(buf, fmt, ap);
	va_end(ap);

	return (res);
}

int
evbuffer_add_reference(struct evbuffer *outbuf,
    const void *data, size_t datlen,
    void (*cleanupfn)(void *extra), void *extra)
{
	size_t old_len = outbuf->total_len;
	struct evbuffer_chain *chain =
	    evbuffer_chain_new(sizeof(struct evbuffer_chain_reference));
	struct evbuffer_chain_reference *info;
	if (chain == NULL)
		return (-1);

	chain->flags |= EVBUFFER_REFERENCE | EVBUFFER_IMMUTABLE;
	chain->buffer = (u_char *)data;
	chain->buffer_len = datlen;
	chain->off = datlen;

	info = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_reference, chain);
	info->cleanupfn = cleanupfn;
	info->extra = extra;

	evbuffer_chain_insert(outbuf, chain);

	evbuffer_invoke_callbacks(outbuf, old_len);

	return (0);
}

/* TODO(niels): maybe we don't want to own the fd, however, in that
 * case, we should dup it - dup is cheap.  Perhaps, we should use a
 * callback insead?
 */
/* TODO(niels): we may want to add to automagically convert to mmap, in
 * case evbuffer_remove() or evbuffer_pullup() are being used.
 */
int
evbuffer_add_file(struct evbuffer *outbuf, int fd,
    off_t offset, size_t length)
{
	size_t old_len = outbuf->total_len;

#if defined(USE_SENDFILE) || defined(_EVENT_HAVE_MMAP)
	struct evbuffer_chain *chain;
	struct evbuffer_chain_fd *info;
#endif

#if defined(USE_SENDFILE)
	if (use_sendfile) {
		chain = evbuffer_chain_new(sizeof(struct evbuffer_chain_fd));
		if (chain == NULL) {
			event_warn("%s: out of memory\n", __func__);
			return (-1);
		}

		chain->flags |= EVBUFFER_SENDFILE | EVBUFFER_IMMUTABLE;
		chain->buffer = NULL;	/* no reading possible */
		chain->buffer_len = length + offset;
		chain->off = length;
		chain->misalign = offset;

		info = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_fd, chain);
		info->fd = fd;

		evbuffer_chain_insert(outbuf, chain);
	} else
#endif
#if defined(_EVENT_HAVE_MMAP)
	if (use_mmap) {
		void *mapped = mmap(NULL, length + offset, PROT_READ,
#ifdef MAP_NOCACHE
		    MAP_NOCACHE |
#endif
		    MAP_FILE | MAP_PRIVATE,
		    fd, 0);
		/* some mmap implementations require offset to be a multiple of
		 * the page size.  most users of this api, are likely to use 0
		 * so mapping everything is not likely to be a problem.
		 * TODO(niels): determine page size and round offset to that
		 * page size to avoid mapping too much memory.
		 */
		if (mapped == MAP_FAILED) {
			event_warn("%s: mmap(%d, %d, %zu) failed",
			    __func__, fd, 0, (size_t)(offset + length));
			return (-1);
		}
		chain = evbuffer_chain_new(sizeof(struct evbuffer_chain_fd));
		if (chain == NULL) {
			event_warn("%s: out of memory\n", __func__);
			munmap(mapped, length);
			return (-1);
		}

		chain->flags |= EVBUFFER_MMAP | EVBUFFER_IMMUTABLE;
		chain->buffer = mapped;
		chain->buffer_len = length + offset;
		chain->off = length + offset;

		info = EVBUFFER_CHAIN_EXTRA(struct evbuffer_chain_fd, chain);
		info->fd = fd;

		evbuffer_chain_insert(outbuf, chain);

		/* we need to subtract whatever we don't need */
		evbuffer_drain(outbuf, offset);
	} else
#endif
	{
		/* the default implementation */
		struct evbuffer *tmp = evbuffer_new();
		ssize_t read;

		if (tmp == NULL)
			return (-1);

		if (lseek(fd, offset, SEEK_SET) == -1) {
			evbuffer_free(tmp);
			return (-1);
		}

		/* we add everything to a temporary buffer, so that we
		 * can abort without side effects if the read fails.
		 */
		while (length) {
			read = evbuffer_read(tmp, fd, length);
			if (read == -1) {
				evbuffer_free(tmp);
				return (-1);
			}

			length -= read;
		}

		evbuffer_add_buffer(outbuf, tmp);
		evbuffer_free(tmp);

		close(fd);
	}

	evbuffer_invoke_callbacks(outbuf, old_len);

	return (0);
}


void
evbuffer_setcb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg)
{
	if (!TAILQ_EMPTY(&buffer->callbacks))
		evbuffer_remove_all_callbacks(buffer);

	if (cb)
		evbuffer_add_cb(buffer, cb, cbarg);
}

struct evbuffer_cb_entry *
evbuffer_add_cb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg)
{
	struct evbuffer_cb_entry *e;
	if (! (e = mm_calloc(1, sizeof(struct evbuffer_cb_entry))))
		return NULL;
	e->cb = cb;
	e->cbarg = cbarg;
	e->flags = EVBUFFER_CB_ENABLED;
	TAILQ_INSERT_HEAD(&buffer->callbacks, e, next);
	return e;
}

int
evbuffer_remove_cb_entry(struct evbuffer *buffer,
			 struct evbuffer_cb_entry *ent)
{
	TAILQ_REMOVE(&buffer->callbacks, ent, next);
	mm_free(ent);
	return 0;
}

int
evbuffer_remove_cb(struct evbuffer *buffer, evbuffer_cb cb, void *cbarg)
{
	struct evbuffer_cb_entry *cbent;
	TAILQ_FOREACH(cbent, &buffer->callbacks, next) {
		if (cb == cbent->cb && cbarg == cbent->cbarg) {
			return evbuffer_remove_cb_entry(buffer, cbent);
		}
	}
	return -1;
}

int
evbuffer_cb_set_flags(struct evbuffer *buffer,
		      struct evbuffer_cb_entry *cb, ev_uint32_t flags)
{
	(void)buffer; /* unused */
	cb->flags = (cb->flags & EVBUFFER_CB_INTERNAL_FLAGS) | flags;
	return 0;
}

void
evbuffer_cb_suspend(struct evbuffer *buffer, struct evbuffer_cb_entry *cb)
{
	if (!(cb->flags & EVBUFFER_CB_SUSPENDED)) {
		cb->size_before_suspend = EVBUFFER_LENGTH(buffer);
		cb->flags |= EVBUFFER_CB_SUSPENDED;
	}
}

void
evbuffer_cb_unsuspend(struct evbuffer *buffer, struct evbuffer_cb_entry *cb)
{
	if ((cb->flags & EVBUFFER_CB_SUSPENDED)) {
		unsigned call = (cb->flags & EVBUFFER_CB_CALL_ON_UNSUSPEND);
		size_t sz = cb->size_before_suspend;
		cb->flags &= ~(EVBUFFER_CB_SUSPENDED|
			       EVBUFFER_CB_CALL_ON_UNSUSPEND);
		cb->size_before_suspend = 0;
		if (call && (cb->flags & EVBUFFER_CB_ENABLED)) {
			cb->cb(buffer, sz, EVBUFFER_LENGTH(buffer), cb->cbarg);
		}
	}
}
