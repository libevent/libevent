/*
 * Copyright (c) 2002, 2003 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef HAVE_VASPRINTF
/* If we have vasprintf, we need to define this before we include stdio.h. */
#define _GNU_SOURCE
#endif

#include <sys/types.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "event2/event.h"
#include "event2/buffer.h"
#include "config.h"
#include "log.h"
#include "mm-internal.h"
#include "evbuffer-internal.h"

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

	return (chain);
}

struct evbuffer *
evbuffer_new(void)
{
	struct evbuffer *buffer;
	
	buffer = mm_calloc(1, sizeof(struct evbuffer));

	return (buffer);
}

void
evbuffer_free(struct evbuffer *buffer)
{
	struct evbuffer_chain *chain, *next;
	for (chain = buffer->first; chain != NULL; chain = next) {
		next = chain->next;
		mm_free(chain);
	}
	mm_free(buffer);
}

size_t
evbuffer_get_length(struct evbuffer *buffer)
{
	return (buffer->total_len);
}

size_t
evbuffer_get_contiguous_space(struct evbuffer *buf)
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

	if (in_total_len == 0)
		return (0);

	if (out_total_len == 0) {
		COPY_CHAIN(outbuf, inbuf);
	} else {
		APPEND_CHAIN(outbuf, inbuf);
	}

	/* remove everything from inbuf */
	ZERO_CHAIN(inbuf);

	if (inbuf->cb != NULL && inbuf->total_len != in_total_len)
		(*inbuf->cb)(inbuf, in_total_len, inbuf->total_len,
		    inbuf->cbarg);
	if (outbuf->cb != NULL && outbuf->total_len != out_total_len)
		(*outbuf->cb)(outbuf, out_total_len, outbuf->total_len,
		    outbuf->cbarg);
		
	return (0);
}

void
evbuffer_prepend_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	size_t out_total_len = outbuf->total_len;
	size_t in_total_len = inbuf->total_len;

	if (!in_total_len)
		return;

	if (out_total_len == 0) {
		COPY_CHAIN(outbuf, inbuf);
	} else {
		PREPEND_CHAIN(outbuf, inbuf);
	}

	/* remove everything from inbuf */
	ZERO_CHAIN(inbuf);

	if (inbuf->cb != NULL && inbuf->total_len != in_total_len)
		(*inbuf->cb)(inbuf, in_total_len, inbuf->total_len,
		    inbuf->cbarg);
	if (outbuf->cb != NULL && outbuf->total_len != out_total_len)
		(*outbuf->cb)(outbuf, out_total_len, outbuf->total_len,
		    outbuf->cbarg);
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

			mm_free(chain);
		}

		ZERO_CHAIN(buf);
	} else {
		buf->total_len -= len;

		for (chain = buf->first; len >= chain->off; chain = next) {
			next = chain->next;
			len -= chain->off;

			mm_free(chain);
		}

		buf->first = chain;
		if (buf->first == buf->last)
			buf->previous_to_last = NULL;
		chain->misalign += len;
		chain->off -= len;
	}

	/* Tell someone about changes in this buffer */
	if (buf->cb != NULL && buf->total_len != old_len)
		(*buf->cb)(buf, old_len, buf->total_len, buf->cbarg);

}

/* Reads data from an event buffer and drains the bytes read */

int
evbuffer_remove(struct evbuffer *buf, void *data_out, size_t datlen)
{
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
		mm_free(tmp);
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

	if (buf->cb != NULL && nread)
		(*buf->cb)(buf, buf->total_len + nread, buf->total_len,
		    buf->cbarg);

	return (nread);
}

/* reads data from the src buffer to the dst buffer, avoids memcpy as
 * possible. */
int
evbuffer_remove_buffer(struct evbuffer *src, struct evbuffer *dst,
    size_t datlen)
{
	struct evbuffer_chain *chain = src->first;
	struct evbuffer_chain *previous = chain, *previous_to_previous = NULL;
	size_t nread = 0;

	/* short-cut if there is no more data buffered */
	if (datlen >= src->total_len) {
		datlen = src->total_len;
		evbuffer_add_buffer(dst, src);
		return (datlen);
	}

	if (datlen == 0)
		return (0);

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

	if (dst->cb != NULL && nread)
		(*dst->cb)(dst, dst->total_len - nread, dst->total_len,
		    dst->cbarg);
	if (src->cb != NULL && nread)
		(*src->cb)(src, src->total_len + nread, src->total_len,
		    src->cbarg);

	return (nread);
}

/* XXX shouldn't the second arg be ssize_t? */
unsigned char *
evbuffer_pullup(struct evbuffer *buf, int size)
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

	/* Copy and free every chunk that will be entirely pulled into tmp */
	for (; chain != NULL && size >= chain->off; chain = next) {
		next = chain->next;

		memcpy(buffer, chain->buffer + chain->misalign, chain->off);
		size -= chain->off;
		buffer += chain->off;
		
		mm_free(chain);
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

/* Adds data to an event buffer */

int
evbuffer_add(struct evbuffer *buf, const void *data_in, size_t datlen)
{
	struct evbuffer_chain *chain = buf->last;
	const unsigned char *data = data_in;
	size_t old_len = buf->total_len, remain, to_alloc;

	/* If there are no chains allocated for this buffer, allocate one
	 * big enough to hold all the data. */
	if (chain == NULL) {
		if (evbuffer_expand(buf, datlen) == -1)
			return (-1);
		chain = buf->last;
	}

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

	/* we need to add another chain */
	/* XXX Does this double the length of every successive chain? */
	to_alloc = chain->buffer_len << 1;
	if (datlen > to_alloc)
		to_alloc = datlen;
	chain->next = evbuffer_chain_new(to_alloc);
	if (chain->next == NULL)
		return (-1);
	buf->last = chain->next;
	buf->previous_to_last = chain;
	buf->total_len += datlen;
	
	memcpy(chain->buffer + chain->misalign + chain->off,
	    data, remain);
	chain->off += remain;

	data += remain;
	datlen -= remain;

	chain = chain->next;
	memcpy(chain->buffer, data, datlen);
	chain->off = datlen;

out:
	if (buf->cb != NULL && datlen)
		(*buf->cb)(buf, old_len, buf->total_len, buf->cbarg);

	return (0);
}

int
evbuffer_prepend(struct evbuffer *buf, const void *data, size_t datlen)
{
	struct evbuffer_chain *chain = buf->first;
	size_t old_len = buf->total_len;

	if (chain == NULL) {
		if (evbuffer_expand(buf, datlen) == -1)
			return (-1);
		chain = buf->first;
		chain->misalign = chain->buffer_len;
	}

	if (chain->misalign >= datlen) {
		/* we have enough space */
		memcpy(chain->buffer + chain->misalign - datlen,
		    data, datlen);
		chain->off += datlen;
		chain->misalign -= datlen;
	} else {
		struct evbuffer_chain *tmp;
		/* XXX we should copy as much of the data into chain
		 * as possible before we put any into tmp. */

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
	}
	buf->total_len += datlen;

	if (buf->cb != NULL && datlen)
		(*buf->cb)(buf, old_len, buf->total_len, buf->cbarg);

	return (0);
}

/** Helper: realigns the memory in chain->buffer so that misalign is
 * 0. */
static void
evbuffer_chain_align(struct evbuffer_chain *chain)
{
	memmove(chain->buffer, chain->buffer + chain->misalign, chain->off);
	chain->misalign = 0;
}

/* Expands the available space in the event buffer to at least datlen */

int
evbuffer_expand(struct evbuffer *buf, size_t datlen)
{
	struct evbuffer_chain *chain = buf->last, *tmp;
	size_t need, length;

	if (chain == NULL) {
		chain = evbuffer_chain_new(datlen);
		if (chain == NULL)
			return (-1);

		buf->first = buf->last = chain;
		buf->previous_to_last = NULL;
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

	mm_free(chain);

	return (0);
}

/*
 * Reads data from a file descriptor into a buffer.
 */

#define EVBUFFER_MAX_READ	4096

int
evbuffer_read(struct evbuffer *buf, evutil_socket_t fd, int howmuch)
{
	struct evbuffer_chain *chain = buf->last;
	unsigned char *p;
	size_t old_len = buf->total_len;
	int n = EVBUFFER_MAX_READ;

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
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

	chain->off += n;
	buf->total_len += n;

	/* Tell someone about changes in this buffer */
	if (buf->cb != NULL)
		(*buf->cb)(buf, old_len, buf->total_len, buf->cbarg);

	return (n);
}

int
evbuffer_write(struct evbuffer *buffer, evutil_socket_t fd)
{
	int n;

#ifndef WIN32
  #ifdef HAVE_SYS_UIO_H
	struct iovec iov[NUM_IOVEC];
	struct evbuffer_chain *chain = buffer->first;
	int i = 0;
	/* XXX make this top out at some maximal data length? if the buffer has
	 * (say) 1MB in it, split over 128 chains, there's no way it all gets
	 * written in one go. */
	while (chain != NULL && i < NUM_IOVEC) {
		iov[i].iov_base = chain->buffer + chain->misalign;
		iov[i++].iov_len = chain->off;
		chain = chain->next;
	}
	n = writev(fd, iov, i);
  #else /* !HAVE_SYS_UIO_H */
	void *p = evbuffer_pullup(buffer, -1);
	n = write(fd, p, buffer->total_len, 0);
  #endif
#else
	/* XXX(niels): investigate if windows has writev */
	void *p = evbuffer_pullup(buffer, -1);
	n = send(fd, p, buffer->total_len, 0);
#endif
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);
	evbuffer_drain(buffer, n);

	return (n);
}

unsigned char *
evbuffer_find(struct evbuffer *buffer, const unsigned char *what, size_t len)
{
	unsigned char *search = evbuffer_pullup(buffer, -1);
	unsigned char *end = search + buffer->total_len;
	unsigned char *p;

	while (search < end &&
	    (p = memchr(search, *what, end - search)) != NULL) {
		if (p + len > end)
			break;
		if (memcmp(p, what, len) == 0)
			return (p);
		search = p + 1;
	}

	return (NULL);
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
			if (buf->cb != NULL)
				(*buf->cb)(buf, old_len,
				    buf->total_len, buf->cbarg);
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

void
evbuffer_setcb(struct evbuffer *buffer,
    void (*cb)(struct evbuffer *, size_t, size_t, void *),
    void *cbarg)
{
	buffer->cb = cb;
	buffer->cbarg = cbarg;
}
