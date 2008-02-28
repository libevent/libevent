/*
 * Copyright (c) 2003, 2004 Niels Provos <provos@citi.umich.edu>
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#else
#include <sys/ioctl.h>
#endif

#include <sys/queue.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <syslog.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "event.h"
#include "log.h"
#include "mm-internal.h"

int evtag_decode_int(ev_uint32_t *pnumber, struct evbuffer *evbuf);
int evtag_encode_tag(struct evbuffer *evbuf, ev_uint32_t tag);
int evtag_decode_tag(ev_uint32_t *ptag, struct evbuffer *evbuf);

static struct evbuffer *_buf;	/* not thread safe */

void
evtag_init(void)
{
	if (_buf != NULL)
		return;

	if ((_buf = evbuffer_new()) == NULL)
		event_err(1, "%s: malloc", __func__);
}

/* 
 * We encode integer's by nibbles; the first nibble contains the number
 * of significant nibbles - 1;  this allows us to encode up to 64-bit
 * integers.  This function is byte-order independent.
 */

static inline int
encode_int_internal(ev_uint8_t *data, ev_uint32_t number)
{
	int off = 1, nibbles = 0;

	memset(data, 0, sizeof(data));
	while (number) {
		if (off & 0x1)
			data[off/2] = (data[off/2] & 0xf0) | (number & 0x0f);
		else
			data[off/2] = (data[off/2] & 0x0f) |
			    ((number & 0x0f) << 4);
		number >>= 4;
		off++;
	}

	if (off > 2)
		nibbles = off - 2;

	/* Off - 1 is the number of encoded nibbles */
	data[0] = (data[0] & 0x0f) | ((nibbles & 0x0f) << 4);

	return ((off + 1) / 2);
}

void
encode_int(struct evbuffer *evbuf, ev_uint32_t number)
{
	ev_uint8_t data[5];
	int len = encode_int_internal(data, number);
	evbuffer_add(evbuf, data, len);
}

/*
 * Support variable length encoding of tags; we use the high bit in each
 * octet as a continuation signal.
 */

int
evtag_encode_tag(struct evbuffer *evbuf, ev_uint32_t tag)
{
	int bytes = 0;
	ev_uint8_t data[5];

	memset(data, 0, sizeof(data));
	do {
		ev_uint8_t lower = tag & 0x7f;
		tag >>= 7;

		if (tag)
			lower |= 0x80;

		data[bytes++] = lower;
	} while (tag);

	if (evbuf != NULL)
		evbuffer_add(evbuf, data, bytes);

	return (bytes);
}

static int
decode_tag_internal(ev_uint32_t *ptag, struct evbuffer *evbuf, int dodrain)
{
	ev_uint32_t number = 0;
	int len = EVBUFFER_LENGTH(evbuf);
	ev_uint8_t *data;
	int count = 0, shift = 0, done = 0;

	/*
	 * the encoding of a number is at most one byte more than its
	 * storage size.  however, it may also be much smaller.
	 */
	data = evbuffer_pullup(
		evbuf, len < sizeof(number) + 1 ? len : sizeof(number) + 1);

	while (count++ < len) {
		ev_uint8_t lower = *data++;
		number |= (lower & 0x7f) << shift;
		shift += 7;

		if (!(lower & 0x80)) {
			done = 1;
			break;
		}
	}

	if (!done)
		return (-1);

	if (dodrain)
		evbuffer_drain(evbuf, count);

	if (ptag != NULL)
		*ptag = number;

	return (count);
}

int
evtag_decode_tag(ev_uint32_t *ptag, struct evbuffer *evbuf)
{
	return (decode_tag_internal(ptag, evbuf, 1 /* dodrain */));
}

/*
 * Marshal a data type, the general format is as follows:
 *
 * tag number: one byte; length: var bytes; payload: var bytes
 */

void
evtag_marshal(struct evbuffer *evbuf, ev_uint32_t tag,
    const void *data, ev_uint32_t len)
{
	evtag_encode_tag(evbuf, tag);
	encode_int(evbuf, len);
	evbuffer_add(evbuf, (void *)data, len);
}

void
evtag_marshal_buffer(struct evbuffer *evbuf, ev_uint32_t tag,
    struct evbuffer *data)
{
	evtag_encode_tag(evbuf, tag);
	encode_int(evbuf, EVBUFFER_LENGTH(data));
	evbuffer_add_buffer(evbuf, data);
}

/* Marshaling for integers */
void
evtag_marshal_int(struct evbuffer *evbuf, ev_uint32_t tag, ev_uint32_t integer)
{
	ev_uint8_t data[5];
	int len = encode_int_internal(data, integer);

	evtag_encode_tag(evbuf, tag);
	encode_int(evbuf, len);
	evbuffer_add(evbuf, data, len);
}

void
evtag_marshal_string(struct evbuffer *buf, ev_uint32_t tag, const char *string)
{
	evtag_marshal(buf, tag, string, strlen(string));
}

void
evtag_marshal_timeval(struct evbuffer *evbuf, ev_uint32_t tag, struct timeval *tv)
{
	ev_uint8_t data[10];
	int len = encode_int_internal(data, tv->tv_sec);
	len += encode_int_internal(data + len, tv->tv_usec);
	evtag_marshal(evbuf, tag, data, len);
}

static int
decode_int_internal(ev_uint32_t *pnumber, struct evbuffer *evbuf, int offset)
{
	ev_uint32_t number = 0;
	ev_uint8_t *data;
	int len = EVBUFFER_LENGTH(evbuf) - offset;
	int nibbles = 0;

	if (len <= 0)
		return (-1);

	/* XXX(niels): faster? */
	data = evbuffer_pullup(evbuf, offset + 1) + offset;

	nibbles = ((data[0] & 0xf0) >> 4) + 1;
	if (nibbles > 8 || (nibbles >> 1) + 1 > len)
		return (-1);
	len = (nibbles >> 1) + 1;

	data = evbuffer_pullup(evbuf, offset + len) + offset;
	
	while (nibbles > 0) {
		number <<= 4;
		if (nibbles & 0x1)
			number |= data[nibbles >> 1] & 0x0f;
		else
			number |= (data[nibbles >> 1] & 0xf0) >> 4;
		nibbles--;
	}

	*pnumber = number;

	return (len);
}

int
evtag_decode_int(ev_uint32_t *pnumber, struct evbuffer *evbuf)
{
	int res = decode_int_internal(pnumber, evbuf, 0);
	if (res != -1)
		evbuffer_drain(evbuf, res);

	return (res == -1 ? -1 : 0);
}

int
evtag_peek(struct evbuffer *evbuf, ev_uint32_t *ptag)
{
	return (decode_tag_internal(ptag, evbuf, 0 /* dodrain */));
}

int
evtag_peek_length(struct evbuffer *evbuf, ev_uint32_t *plength)
{
	int res, len;

	len = decode_tag_internal(NULL, evbuf, 0 /* dodrain */);
	if (len == -1)
		return (-1);

	res = decode_int_internal(plength, evbuf, len);
	if (res == -1)
		return (-1);

	*plength += res + len;

	return (0);
}

int
evtag_payload_length(struct evbuffer *evbuf, ev_uint32_t *plength)
{
	int res, len;

	len = decode_tag_internal(NULL, evbuf, 0 /* dodrain */);
	if (len == -1)
		return (-1);

	res = decode_int_internal(plength, evbuf, len);
	if (res == -1)
		return (-1);

	return (0);
}

/* just unmarshals the header and returns the length of the remaining data */

int
evtag_unmarshal_header(struct evbuffer *evbuf, ev_uint32_t *ptag)
{
	ev_uint32_t len;

	if (decode_tag_internal(ptag, evbuf, 1 /* dodrain */) == -1)
		return (-1);
	if (evtag_decode_int(&len, evbuf) == -1)
		return (-1);

	if (EVBUFFER_LENGTH(evbuf) < len)
		return (-1);

	return (len);
}

int
evtag_consume(struct evbuffer *evbuf)
{
	int len;
	if ((len = evtag_unmarshal_header(evbuf, NULL)) == -1)
		return (-1);
	evbuffer_drain(evbuf, len);

	return (0);
}

/* Reads the data type from an event buffer */

int
evtag_unmarshal(struct evbuffer *src, ev_uint32_t *ptag, struct evbuffer *dst)
{
	int len;

	if ((len = evtag_unmarshal_header(src, ptag)) == -1)
		return (-1);

	if (evbuffer_add(dst, evbuffer_pullup(src, len), len) == -1)
		return (-1);

	evbuffer_drain(src, len);

	return (len);
}

/* Marshaling for integers */

int
evtag_unmarshal_int(struct evbuffer *evbuf, ev_uint32_t need_tag,
    ev_uint32_t *pinteger)
{
	ev_uint32_t tag;
	ev_uint32_t len;
	ev_uint32_t integer;

	if (decode_tag_internal(&tag, evbuf, 1 /* dodrain */) == -1)
		return (-1);
	if (need_tag != tag)
		return (-1);
	if (evtag_decode_int(&integer, evbuf) == -1)
		return (-1);
	len = integer;

	if (EVBUFFER_LENGTH(evbuf) < len)
		return (-1);
	
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (evbuffer_add(_buf, evbuffer_pullup(evbuf, len), len) == -1)
		return (-1);

	evbuffer_drain(evbuf, len);

	return (evtag_decode_int(pinteger, _buf));
}

/* Unmarshal a fixed length tag */

int
evtag_unmarshal_fixed(struct evbuffer *src, ev_uint32_t need_tag, void *data,
    size_t len)
{
	ev_uint32_t tag;
	int tag_len;

	/* Now unmarshal a tag and check that it matches the tag we want */
	if ((tag_len = evtag_unmarshal_header(src, &tag)) == -1 ||
	    tag != need_tag)
		return (-1);

	if (tag_len != len)
		return (-1);
	
	evbuffer_remove(src, data, len);
	return (0);
}

int
evtag_unmarshal_string(struct evbuffer *evbuf, ev_uint32_t need_tag,
    char **pstring)
{
	ev_uint32_t tag;
	int tag_len;

	if ((tag_len = evtag_unmarshal_header(evbuf, &tag)) == -1 ||
	    tag != need_tag)
		return (-1);

	*pstring = event_malloc(tag_len + 1);
	if (*pstring == NULL)
		event_err(1, "%s: malloc", __func__);
	evbuffer_remove(evbuf, *pstring, tag_len);
	(*pstring)[tag_len] = '\0';

	return (0);
}

int
evtag_unmarshal_timeval(struct evbuffer *evbuf, ev_uint32_t need_tag,
    struct timeval *ptv)
{
	ev_uint32_t tag;
	ev_uint32_t integer;

	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (evtag_unmarshal(evbuf, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	if (evtag_decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_sec = integer;
	if (evtag_decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_usec = integer;

	return (0);
}
