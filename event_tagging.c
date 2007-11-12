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

int decode_int(uint32_t *pnumber, struct evbuffer *evbuf);

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

void
encode_int(struct evbuffer *evbuf, uint32_t number)
{
	int off = 1, nibbles = 0;
	uint8_t data[5];

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

	evbuffer_add(evbuf, data, (off + 1) / 2);
}

/*
 * Marshal a data type, the general format is as follows:
 *
 * tag number: one byte; length: var bytes; payload: var bytes
 */

void
evtag_marshal(struct evbuffer *evbuf, uint8_t tag,
    const void *data, uint32_t len)
{
	evbuffer_add(evbuf, &tag, sizeof(tag));
	encode_int(evbuf, len);
	evbuffer_add(evbuf, (void *)data, len);
}

/* Marshaling for integers */
void
evtag_marshal_int(struct evbuffer *evbuf, uint8_t tag, uint32_t integer)
{
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	encode_int(_buf, integer);

	evbuffer_add(evbuf, &tag, sizeof(tag));
	encode_int(evbuf, EVBUFFER_LENGTH(_buf));
	evbuffer_add_buffer(evbuf, _buf);
}

void
evtag_marshal_string(struct evbuffer *buf, uint8_t tag, const char *string)
{
	evtag_marshal(buf, tag, string, strlen(string));
}

void
evtag_marshal_timeval(struct evbuffer *evbuf, uint8_t tag, struct timeval *tv)
{
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	encode_int(_buf, tv->tv_sec);
	encode_int(_buf, tv->tv_usec);

	evtag_marshal(evbuf, tag, EVBUFFER_DATA(_buf),
	    EVBUFFER_LENGTH(_buf));
}

static int
decode_int_internal(uint32_t *pnumber, struct evbuffer *evbuf, int dodrain)
{
	uint32_t number = 0;
	uint8_t *data = EVBUFFER_DATA(evbuf);
	int len = EVBUFFER_LENGTH(evbuf);
	int nibbles = 0;

	if (!len)
		return (-1);

	nibbles = ((data[0] & 0xf0) >> 4) + 1;
	if (nibbles > 8 || (nibbles >> 1) + 1 > len)
		return (-1);
	len = (nibbles >> 1) + 1;

	while (nibbles > 0) {
		number <<= 4;
		if (nibbles & 0x1)
			number |= data[nibbles >> 1] & 0x0f;
		else
			number |= (data[nibbles >> 1] & 0xf0) >> 4;
		nibbles--;
	}

	if (dodrain)
		evbuffer_drain(evbuf, len);

	*pnumber = number;

	return (len);
}

int
decode_int(uint32_t *pnumber, struct evbuffer *evbuf)
{
	return (decode_int_internal(pnumber, evbuf, 1) == -1 ? -1 : 0);
}

int
evtag_peek(struct evbuffer *evbuf, uint8_t *ptag)
{
	if (EVBUFFER_LENGTH(evbuf) < 2)
		return (-1);
	*ptag = EVBUFFER_DATA(evbuf)[0];

	return (0);
}

int
evtag_peek_length(struct evbuffer *evbuf, uint32_t *plength)
{
	struct evbuffer tmp;
	int res;

	if (EVBUFFER_LENGTH(evbuf) < 2)
		return (-1);

	tmp = *evbuf;
	tmp.buffer += 1;
	tmp.off -= 1;

	res = decode_int_internal(plength, &tmp, 0);
	if (res == -1)
		return (-1);

	*plength += res + 1;

	return (0);
}

int
evtag_payload_length(struct evbuffer *evbuf, uint32_t *plength)
{
	struct evbuffer tmp;
	int res;

	if (EVBUFFER_LENGTH(evbuf) < 2)
		return (-1);

	tmp = *evbuf;
	tmp.buffer += 1;
	tmp.off -= 1;

	res = decode_int_internal(plength, &tmp, 0);
	if (res == -1)
		return (-1);

	return (0);
}

int
evtag_consume(struct evbuffer *evbuf)
{
	uint32_t len;
	evbuffer_drain(evbuf, 1);
	if (decode_int(&len, evbuf) == -1)
		return (-1);
	evbuffer_drain(evbuf, len);

	return (0);
}

/* Reads the data type from an event buffer */

int
evtag_unmarshal(struct evbuffer *src, uint8_t *ptag, struct evbuffer *dst)
{
	uint8_t tag;
	uint32_t len;
	uint32_t integer;

	if (evbuffer_remove(src, &tag, sizeof(tag)) != sizeof(tag))
		return (-1);
	if (decode_int(&integer, src) == -1)
		return (-1);
	len = integer;

	if (EVBUFFER_LENGTH(src) < len)
		return (-1);

	if (evbuffer_add(dst, EVBUFFER_DATA(src), len) == -1)
		return (-1);

	evbuffer_drain(src, len);

	*ptag = tag;
	return (len);
}

/* Marshaling for integers */

int
evtag_unmarshal_int(struct evbuffer *evbuf, uint8_t need_tag,
    uint32_t *pinteger)
{
	uint8_t tag;
	uint32_t len;
	uint32_t integer;

	if (evbuffer_remove(evbuf, &tag, sizeof(tag)) != sizeof(tag) ||
	    tag != need_tag)
		return (-1);
	if (decode_int(&integer, evbuf) == -1)
		return (-1);
	len = integer;

	if (EVBUFFER_LENGTH(evbuf) < len)
		return (-1);
	
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (evbuffer_add(_buf, EVBUFFER_DATA(evbuf), len) == -1)
		return (-1);

	evbuffer_drain(evbuf, len);

	return (decode_int(pinteger, _buf));
}

/* Unmarshal a fixed length tag */

int
evtag_unmarshal_fixed(struct evbuffer *src, uint8_t need_tag, void *data,
    size_t len)
{
	uint8_t tag;

	/* Initialize this event buffer so that we can read into it */
	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	/* Now unmarshal a tag and check that it matches the tag we want */
	if (evtag_unmarshal(src, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	if (EVBUFFER_LENGTH(_buf) != len)
		return (-1);

	memcpy(data, EVBUFFER_DATA(_buf), len);
	return (0);
}

int
evtag_unmarshal_string(struct evbuffer *evbuf, uint8_t need_tag,
    char **pstring)
{
	uint8_t tag;

	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));

	if (evtag_unmarshal(evbuf, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	*pstring = calloc(EVBUFFER_LENGTH(_buf) + 1, 1);
	if (*pstring == NULL)
		event_err(1, "%s: calloc", __func__);
	evbuffer_remove(_buf, *pstring, EVBUFFER_LENGTH(_buf));

	return (0);
}

int
evtag_unmarshal_timeval(struct evbuffer *evbuf, uint8_t need_tag,
    struct timeval *ptv)
{
	uint8_t tag;
	uint32_t integer;

	evbuffer_drain(_buf, EVBUFFER_LENGTH(_buf));
	if (evtag_unmarshal(evbuf, &tag, _buf) == -1 || tag != need_tag)
		return (-1);

	if (decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_sec = integer;
	if (decode_int(&integer, _buf) == -1)
		return (-1);
	ptv->tv_usec = integer;

	return (0);
}
