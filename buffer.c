/*
 * Copyright 2002, 2003 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 */

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#include <unistd.h>

#undef timeout_pending
#undef timeout_initialized

#include <event.h>

#include "event.h"

extern int debug;

struct evbuffer *
evbuffer_new(void)
{
	struct evbuffer *buffer;
	
	if ((buffer = calloc(1, sizeof(struct evbuffer))) == NULL)
		err(1, "%s: calloc", __func__);

	return (buffer);
}

void
evbuffer_free(struct evbuffer *buffer)
{
	if (buffer->buffer != NULL)
		free(buffer->buffer);
	free(buffer);
}

void
evbuffer_add_buffer(struct evbuffer *outbuf, struct evbuffer *inbuf)
{
	evbuffer_add(outbuf, inbuf->buffer, inbuf->off);
	evbuffer_drain(inbuf, inbuf->off);
}

int
evbuffer_add_printf(struct evbuffer *buf, char *fmt, ...)
{
	int res = -1;
	char *msg;
	va_list ap;

	va_start(ap, fmt);

	if (vasprintf(&msg, fmt, ap) == -1)
		goto end;
	
	res = strlen(msg);
	evbuffer_add(buf, msg, res);
	free(msg);


 end:
	va_end(ap);

	return (res);
}

void
evbuffer_add(struct evbuffer *buf, u_char *data, size_t datlen)
{
	size_t need = buf->off + datlen;

	if (buf->totallen < need) {
		if ((buf->buffer = realloc(buf->buffer, need)) == NULL)
			err(1, "%s: realloc", __func__);
		buf->totallen = need;
	}

	memcpy(buf->buffer + buf->off, data, datlen);
	buf->off += datlen;
}

void
evbuffer_drain(struct evbuffer *buf, size_t len)
{
	if (len >= buf->off) {
		buf->off = 0;
		return;
	}

	memmove(buf->buffer, buf->buffer + len, buf->off - len);
	buf->off -= len;
}

int
evbuffer_read(struct evbuffer *buffer, int fd, int howmuch)
{
	u_char inbuf[4096];
	int n;
	
	if (howmuch < 0 || howmuch > sizeof(inbuf))
		howmuch = sizeof(inbuf);

	n = read(fd, inbuf, howmuch);
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

	evbuffer_add(buffer, inbuf, n);

	return (n);
}

int
evbuffer_write(struct evbuffer *buffer, int fd)
{
	int n;

	n = write(fd, buffer->buffer, buffer->off);
	if (n == -1)
		return (-1);
	if (n == 0)
		return (0);

	evbuffer_drain(buffer, n);

	return (n);
}

u_char *
evbuffer_find(struct evbuffer *buffer, u_char *what, size_t len)
{
	size_t remain = buffer->off;
	u_char *search = buffer->buffer;
	u_char *p;

	while ((p = memchr(search, *what, remain)) != NULL && remain >= len) {
		if (memcmp(p, what, len) == 0)
			return (p);

		search = p + 1;
		remain = buffer->off - (size_t)(search - buffer->buffer);
	}

	return (NULL);
}
