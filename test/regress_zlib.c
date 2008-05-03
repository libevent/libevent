/*
 * Copyright (c) 2008 Niels Provos <provos@citi.umich.edu>
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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/signal.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zlib.h>
#include <assert.h>

#include "evutil.h"
#include "event.h"

void regress_zlib(void);

static int test_ok;

/*
 * Zlib filters
 */

static void
zlib_deflate_init(void *ctx)
{
	z_streamp p = ctx;

	memset(p, 0, sizeof(z_stream));
	assert(deflateInit(p, Z_DEFAULT_COMPRESSION) == Z_OK);
}

static void
zlib_deflate_free(void *ctx)
{
	z_streamp p = ctx;

	assert(deflateEnd(p) == Z_OK);
}

static void
zlib_inflate_init(void *ctx)
{
	z_streamp p = ctx;

	memset(p, 0, sizeof(z_stream));
	assert(inflateInit(p) == Z_OK);
}

static void
zlib_inflate_free(void *ctx)
{
	z_streamp p = ctx;

	assert(inflateEnd(p) == Z_OK);
}

/*
 * The input filter is triggered only on new input read from the network.
 * That means all input data needs to be consumed or the filter needs to
 * initiate its own triggering via a timeout.
 */
static enum bufferevent_filter_result
zlib_input_filter(struct evbuffer *src, struct evbuffer *dst,
    enum bufferevent_filter_state state, void *ctx)
{
	char tmp[4096];
	int nread, nwrite;
	int res;

	z_streamp p = ctx;

	do {
		/* let's do some decompression */
		p->avail_in = evbuffer_contiguous_space(src);
		p->next_in = evbuffer_pullup(src, p->avail_in);

		p->next_out = (unsigned char *)tmp;
		p->avail_out = sizeof(tmp);

		/* we need to flush zlib if we got a flush */
		res = inflate(p, state == BEV_FLUSH ?
		    Z_FINISH : Z_NO_FLUSH);
		assert(res == Z_OK || res == Z_STREAM_END);

		/* let's figure out how much was compressed */
		nread = evbuffer_contiguous_space(src) - p->avail_in;
		nwrite = sizeof(tmp) - p->avail_out;

		evbuffer_drain(src, nread);
		evbuffer_add(dst, tmp, nwrite);
	} while (EVBUFFER_LENGTH(src) > 0);

	test_ok++;

	return (BEV_OK);
}

static enum bufferevent_filter_result
zlib_output_filter(struct evbuffer *src, struct evbuffer *dst,
    enum bufferevent_filter_state state, void *ctx)
{
	char tmp[4096];
	int nread, nwrite;
	int res;

	z_streamp p = ctx;

	do {
		/* let's do some compression */
		p->avail_in = evbuffer_contiguous_space(src);
		p->next_in = evbuffer_pullup(src, p->avail_in);

		p->next_out = (unsigned char *)tmp;
		p->avail_out = sizeof(tmp);

		/* we need to flush zlib if we got a flush */
		res = deflate(p, state == BEV_FLUSH ? Z_FINISH : Z_NO_FLUSH);
		assert(res == Z_OK || res == Z_STREAM_END);

		/* let's figure out how much was compressed */
		nread = evbuffer_contiguous_space(src) - p->avail_in;
		nwrite = sizeof(tmp) - p->avail_out;

		evbuffer_drain(src, nread);
		evbuffer_add(dst, tmp, nwrite);
	} while (EVBUFFER_LENGTH(src) > 0);

	test_ok++;

	return (BEV_OK);
}

/*
 * simple bufferevent test (over transparent zlib treatment)
 */

static void
readcb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->input) == 8333) {
		struct evbuffer *evbuf = evbuffer_new();
		assert(evbuf != NULL);

		/* gratuitous test of bufferevent_read_buffer */
		bufferevent_read_buffer(bev, evbuf);

		bufferevent_disable(bev, EV_READ);

		if (EVBUFFER_LENGTH(evbuf) == 8333)
			test_ok++;

		evbuffer_free(evbuf);
	}
}

static void
writecb(struct bufferevent *bev, void *arg)
{
	if (EVBUFFER_LENGTH(bev->output) == 0)
		test_ok++;
}

static void
errorcb(struct bufferevent *bev, short what, void *arg)
{
	test_ok = -2;
}

static void
test_bufferevent_zlib(void)
{
	struct bufferevent *bev1, *bev2;
	struct bufferevent_filter *finput, *foutput;
	char buffer[8333];
	z_stream z_input, z_output;
	int i, pair[2];

	test_ok = 0;
	fprintf(stdout, "Testing Zlib Filter: ");

	if (evutil_socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == -1) {
		fprintf(stderr, "%s: socketpair\n", __func__);
		exit(1);
	}

	evutil_make_socket_nonblocking(pair[0]);
	evutil_make_socket_nonblocking(pair[1]);

	bev1 = bufferevent_new(pair[0], readcb, writecb, errorcb, NULL);
	bev2 = bufferevent_new(pair[1], readcb, writecb, errorcb, NULL);

	/* initialize filters */
	finput = bufferevent_filter_new(
		zlib_inflate_init, zlib_inflate_free,
		zlib_input_filter, &z_input);
	bufferevent_filter_insert(bev2, BEV_INPUT, finput);

	foutput = bufferevent_filter_new(
		zlib_deflate_init, zlib_deflate_free,
		zlib_output_filter, &z_output);
	bufferevent_filter_insert(bev1, BEV_OUTPUT, foutput);

	bufferevent_disable(bev1, EV_READ);
	bufferevent_enable(bev2, EV_READ);

	for (i = 0; i < sizeof(buffer); i++)
		buffer[i] = i;

	/* break it up into multiple buffer chains */
	bufferevent_write(bev1, buffer, 1800);
	bufferevent_write(bev1, buffer + 1800, sizeof(buffer) - 1800);

	/* we are done writing - we need to flush everything */
	bufferevent_trigger_filter(bev1, NULL, BEV_OUTPUT, BEV_FLUSH);

	event_dispatch();

	bufferevent_free(bev1);
	bufferevent_free(bev2);

	if (test_ok != 6) {
		fprintf(stdout, "FAILED: %d\n", test_ok);
		exit(1);
	}

#ifndef WIN32
	close(pair[0]);
	close(pair[1]);
#else
	CloseHandle((HANDLE)pair[0]);
	CloseHandle((HANDLE)pair[1]);
#endif

	fprintf(stdout, "OK\n");
}

void
regress_zlib(void)
{
	test_bufferevent_zlib();
}
