/*
 * Copyright (c) 2009 Niels Provos, Nick Mathewson
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

#include <windows.h>
#include <process.h>

#include "event2/util.h"
#include "util-internal.h"
#include "iocp-internal.h"
#include "log-internal.h"
#include "mm-internal.h"

void
event_overlapped_init(struct event_overlapped *o, iocp_callback cb)
{
	memset(o, 0, sizeof(struct event_overlapped));
	o->cb = cb;
}

static void
handle_entry(OVERLAPPED *o, ULONG_PTR completion_key, DWORD nBytes)
{
	struct event_overlapped *eo =
	    EVUTIL_UPCAST(o, struct event_overlapped, overlapped);
	eo->cb(eo, completion_key, nBytes);
}

static void
loop(void *_port)
{
	struct event_iocp_port *port = _port;
	OVERLAPPED *overlapped;
	ULONG_PTR key;
	DWORD bytes;
	long ms = port->ms;

	if (ms <= 0)
		ms = INFINITE;


	while (GetQueuedCompletionStatus(port->port, &bytes, &key,
		&overlapped, ms)) {
		if (port->shutdown)
			return;
		handle_entry(overlapped, key, bytes);
	}
	event_warnx("GetQueuedCompletionStatus exited with no event.");
}

int
event_iocp_port_associate(struct event_iocp_port *port, evutil_socket_t fd,
    uintptr_t key)
{
	HANDLE h;
	h = CreateIoCompletionPort((HANDLE)fd, port->port, key, port->n_threads);
	if (!h)
		return -1;
	return 0;
}

struct event_iocp_port *
event_iocp_port_launch(void)
{
	struct event_iocp_port *port;
	int thread, i;

	if (!(port = mm_calloc(1, sizeof(struct event_iocp_port))))
		return NULL;
	port->n_threads = 2;
	port->port = CreateIoCompletionPort(NULL, NULL, 0, port->n_threads);
	port->ms = -1;
	if (!port->port)
		mm_free(port);

	for (i=0; i<port->n_threads; ++i)
		thread = _beginthread(loop, 0, port);

	return port;
}


void
event_iocp_shutdown(struct event_iocp_port *port)
{
	port->shutdown = 1;
	/* XXX notify. */
}
