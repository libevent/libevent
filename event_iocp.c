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
#include <stdio.h>

#include "event2/util.h"
#include "util-internal.h"
#include "iocp-internal.h"
#include "log-internal.h"
#include "mm-internal.h"
#include "event-internal.h"

#define NOTIFICATION_KEY ((ULONG_PTR)-1)

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
	HANDLE p = port->port;

	if (ms <= 0)
		ms = INFINITE;

	while (GetQueuedCompletionStatus(p, &bytes, &key,
		&overlapped, ms)) {
		EnterCriticalSection(&port->lock);
		if (port->shutdown) {
			if (--port->n_live_threads == 0)
				ReleaseSemaphore(port->shutdownSemaphore, 1, NULL);
			LeaveCriticalSection(&port->lock);
			return;
		}
		LeaveCriticalSection(&port->lock);

		if (key != NOTIFICATION_KEY)
			handle_entry(overlapped, key, bytes);
	}
	event_warnx("GetQueuedCompletionStatus exited with no event.");
	EnterCriticalSection(&port->lock);
	if (--port->n_live_threads == 0)
		ReleaseSemaphore(port->shutdownSemaphore, 1, NULL);
	LeaveCriticalSection(&port->lock);
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
	int i;

	if (!(port = mm_calloc(1, sizeof(struct event_iocp_port))))
		return NULL;
	port->n_threads = 2;
	port->threads = calloc(port->n_threads, sizeof(HANDLE));
	if (!port->threads)
		goto err;

	port->port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, port->n_threads);
	port->ms = -1;
	if (!port->port)
		goto err;

	port->shutdownSemaphore = CreateSemaphore(NULL, 0, 1, NULL);
	if (!port->shutdownSemaphore)
		goto err;

	for (i=0; i<port->n_threads; ++i) {
		uintptr_t th = _beginthread(loop, 0, port);
		if (th == (uintptr_t)-1)
			goto err;
		port->threads[i] = (HANDLE)th;
		++port->n_live_threads;
	}

	InitializeCriticalSection(&port->lock);

	return port;
err:
	if (port->port)
		CloseHandle(port->port);
	if (port->threads)
		mm_free(port->threads);
	if (port->shutdownSemaphore)
		CloseHandle(port->shutdownSemaphore);
	mm_free(port);
	return NULL;
}

static void
_event_iocp_port_unlock_and_free(struct event_iocp_port *port)
{
	DeleteCriticalSection(&port->lock);
	CloseHandle(port->port);
	CloseHandle(port->shutdownSemaphore);
	mm_free(port->threads);
	mm_free(port);
}

static int
event_iocp_notify_all(struct event_iocp_port *port)
{
	int i, r, ok=1;
	for (i=0; i<port->n_threads; ++i) {
		r = PostQueuedCompletionStatus(port->port, 0, NOTIFICATION_KEY,
		    NULL);
		if (!r)
			ok = 0;
	}
	return ok ? 0 : -1;
}

int
event_iocp_shutdown(struct event_iocp_port *port, long waitMsec)
{
	int n;
	EnterCriticalSection(&port->lock);
	port->shutdown = 1;
	LeaveCriticalSection(&port->lock);
	event_iocp_notify_all(port);

	WaitForSingleObject(port->shutdownSemaphore, waitMsec);
	EnterCriticalSection(&port->lock);
	n = port->n_live_threads;
	LeaveCriticalSection(&port->lock);
	if (n == 0) {
		_event_iocp_port_unlock_and_free(port);
		return 0;
	} else {
		return -1;
	}
}

int
event_iocp_activate_overlapped(
    struct event_iocp_port *port, struct event_overlapped *o,
    uintptr_t key, ev_uint32_t n)
{
	BOOL r;

	r = PostQueuedCompletionStatus(port->port, n, key, &o->overlapped);
	return (r==0) ? -1 : 0;
}

struct event_iocp_port *
event_base_get_iocp(struct event_base *base)
{
#ifdef WIN32
	return base->iocp;
#else
	return NULL;
#endif
}

