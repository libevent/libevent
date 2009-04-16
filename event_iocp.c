
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
