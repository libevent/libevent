
#include "event-config.h"
#include <sys/types.h>
#include <windows.h>
#include <WinBase.h>
#include "event2/util.h"
#include "util-internal.h"
#include "iocp-internal.h"

void
event_overlapped_init(struct event_overlapped *o, iocp_callback cb)
{
	memset(o, 0, sizeof(struct event_overlapped));
	o->cb = cb;
}

static void
handle_entry(OVERLAPPED *o, ULONG_PTR completion_key, DWORD nBytes)
{
	OVERLAPPED *o = ent->lpOverlapped;
	struct event_overlapped *eo =
	    EVUTIL_UPCAST(o, struct event_overlapped, overlapped);
	eo = upcast(o, struct event_overlapped, overlapped);
	eo->cb(eo, completion_key, nBytes);
}

static void
loop(struct event_iocp_port *port, long ms)
{
	OVERLAPPED *overlapped;
	ULONG_PTR key;
	DWORD bytes;

	if (ms <= 0)
		ms = INFINITE;

	while(GetQueuedCompletionStatus(port->port, &nBytes, &key,
		&overlapped, ms)) {
		handle_entry(overlapped, key, bytes);
	}
}

