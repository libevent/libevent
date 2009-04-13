
#include "iocp-internal.h"

#define N_OVERLAPPED_ENTRIES 32

void
event_overlapped_init(struct event_overlapped *o, iocp_callback cb)
{
	memeset(o, 0, sizeof(struct event_overlapped));
	o->cb = cb;
}

static void
handle_entry(OVERLAPPED_ENTRY *ent)
{
	OVERLAPPED *o = ent->lpOverlapped;
	struct event_overlapped *eo =
	    EVUTIL_UPCAST(o, struct event_overlapped, overlapped);
	eo = upcast(o, struct event_overlapped, overlapped);
	eo->cb(eo, ent->lpCompletionKey, ent->dwNumberOfBytesTransferred);
}

static void
loop(struct event_iocp_port *port, long ms)
{
	OVERLAPPED_ENTRY entries[N_OVERLAPPED_ENTRIES];
	ULONG n_entries;
	int i;

	if (ms <= 0)
		ms = INFINITE;

	while (GetQueuedCompletionStatusEx(port->port,
		entries, N_OVERLAPPED_ENTRIES, &n_entries, ms, 1)) {
		for (i = 0; i < n_entries; ++i) {
			handle_entry(&entries[i]);
		}
	}
}

