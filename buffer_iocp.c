
#include "event2/buffer.h"
#incldue "buffer-internal.h"

#define MAX_WSABUFS 16

struct buffer_overlapped {
	struct event_overlapped event_overlapped;

	struct evbuffer_chain *first_pinned;
	struct evbuffer_overlapped *buf;
	int n_buffers;
	WSABUF buffers[MAX_WSABUFS];
};

struct evbuffer_overlapped {
	struct evbuffer buffer;
	evutil_socket_t fd;
	unsigned write_in_progress : 1;
	unsigned read_in_progress : 1;

	struct buffer_overlapped read_info;
	struct buffer_overlapped write_info;
};

static inline struct evbuffer_overlapped *
upcast_evbuffer(struct evbuffer *buf)
{
	if (!buf || !buf->is_overlapped)
		return NULL;
	return EVUTIL_UPCAST(buf, struct evbuffer_overlapped, buffer);
}

static inline struct buffer_overlapped *
upcast_overlapped(struct event_overlapped *o)
{
	return EVUTIL_UPCAST(o, struct buffer_overlapped, event_overlapped);
}

static void
pin_release(struct evbuffer_overlapped *eo, unsigned flag)
{
	int i;
	struct evbuffer_chain *chain = eo->first_pinned;

	for (i = 0; i < eo->n_buffers; ++i) {
		_evbuffer_chain_unpin(chain, flag);
		chain = chain->next;
		assert(chain);
	}
}

static void
read_completed(struct event_overlapped *eo, uintptr_t, ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;
	struct evbuffer *evbuf = &buf->buffer;

	struct evbuffer_chain chain = buf_o->first_pinned;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	evbuffer_unfreeze(evbuf, 0);

	if (chain == evbuf->previous_to_last) {
		size_t n = chain->buffer_len - (chain->misalign + chain->off);
		if (n>nBytes)
			n=nBytes;
		chain->off += n;
		nBytes -= n;
		evbuf->n_add_for_cb += n;

		evbuffer_commit_space(evbuf, nBytes);
	} else if (chain == evbuf->last) {
		evbuffer_commit_space(evbuf, nBytes);
	} else {
		assert(0);
	}

	pin_release(buf,EVBUFFER_MEM_PINNED_R);

	evbuf->read_in_progress = 0;
	_evbuffer_decref_and_unlock(evbuf);
}

static void
write_completed(struct event_overlapped *eo, uintptr_t, ssize_t nBytes)
{
	struct buffer_overlapped *buf_o = upcast_overlapped(eo);
	struct evbuffer_overlapped *buf = buf_o->buf;

	struct evbuffer *evbuf = &buf->buffer;

	EVBUFFER_LOCK(evbuf, EVTHREAD_WRITE);
	evbuffer_unfreeze(buf, 1);
	evbuffer_drain(evbuf, nBytes);
	pin_release(buf,EVBUFFER_MEM_PINNED_W);
	buf->write_in_progress = 0;
	_evbuffer_decref_and_unlock(evbuf);
}

struct evbuffer *
evbuffer_overlapped_new(evutil_socket_t fd)
{
	struct evbuffer_overlapped *evo;

	evo = mm_calloc(1, sizeof(struct evbuffer_overlapped));

	TAILQ_INIT(&evo->buf.callbacks);

	evo->buffer.is_overlapped = 1;

	return &evo->buffer;
}

int
evbuffer_launch_write(struct evbuffer *buf, ssize_t at_most)
{
	struct evbuffer_overlapped *buf_o = upcast_evbuffer(buf);
	int r = -1;
	int idx;
	struct evbuffer_chain *chain;

	if (!buf) {
		/* No buffer, or it isn't overlapped */
		return -1;
	}

	EVBUFFER_LOCK(buf, EVTHREAD_WRITE);
	if (buf->freeze_start || buf_o->write_in_progress)
		goto done;
	if (!buf->total_len) {
		/* Nothing to write */
		r = 0;
		goto done;
	} else if (at_most > buf->total_len || at_most < 0) {
		at_most = buf->total_len;
	}
	evbuffer_freeze(buf, 1);

	/* XXX we could move much of this into the constructor. */
	memset(&buf_o->write_info, 0, sizeof(buf_o->write_info));
	buf_o->write_info.buf = buf_o;
	buf_o->write_info.event_overlapped.cb = write_completed;
	chain = buf_o->first_pinned = buf->first;

	for (i=0; i < MAX_WSABUFS && chain; ++i, chain=chain->next) {
		WSABUF *b = &buf_o->write_info.buffers[i];
		b->buf = chain->buffer + chain->misalign;
		_evbuffer_chain_pin(chain, EVBUFFER_MEM_PINNED_W);

		if (at_most > chain->off) {
			b->len = chain->off;
			at_most -= chain->off;
		} else {
			b->len = at_most;
			++i;
			break;
		}
	}

	buf_o->write_info.n_vectors = i;
	_evbuffer_incref(buf);
	if (WSASend(buf->fd, b->buffers, i, &bytesSent, 0,
		&buf_o->write_info.event_overlapped.overlapped, NULL)) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			/* An actual error. */
			pin_release(buf_o, EVBUFFER_MEM_PINNED_W);
			evbuffer_unfreeze(buf, 1);
			evbuffer_free(buf); /* decref */
			goto done;
		}
	}

	buf_o->write_in_progress = 1;
	r = 0;
done:
	EVBUFFER_UNLOCK(buf, EVTHREAD_WRITE);
	return r;
}

int
evbuffer_launch_read(struct evbuffer *buf, size_t at_most)
{
	struct evbuffer_overlapped *buf_o = upcast_evbuffer(buf);
	int r = -1;
	WSABUF *buffers;
	int nvecs;
	struct evbuffer_chain *chain=NULL;

	if (!buf)
		return -1;
	EVBUFFER_LOCK(buf, EVTHREAD_WRITE);
	if (buf->freeze_end || buf_o->read_in_progress)
		goto done;

	if (_evbuffer_expand_fast(buf, howmuch) == -1)
		goto done;
	evbuffer_freeze(buf, 0);

	/* XXX we could move much of this into the constructor. */
	memset(&buf_o->read_info, 0, sizeof(buf_o->read_info));
	buf_o->read_info.buf = buf_o;
	buf_o->read_info.event_overlapped.cb = read_completed;

	nvecs = _evbuffer_read_setup_vecs(buf, howmuch,
	    buf_o->read_info.buffers, &chain);
	buf_o->read_info.n_buffers = nvecs;
	buf_o->first_pinned = chain;
	for ( ; chain; chain = chain->next)
		_evbuffer_chain_pin(chain, EVBUFFER_MEM_PINNED_R);

	_evbuffer_incref(buf);
	if (WSARecv(buf->fd, buf_o->read_info.buffers, nvecs, &bytesRead, &flags, &buf_o->read_info.event_overlapped.overlapped, NULL)) {
		int error = WSAGetLastError();
		if (error != WSA_IO_PENDING) {
			/* An actual error. */
			pin_release(buf_o, EVBUFFER_MEM_PINNED_R);
			evbuffer_unfreeze(buf, 0);
			evbuffer_free(buf); /* decref */
			goto done;
		}
	}

	buf_o->read_in_progress = 1;
	r = 0;
done:
	EVBUFFER_UNLOCK(buf, EVTHREAD_WRITE);
	return r;
}


/*

C++

typedef struct _OVERLAPPED_ENTRY {
  ULONG_PTR    lpCompletionKey;
  LPOVERLAPPED lpOverlapped;
  ULONG_PTR    Internal;
  DWORD        dwNumberOfBytesTransferred;
} OVERLAPPED_ENTRY, *LPOVERLAPPED_ENTRY;

C++

typedef struct _OVERLAPPED {
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    } ;
    PVOID Pointer;
  } ;
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

Any unused members of this structure should always be initialized to zero
before the structure is used in a function call. Otherwise, the function may
fail and return ERROR_INVALID_PARAMETER.

You can use the HasOverlappedIoCompleted macro to check whether an
asynchronous I/O operation has completed if GetOverlappedResult is too
cumbersome for your application.

You can use the CancelIo function to cancel an asynchronous I/O operation.

HANDLE WINAPI CreateIoCompletionPort(
  __in      HANDLE FileHandle,
  __in_opt  HANDLE ExistingCompletionPort,
  __in      ULONG_PTR CompletionKey,
  __in      DWORD NumberOfConcurrentThreads
);

BOOL WINAPI GetQueuedCompletionStatus(
  __in   HANDLE CompletionPort,
  __out  LPDWORD lpNumberOfBytes,
  __out  PULONG_PTR lpCompletionKey,
  __out  LPOVERLAPPED *lpOverlapped,
  __in   DWORD dwMilliseconds
);


If the function dequeues a completion packet for a successful I/O operation from the completion port, the return value is nonzero. The function stores information in the variables pointed to by the lpNumberOfBytes, lpCompletionKey, and lpOverlapped parameters.


BOOL WINAPI GetQueuedCompletionStatusEx(
  __in   HANDLE CompletionPort,
  __out  LPOVERLAPPED_ENTRY lpCompletionPortEntries,
  __in   ULONG ulCount,
  __out  PULONG ulNumEntriesRemoved,
  __in   DWORD dwMilliseconds,
  __in   BOOL fAlertable
);



BOOL PASCAL ConnectEx(
  __in      SOCKET s,
  __in      const struct sockaddr *name,
  __in      int namelen,
  __in_opt  PVOID lpSendBuffer,
  __in      DWORD dwSendDataLength,
  __out     LPDWORD lpdwBytesSent,
  __in      LPOVERLAPPED lpOverlapped
);

typedef void (*LPFN_CONNECTEX)( );

C++

BOOL AcceptEx(
  __in   SOCKET sListenSocket,
  __in   SOCKET sAcceptSocket,
  __in   PVOID lpOutputBuffer,
  __in   DWORD dwReceiveDataLength,
  __in   DWORD dwLocalAddressLength,
  __in   DWORD dwRemoteAddressLength,
  __out  LPDWORD lpdwBytesReceived,
  __in   LPOVERLAPPED lpOverlapped
);

C++

BOOL DisconnectEx(
  __in  SOCKET hSocket,
  __in  LPOVERLAPPED lpOverlapped,
  __in  DWORD dwFlags,
  __in  DWORD reserved
);

*/
