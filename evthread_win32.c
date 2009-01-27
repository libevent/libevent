#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

struct event_base;
#include <event2/thread.h>

static void *
evthread_win32_lock_create(void)
{
	CRITICAL_SECTION *lock = mm_malloc(sizeof(CRITICAL_SECTION));
	if (!lock)
		return NULL;
	InitializeCriticalSection(lock);
	return lock;
}

static void
evthread_win32_lock_free(void *_lock)
{
	CRITICAL_SECTION *lock = _lock;
	DeleteCriticalSection(lock);
}

static void
evthread_win32_lock(int mode, void *_lock)
{
	CRITICAL_SECTION *lock = _lock;
	if (0 != (mode & EVTHREAD_LOCK))
		EnterCriticalSection(lock);
	else
		LeaveCriticalSection(lock);
}

static unsigned long
evthread_win32_get_id(void)
{
	return (unsigned long) GetCurrentThreadId();
}

int
evthread_use_windows_threads(struct event_base *base)
{
	evthread_set_lock_create_callbacks(base,
									   evthread_win32_lock_create,
									   evthread_win32_lock_free);
	evthread_set_locking_callback(base, evthread_win32_lock);
	evthread_set_id_callback(base, evthread_win32_get_id);
	return 0;
}

