/*
 * Copyright 2009 Niels Provos and Nick Mathewson
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
#include "event-config.h"

#ifdef WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <sys/locking.h>
#endif

struct event_base;
#include <event2/thread.h>

#include "mm-internal.h"

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
evthread_use_windows_threads(void)
{
	evthread_set_lock_create_callbacks(
            evthread_win32_lock_create,
            evthread_win32_lock_free);
	evthread_set_locking_callback(evthread_win32_lock);
	evthread_set_id_callback(evthread_win32_get_id);
	return 0;
}

