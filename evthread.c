/*
 * Copyright (c) 2008-2009 Niels Provos, Nick Mathewson
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

#ifndef _EVENT_DISABLE_THREAD_SUPPORT

#include <event2/thread.h>

#include <stdlib.h>
#include <string.h>

#include "log-internal.h"
#include "mm-internal.h"
#include "util-internal.h"
#include "evthread-internal.h"

/* globals */
int _evthread_lock_debugging_enabled = 0;
struct evthread_lock_callbacks _evthread_lock_fns = {
	0, 0, NULL, NULL, NULL, NULL
};
/* Used for debugging */
static struct evthread_lock_callbacks _original_lock_fns = {
	0, 0, NULL, NULL, NULL, NULL
};
unsigned long (*_evthread_id_fn)(void) = NULL;

void
evthread_set_id_callback(unsigned long (*id_fn)(void))
{
	_evthread_id_fn = id_fn;
}

int
evthread_set_lock_callbacks(const struct evthread_lock_callbacks *cbs)
{
	struct evthread_lock_callbacks *target =
	    _evthread_lock_debugging_enabled
	    ? &_original_lock_fns : &_evthread_lock_fns;

	if (!cbs) {
		memset(target, 0, sizeof(_evthread_lock_fns));
		return 0;
	}
	if (cbs->alloc && cbs->free && cbs->lock && cbs->unlock) {
		memcpy(target, cbs, sizeof(_evthread_lock_fns));
		return 0;
	} else {
		return -1;
	}
}

#ifndef DISABLE_OBSOLETE_LOCK_API
/* Obsolete: for compatibility only.  Remove these before 2.0.x-stable! */

static void (*_obsolete_locking_fn)(int, void *) = NULL;
static void *(*_obsolete_lock_alloc_fn)(void) = NULL;
static void (*_obsolete_lock_free_fn)(void *) = NULL;

static void
api_warn(void)
{
	static int warned = 0;
	if (!warned) {
		warned = 1;
		event_warnx("evthread_set_locking_callback and "
		    "evthread_set_lock_create_callbacks are obsolete; use "
		    "evthread_set_lock_callbacks instead.");
	}
}

static void *
compat_lock_alloc(unsigned locktype)
{
	if (_obsolete_lock_alloc_fn)
		return _obsolete_lock_alloc_fn();
	return NULL;
}

static void
compat_lock_free(void *lock, unsigned locktype)
{
	if (_obsolete_lock_free_fn)
		_obsolete_lock_free_fn(lock);
}

static int
compat_lock_lock(unsigned mode, void *lock)
{
	_obsolete_locking_fn(EVTHREAD_LOCK|EVTHREAD_WRITE, lock);
	return 0;
}


static int
compat_lock_unlock(unsigned mode, void *lock)
{
	_obsolete_locking_fn(EVTHREAD_UNLOCK|EVTHREAD_WRITE, lock);
	return 0;
}

void
evthread_set_locking_callback(void (*locking_fn)(int mode, void *lock))
{
	api_warn();
	if (locking_fn) {
		_evthread_lock_fns.lock = compat_lock_lock;
		_evthread_lock_fns.unlock = compat_lock_unlock;
	} else {
		_evthread_lock_fns.lock = NULL;
		_evthread_lock_fns.unlock = NULL;
	}
	_obsolete_locking_fn = locking_fn;
}

void
evthread_set_lock_create_callbacks(void *(*alloc_fn)(void),
    void (*free_fn)(void *))
{
	api_warn();
	_obsolete_lock_alloc_fn = alloc_fn;
	_obsolete_lock_free_fn = free_fn;
	_evthread_lock_fns.alloc = alloc_fn ? compat_lock_alloc : NULL;
	_evthread_lock_fns.free = free_fn ? compat_lock_free : NULL;
}
#endif

struct debug_lock {
	unsigned locktype;
	unsigned long held_by;
	/* XXXX if we ever use read-write locks, we will need a separate
	 * lock to protect count. */
	int count;
	void *lock;
};

static void *
debug_lock_alloc(unsigned locktype)
{
	struct debug_lock *result = mm_malloc(sizeof(struct debug_lock));
	if (!result)
		return NULL;
	if (_original_lock_fns.alloc) {
		if (!(result->lock = _original_lock_fns.alloc(
				locktype|EVTHREAD_LOCKTYPE_RECURSIVE))) {
			mm_free(result);
			return NULL;
		}
	} else {
		result->lock = NULL;
	}
	result->locktype = locktype;
	result->count = 0;
	result->held_by = 0;
	return result;
}

static void
debug_lock_free(void *lock_, unsigned locktype)
{
	struct debug_lock *lock = lock_;
	EVUTIL_ASSERT(lock->count == 0);
	EVUTIL_ASSERT(locktype == lock->locktype);
	if (_original_lock_fns.free) {
		_original_lock_fns.free(lock->lock,
		    lock->locktype|EVTHREAD_LOCKTYPE_RECURSIVE);
	}
	lock->lock = NULL;
	lock->count = -100;
	mm_free(lock);
}

static int
debug_lock_lock(unsigned mode, void *lock_)
{
	struct debug_lock *lock = lock_;
	int res = 0;
	if (lock->locktype & EVTHREAD_LOCKTYPE_READWRITE)
		EVUTIL_ASSERT(mode & (EVTHREAD_READ|EVTHREAD_WRITE));
	else
		EVUTIL_ASSERT((mode & (EVTHREAD_READ|EVTHREAD_WRITE)) == 0);
	if (_original_lock_fns.lock)
		res = _original_lock_fns.lock(mode, lock->lock);
	if (!res) {
		++lock->count;
		if (!(lock->locktype & EVTHREAD_LOCKTYPE_RECURSIVE))
			EVUTIL_ASSERT(lock->count == 1);
		if (_evthread_id_fn) {
			unsigned long me;
			me = _evthread_id_fn();
			if (lock->count > 1)
				EVUTIL_ASSERT(lock->held_by == me);
			lock->held_by = me;
		}
	}
	return res;
}

static int
debug_lock_unlock(unsigned mode, void *lock_)
{
	struct debug_lock *lock = lock_;
	int res = 0;
	if (lock->locktype & EVTHREAD_LOCKTYPE_READWRITE)
		EVUTIL_ASSERT(mode & (EVTHREAD_READ|EVTHREAD_WRITE));
	else
		EVUTIL_ASSERT((mode & (EVTHREAD_READ|EVTHREAD_WRITE)) == 0);
	if (_evthread_id_fn) {
		unsigned long me = _evthread_id_fn();
		EVUTIL_ASSERT(lock->held_by == me);
		if (lock->count == 1)
			lock->held_by = 0;
	}
	--lock->count;
	EVUTIL_ASSERT(lock->count >= 0);
	if (_original_lock_fns.unlock)
		res = _original_lock_fns.unlock(mode, lock->lock);
	return res;
}

void
evthread_enable_lock_debuging(void)
{
	struct evthread_lock_callbacks cbs = {
		EVTHREAD_LOCK_API_VERSION,
		EVTHREAD_LOCKTYPE_RECURSIVE,
		debug_lock_alloc,
		debug_lock_free,
		debug_lock_lock,
		debug_lock_unlock
	};
	if (_evthread_lock_debugging_enabled)
		return;
	memcpy(&_original_lock_fns, &_evthread_lock_fns,
	    sizeof(struct evthread_lock_callbacks));
	memcpy(&_evthread_lock_fns, &cbs,
	    sizeof(struct evthread_lock_callbacks));
	_evthread_lock_debugging_enabled = 1;
}

int
_evthread_is_debug_lock_held(void *lock_)
{
	struct debug_lock *lock = lock_;
	if (! lock->count)
		return 0;
	if (_evthread_id_fn) {
		unsigned long me = _evthread_id_fn();
		if (lock->held_by != me)
			return 0;
	}
	return 1;
}

#endif
