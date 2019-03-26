/*
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

#include "event2/watch.h"
#include "event-internal.h"
#include "evthread-internal.h"

static inline struct evwatch *
evwatch_new(struct event_base *base, union evwatch_cb callback, void *arg, unsigned type)
{
	struct evwatch *watcher = mm_malloc(sizeof(struct evwatch));
	if (!watcher)
		return NULL;
	watcher->base = base;
	watcher->type = type;
	watcher->callback = callback;
	watcher->arg = arg;
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	TAILQ_INSERT_TAIL(&base->watchers[type], watcher, next);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return watcher;
}

struct evwatch *
evwatch_prepare_new(struct event_base *base, evwatch_prepare_cb callback, void *arg)
{
	union evwatch_cb cb = { .prepare = callback };
	return evwatch_new(base, cb, arg, EVWATCH_PREPARE);
}

struct evwatch *
evwatch_check_new(struct event_base *base, evwatch_check_cb callback, void *arg)
{
	union evwatch_cb cb = { .check = callback };
	return evwatch_new(base, cb, arg, EVWATCH_CHECK);
}

struct event_base *
evwatch_base(struct evwatch *watcher)
{
	return watcher->base;
}

void
evwatch_free(struct evwatch *watcher)
{
	EVBASE_ACQUIRE_LOCK(watcher->base, th_base_lock);
	TAILQ_REMOVE(&watcher->base->watchers[watcher->type], watcher, next);
	EVBASE_RELEASE_LOCK(watcher->base, th_base_lock);
	mm_free(watcher);
}

int
evwatch_prepare_get_timeout(const struct evwatch_prepare_cb_info *info, struct timeval *timeout)
{
	if (info->timeout) {
		*timeout = *(info->timeout);
		return 1;
	}
	return 0;
}
