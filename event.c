/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
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
#include "event2/event-config.h"
#include "evconfig-private.h"

#ifdef _WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif
#include <sys/types.h>
#if !defined(_WIN32) && defined(EVENT__HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifdef EVENT__HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "event2/event.h"
#include "event2/event_struct.h"
#include "event2/event_compat.h"
#include "event-internal.h"
#include "defer-internal.h"
#include "evthread-internal.h"
#include "event2/thread.h"
#include "event2/util.h"
#include "log-internal.h"
#include "evmap-internal.h"
#include "iocp-internal.h"
#include "changelist-internal.h"
#define HT_NO_CACHE_HASH_VALUES
#include "ht-internal.h"
#include "util-internal.h"

#ifdef EVENT__HAVE_WORKING_KQUEUE
#include "kqueue-internal.h"
#endif

#undef timeout_add
#undef timeout_del
#undef timeout_pending

#define timeout event_timeout
#define timeouts event_timeouts
#define malloc mm_malloc
#define free mm_free
#define TIMEOUT_PUBLIC static __attribute__((unused))
#define TIMEOUT_DEBUG 0
#define TIMEOUT_CB_OVERRIDE
struct timeout_cb {
	struct event *arg;
};
#include "contrib/timeout/timeout.h"
#include "contrib/timeout/timeout.c"
#undef timeout
#undef timeouts
#undef malloc
#undef free

#define TV_TO_TIMEOUT(tv) (((ev_uint64_t)(tv)->tv_sec)*1000000 + (tv)->tv_usec)
#define TIMEOUT_TO_TV(tv,when)				\
	do {						\
		ev_uint64_t u64 = (when);		\
		(tv)->tv_usec = (long)(u64 % 1000000);	\
		(tv)->tv_sec = (time_t)(u64 / 1000000); \
	} while (0)

#ifdef EVENT__HAVE_EVENT_PORTS
extern const struct eventop evportops;
#endif
#ifdef EVENT__HAVE_SELECT
extern const struct eventop selectops;
#endif
#ifdef EVENT__HAVE_POLL
extern const struct eventop pollops;
#endif
#ifdef EVENT__HAVE_EPOLL
extern const struct eventop epollops;
#endif
#ifdef EVENT__HAVE_WORKING_KQUEUE
extern const struct eventop kqops;
#endif
#ifdef EVENT__HAVE_DEVPOLL
extern const struct eventop devpollops;
#endif
#ifdef _WIN32
extern const struct eventop win32ops;
#endif

/* Array of backends in order of preference. */
static const struct eventop *eventops[] = {
#ifdef EVENT__HAVE_EVENT_PORTS
	&evportops,
#endif
#ifdef EVENT__HAVE_WORKING_KQUEUE
	&kqops,
#endif
#ifdef EVENT__HAVE_EPOLL
	&epollops,
#endif
#ifdef EVENT__HAVE_DEVPOLL
	&devpollops,
#endif
#ifdef EVENT__HAVE_POLL
	&pollops,
#endif
#ifdef EVENT__HAVE_SELECT
	&selectops,
#endif
#ifdef _WIN32
	&win32ops,
#endif
	NULL
};

/* Global state; deprecated */
struct event_base *event_global_current_base_ = NULL;
#define current_base event_global_current_base_

/* Global state */

static void *event_self_cbarg_ptr_ = NULL;

/* Prototypes */
static void	event_queue_insert_active(struct event_base *, struct event_callback *);
static void	event_queue_insert_active_later(struct event_base *, struct event_callback *);
static int	event_queue_alloc_timeout(struct event *);
static void	event_queue_insert_timeout(struct event_base *, struct event *);
static void	event_queue_insert_inserted(struct event_base *, struct event *);
static void	event_queue_remove_active(struct event_base *, struct event_callback *);
static void	event_queue_remove_active_later(struct event_base *, struct event_callback *);
static void	event_queue_remove_timeout(struct event_base *, struct event *, int);
static void	event_queue_remove_inserted(struct event_base *, struct event *);
static void event_queue_make_later_events_active(struct event_base *base);

static int evthread_make_base_notifiable_nolock_(struct event_base *base);
static int event_del_(struct event *ev, int blocking);

static int	event_haveevents(struct event_base *);

static int	event_process_active(struct event_base *);

static int	timeout_next(struct event_base *, struct timeval **);
static void	timeout_process(struct event_base *);

static inline void	event_signal_closure(struct event_base *, struct event *ev);
static inline void	event_persist_closure(struct event_base *, struct event *ev);

static int	evthread_notify_base(struct event_base *base);

#ifndef EVENT__DISABLE_DEBUG_MODE
/* These functions implement a hashtable of which 'struct event *' structures
 * have been setup or added.  We don't want to trust the content of the struct
 * event itself, since we're trying to work through cases where an event gets
 * clobbered or freed.  Instead, we keep a hashtable indexed by the pointer.
 */

struct event_debug_entry {
	HT_ENTRY(event_debug_entry) node;
	const struct event *ptr;
	unsigned added : 1;
};

static inline unsigned
hash_debug_entry(const struct event_debug_entry *e)
{
	/* We need to do this silliness to convince compilers that we
	 * honestly mean to cast e->ptr to an integer, and discard any
	 * part of it that doesn't fit in an unsigned.
	 */
	unsigned u = (unsigned) ((ev_uintptr_t) e->ptr);
	/* Our hashtable implementation is pretty sensitive to low bits,
	 * and every struct event is over 64 bytes in size, so we can
	 * just say >>6. */
	return (u >> 6);
}

static inline int
eq_debug_entry(const struct event_debug_entry *a,
    const struct event_debug_entry *b)
{
	return a->ptr == b->ptr;
}

int event_debug_mode_on_ = 0;


#if !defined(EVENT__DISABLE_THREAD_SUPPORT) && !defined(EVENT__DISABLE_DEBUG_MODE)
/**
 * @brief debug mode variable which is set for any function/structure that needs
 *        to be shared across threads (if thread support is enabled).
 *
 *        When and if evthreads are initialized, this variable will be evaluated,
 *        and if set to something other than zero, this means the evthread setup 
 *        functions were called out of order.
 *
 *        See: "Locks and threading" in the documentation.
 */
int event_debug_created_threadable_ctx_ = 0;
#endif

/* Set if it's too late to enable event_debug_mode. */
static int event_debug_mode_too_late = 0;
#ifndef EVENT__DISABLE_THREAD_SUPPORT
static void *event_debug_map_lock_ = NULL;
#endif
static HT_HEAD(event_debug_map, event_debug_entry) global_debug_map =
	HT_INITIALIZER();

HT_PROTOTYPE(event_debug_map, event_debug_entry, node, hash_debug_entry,
    eq_debug_entry)
HT_GENERATE(event_debug_map, event_debug_entry, node, hash_debug_entry,
    eq_debug_entry, 0.5, mm_malloc, mm_realloc, mm_free)

/* Macro: record that ev is now setup (that is, ready for an add) */
#define event_debug_note_setup_(ev) do {				\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (dent) {						\
			dent->added = 0;				\
		} else {						\
			dent = mm_malloc(sizeof(*dent));		\
			if (!dent)					\
				event_err(1,				\
				    "Out of memory in debugging code");	\
			dent->ptr = (ev);				\
			dent->added = 0;				\
			HT_INSERT(event_debug_map, &global_debug_map, dent); \
		}							\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	event_debug_mode_too_late = 1;					\
	} while (0)
/* Macro: record that ev is no longer setup */
#define event_debug_note_teardown_(ev) do {				\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_REMOVE(event_debug_map, &global_debug_map, &find); \
		if (dent)						\
			mm_free(dent);					\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	event_debug_mode_too_late = 1;					\
	} while (0)
/* Macro: record that ev is now added */
#define event_debug_note_add_(ev)	do {				\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (dent) {						\
			dent->added = 1;				\
		} else {						\
			event_errx(EVENT_ERR_ABORT_,			\
			    "%s: noting an add on a non-setup event %p" \
			    " (events: 0x%x, fd: "EV_SOCK_FMT		\
			    ", flags: 0x%x)",				\
			    __func__, (ev), (ev)->ev_events,		\
			    EV_SOCK_ARG((ev)->ev_fd), (ev)->ev_flags);	\
		}							\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	event_debug_mode_too_late = 1;					\
	} while (0)
/* Macro: record that ev is no longer added */
#define event_debug_note_del_(ev) do {					\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (dent) {						\
			dent->added = 0;				\
		} else {						\
			event_errx(EVENT_ERR_ABORT_,			\
			    "%s: noting a del on a non-setup event %p"	\
			    " (events: 0x%x, fd: "EV_SOCK_FMT		\
			    ", flags: 0x%x)",				\
			    __func__, (ev), (ev)->ev_events,		\
			    EV_SOCK_ARG((ev)->ev_fd), (ev)->ev_flags);	\
		}							\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	event_debug_mode_too_late = 1;					\
	} while (0)
/* Macro: assert that ev is setup (i.e., okay to add or inspect) */
#define event_debug_assert_is_setup_(ev) do {				\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (!dent) {						\
			event_errx(EVENT_ERR_ABORT_,			\
			    "%s called on a non-initialized event %p"	\
			    " (events: 0x%x, fd: "EV_SOCK_FMT\
			    ", flags: 0x%x)",				\
			    __func__, (ev), (ev)->ev_events,		\
			    EV_SOCK_ARG((ev)->ev_fd), (ev)->ev_flags);	\
		}							\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	} while (0)
/* Macro: assert that ev is not added (i.e., okay to tear down or set
 * up again) */
#define event_debug_assert_not_added_(ev) do {				\
	if (event_debug_mode_on_) {					\
		struct event_debug_entry *dent,find;			\
		find.ptr = (ev);					\
		EVLOCK_LOCK(event_debug_map_lock_, 0);			\
		dent = HT_FIND(event_debug_map, &global_debug_map, &find); \
		if (dent && dent->added) {				\
			event_errx(EVENT_ERR_ABORT_,			\
			    "%s called on an already added event %p"	\
			    " (events: 0x%x, fd: "EV_SOCK_FMT", "	\
			    "flags: 0x%x)",				\
			    __func__, (ev), (ev)->ev_events,		\
			    EV_SOCK_ARG((ev)->ev_fd), (ev)->ev_flags);	\
		}							\
		EVLOCK_UNLOCK(event_debug_map_lock_, 0);		\
	}								\
	} while (0)
#else
#define event_debug_note_setup_(ev) \
	((void)0)
#define event_debug_note_teardown_(ev) \
	((void)0)
#define event_debug_note_add_(ev) \
	((void)0)
#define event_debug_note_del_(ev) \
	((void)0)
#define event_debug_assert_is_setup_(ev) \
	((void)0)
#define event_debug_assert_not_added_(ev) \
	((void)0)
#endif

#define EVENT_BASE_ASSERT_LOCKED(base)		\
	EVLOCK_ASSERT_LOCKED((base)->th_base_lock)

/* How often (in seconds) do we check for changes in wall clock time relative
 * to monotonic time?  Set this to -1 for 'never.' */
#define CLOCK_SYNC_INTERVAL 5

/** Set 'tp' to the current time according to 'base'.  We must hold the lock
 * on 'base'.  If there is a cached time, return it.  Otherwise, use
 * clock_gettime or gettimeofday as appropriate to find out the right time.
 * Return 0 on success, -1 on failure.
 */
static int
gettime(struct event_base *base, struct timeval *tp)
{
	EVENT_BASE_ASSERT_LOCKED(base);

	if (base->tv_cache.tv_sec) {
		*tp = base->tv_cache;
		return (0);
	}

	if (evutil_gettime_monotonic_(&base->monotonic_timer, tp) == -1) {
		return -1;
	}

	if (base->last_updated_clock_diff + CLOCK_SYNC_INTERVAL
	    < tp->tv_sec) {
		struct timeval tv;
		evutil_gettimeofday(&tv,NULL);
		evutil_timersub(&tv, tp, &base->tv_clock_diff);
		base->last_updated_clock_diff = tp->tv_sec;
	}

	return 0;
}

int
event_base_gettimeofday_cached(struct event_base *base, struct timeval *tv)
{
	int r;
	if (!base) {
		base = current_base;
		if (!current_base)
			return evutil_gettimeofday(tv, NULL);
	}

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	if (base->tv_cache.tv_sec == 0) {
		r = evutil_gettimeofday(tv, NULL);
	} else {
		evutil_timeradd(&base->tv_cache, &base->tv_clock_diff, tv);
		r = 0;
	}
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

/** Make 'base' have no current cached time. */
static inline void
clear_time_cache(struct event_base *base)
{
	base->tv_cache.tv_sec = 0;
}

/** Replace the cached time in 'base' with the current time. */
static inline void
update_time_cache(struct event_base *base)
{
	base->tv_cache.tv_sec = 0;
	if (!(base->flags & EVENT_BASE_FLAG_NO_CACHE_TIME))
	    gettime(base, &base->tv_cache);
}

int
event_base_update_cache_time(struct event_base *base)
{

	if (!base) {
		base = current_base;
		if (!current_base)
			return -1;
	}

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	if (base->running_loop)
		update_time_cache(base);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return 0;
}

static inline struct event *
event_callback_to_event(struct event_callback *evcb)
{
	EVUTIL_ASSERT((evcb->evcb_flags & EVLIST_INIT));
	return EVUTIL_UPCAST(evcb, struct event, ev_evcallback);
}

static inline struct event_callback *
event_to_event_callback(struct event *ev)
{
	return &ev->ev_evcallback;
}

struct event_base *
event_init(void)
{
	struct event_base *base = event_base_new_with_config(NULL);

	if (base == NULL) {
		event_errx(1, "%s: Unable to construct event_base", __func__);
		return NULL;
	}

	current_base = base;

	return (base);
}

struct event_base *
event_base_new(void)
{
	struct event_base *base = NULL;
	struct event_config *cfg = event_config_new();
	if (cfg) {
		base = event_base_new_with_config(cfg);
		event_config_free(cfg);
	}
	return base;
}

/** Return true iff 'method' is the name of a method that 'cfg' tells us to
 * avoid. */
static int
event_config_is_avoided_method(const struct event_config *cfg,
    const char *method)
{
	struct event_config_entry *entry;

	TAILQ_FOREACH(entry, &cfg->entries, next) {
		if (entry->avoid_method != NULL &&
		    strcmp(entry->avoid_method, method) == 0)
			return (1);
	}

	return (0);
}

/** Return true iff 'method' is disabled according to the environment. */
static int
event_is_method_disabled(const char *name)
{
	char environment[64];
	int i;

	evutil_snprintf(environment, sizeof(environment), "EVENT_NO%s", name);
	for (i = 8; environment[i] != '\0'; ++i)
		environment[i] = EVUTIL_TOUPPER_(environment[i]);
	/* Note that evutil_getenv_() ignores the environment entirely if
	 * we're setuid */
	return (evutil_getenv_(environment) != NULL);
}

int
event_base_get_features(const struct event_base *base)
{
	return base->evsel->features;
}

void
event_enable_debug_mode(void)
{
#ifndef EVENT__DISABLE_DEBUG_MODE
	if (event_debug_mode_on_)
		event_errx(1, "%s was called twice!", __func__);
	if (event_debug_mode_too_late)
		event_errx(1, "%s must be called *before* creating any events "
		    "or event_bases",__func__);

	event_debug_mode_on_ = 1;

	HT_INIT(event_debug_map, &global_debug_map);
#endif
}

void
event_disable_debug_mode(void)
{
#ifndef EVENT__DISABLE_DEBUG_MODE
	struct event_debug_entry **ent, *victim;

	EVLOCK_LOCK(event_debug_map_lock_, 0);
	for (ent = HT_START(event_debug_map, &global_debug_map); ent; ) {
		victim = *ent;
		ent = HT_NEXT_RMV(event_debug_map, &global_debug_map, ent);
		mm_free(victim);
	}
	HT_CLEAR(event_debug_map, &global_debug_map);
	EVLOCK_UNLOCK(event_debug_map_lock_ , 0);

	event_debug_mode_on_  = 0;
#endif
}

struct event_base *
event_base_new_with_config(const struct event_config *cfg)
{
	int i;
	struct event_base *base;
	int should_check_environment;

#ifndef EVENT__DISABLE_DEBUG_MODE
	event_debug_mode_too_late = 1;
#endif

	if ((base = mm_calloc(1, sizeof(struct event_base))) == NULL) {
		event_warn("%s: calloc", __func__);
		return NULL;
	}

	if (cfg)
		base->flags = cfg->flags;

	should_check_environment =
	    !(cfg && (cfg->flags & EVENT_BASE_FLAG_IGNORE_ENV));

	{
		struct timeval tmp;
		int precise_time =
		    cfg && (cfg->flags & EVENT_BASE_FLAG_PRECISE_TIMER);
		int flags;
		if (should_check_environment && !precise_time) {
			precise_time = evutil_getenv_("EVENT_PRECISE_TIMER") != NULL;
			base->flags |= EVENT_BASE_FLAG_PRECISE_TIMER;
		}
		flags = precise_time ? EV_MONOT_PRECISE : 0;
		evutil_configure_monotonic_time_(&base->monotonic_timer, flags);

		gettime(base, &tmp);
	}

	{
		int err;
		base->timeout_queue = timeouts_open(0, &err);
		if (!base->timeout_queue) {
			event_base_free(base);
			return NULL;
		}
	}

	base->sig.ev_signal_pair[0] = -1;
	base->sig.ev_signal_pair[1] = -1;
	base->th_notify_fd[0] = -1;
	base->th_notify_fd[1] = -1;

	TAILQ_INIT(&base->active_later_queue);

	evmap_io_initmap_(&base->io);
	evmap_signal_initmap_(&base->sigmap);
	event_changelist_init_(&base->changelist);

	base->evbase = NULL;

	if (cfg) {
		memcpy(&base->max_dispatch_time,
		    &cfg->max_dispatch_interval, sizeof(struct timeval));
		base->limit_callbacks_after_prio =
		    cfg->limit_callbacks_after_prio;
	} else {
		base->max_dispatch_time.tv_sec = -1;
		base->limit_callbacks_after_prio = 1;
	}
	if (cfg && cfg->max_dispatch_callbacks >= 0) {
		base->max_dispatch_callbacks = cfg->max_dispatch_callbacks;
	} else {
		base->max_dispatch_callbacks = INT_MAX;
	}
	if (base->max_dispatch_callbacks == INT_MAX &&
	    base->max_dispatch_time.tv_sec == -1)
		base->limit_callbacks_after_prio = INT_MAX;

	for (i = 0; eventops[i] && !base->evbase; i++) {
		if (cfg != NULL) {
			/* determine if this backend should be avoided */
			if (event_config_is_avoided_method(cfg,
				eventops[i]->name))
				continue;
			if ((eventops[i]->features & cfg->require_features)
			    != cfg->require_features)
				continue;
		}

		/* also obey the environment variables */
		if (should_check_environment &&
		    event_is_method_disabled(eventops[i]->name))
			continue;

		base->evsel = eventops[i];

		base->evbase = base->evsel->init(base);
	}

	if (base->evbase == NULL) {
		event_warnx("%s: no event mechanism available",
		    __func__);
		base->evsel = NULL;
		event_base_free(base);
		return NULL;
	}

	if (evutil_getenv_("EVENT_SHOW_METHOD"))
		event_msgx("libevent using: %s", base->evsel->name);

	/* allocate a single active event queue */
	if (event_base_priority_init(base, 1) < 0) {
		event_base_free(base);
		return NULL;
	}

	/* prepare for threading */

#if !defined(EVENT__DISABLE_THREAD_SUPPORT) && !defined(EVENT__DISABLE_DEBUG_MODE)
	event_debug_created_threadable_ctx_ = 1;
#endif

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (EVTHREAD_LOCKING_ENABLED() &&
	    (!cfg || !(cfg->flags & EVENT_BASE_FLAG_NOLOCK))) {
		int r;
		EVTHREAD_ALLOC_LOCK(base->th_base_lock, 0);
		EVTHREAD_ALLOC_COND(base->current_event_cond);
		r = evthread_make_base_notifiable(base);
		if (r<0) {
			event_warnx("%s: Unable to make base notifiable.", __func__);
			event_base_free(base);
			return NULL;
		}
	}
#endif

#ifdef _WIN32
	if (cfg && (cfg->flags & EVENT_BASE_FLAG_STARTUP_IOCP))
		event_base_start_iocp_(base, cfg->n_cpus_hint);
#endif

	return (base);
}

int
event_base_start_iocp_(struct event_base *base, int n_cpus)
{
#ifdef _WIN32
	if (base->iocp)
		return 0;
	base->iocp = event_iocp_port_launch_(n_cpus);
	if (!base->iocp) {
		event_warnx("%s: Couldn't launch IOCP", __func__);
		return -1;
	}
	return 0;
#else
	return -1;
#endif
}

void
event_base_stop_iocp_(struct event_base *base)
{
#ifdef _WIN32
	int rv;

	if (!base->iocp)
		return;
	rv = event_iocp_shutdown_(base->iocp, -1);
	EVUTIL_ASSERT(rv >= 0);
	base->iocp = NULL;
#endif
}

static int
event_base_cancel_single_callback_(struct event_base *base,
    struct event_callback *evcb,
    int run_finalizers)
{
	int result = 0;

	if (evcb->evcb_flags & EVLIST_INIT) {
		struct event *ev = event_callback_to_event(evcb);
		if (!(ev->ev_flags & EVLIST_INTERNAL)) {
			event_del_(ev, EVENT_DEL_EVEN_IF_FINALIZING);
			result = 1;
		}
	} else {
		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		event_callback_cancel_nolock_(base, evcb, 1);
		EVBASE_RELEASE_LOCK(base, th_base_lock);
		result = 1;
	}

	if (run_finalizers && (evcb->evcb_flags & EVLIST_FINALIZING)) {
		switch (evcb->evcb_closure) {
		case EV_CLOSURE_EVENT_FINALIZE:
		case EV_CLOSURE_EVENT_FINALIZE_FREE: {
			struct event *ev = event_callback_to_event(evcb);
			ev->ev_evcallback.evcb_cb_union.evcb_evfinalize(ev, ev->ev_arg);
			if (evcb->evcb_closure == EV_CLOSURE_EVENT_FINALIZE_FREE)
				mm_free(ev);
			break;
		}
		case EV_CLOSURE_CB_FINALIZE:
			evcb->evcb_cb_union.evcb_cbfinalize(evcb, evcb->evcb_arg);
			break;
		default:
			break;
		}
	}
	return result;
}

static int event_base_free_queues_(struct event_base *base, int run_finalizers)
{
	int deleted = 0, i;

	for (i = 0; i < base->nactivequeues; ++i) {
		struct event_callback *evcb, *next;
		for (evcb = TAILQ_FIRST(&base->activequeues[i]); evcb; ) {
			next = TAILQ_NEXT(evcb, evcb_active_next);
			deleted += event_base_cancel_single_callback_(base, evcb, run_finalizers);
			evcb = next;
		}
	}

	{
		struct event_callback *evcb;
		while ((evcb = TAILQ_FIRST(&base->active_later_queue))) {
			deleted += event_base_cancel_single_callback_(base, evcb, run_finalizers);
		}
	}

	return deleted;
}

static void
event_base_free_(struct event_base *base, int run_finalizers)
{
	int i, n_deleted=0;
	struct event *ev;
	/* XXXX grab the lock? If there is contention when one thread frees
	 * the base, then the contending thread will be very sad soon. */

	/* event_base_free(NULL) is how to free the current_base if we
	 * made it with event_init and forgot to hold a reference to it. */
	if (base == NULL && current_base)
		base = current_base;
	/* Don't actually free NULL. */
	if (base == NULL) {
		event_warnx("%s: no base to free", __func__);
		return;
	}
	/* XXX(niels) - check for internal events first */

#ifdef _WIN32
	event_base_stop_iocp_(base);
#endif

	/* threading fds if we have them */
	if (base->th_notify_fd[0] != -1) {
		event_del(&base->th_notify);
		EVUTIL_CLOSESOCKET(base->th_notify_fd[0]);
		if (base->th_notify_fd[1] != -1)
			EVUTIL_CLOSESOCKET(base->th_notify_fd[1]);
		base->th_notify_fd[0] = -1;
		base->th_notify_fd[1] = -1;
		event_debug_unassign(&base->th_notify);
	}

	/* Delete all non-internal events. */
	evmap_delete_all_(base);

	if (base->timeout_queue) {
		struct event_timeout *timeout;
		/* Expire all timeouts so we can pull them off the pqueue */
		timeouts_update(base->timeout_queue, EV_UINT64_MAX);
		while ((timeout = timeouts_get(base->timeout_queue))) {
			ev = timeout->callback.arg;
			event_del(ev);
			++n_deleted;
		}
	}

	for (;;) {
		/* For finalizers we can register yet another finalizer out from
		 * finalizer, and iff finalizer will be in active_later_queue we can
		 * add finalizer to activequeues, and we will have events in
		 * activequeues after this function returns, which is not what we want
		 * (we even have an assertion for this).
		 *
		 * A simple case is bufferevent with underlying (i.e. filters).
		 */
		int i = event_base_free_queues_(base, run_finalizers);
		if (!i) {
			break;
		}
		n_deleted += i;
	}

	if (n_deleted)
		event_debug(("%s: %d events were still set in base",
			__func__, n_deleted));

	while (LIST_FIRST(&base->once_events)) {
		struct event_once *eonce = LIST_FIRST(&base->once_events);
		LIST_REMOVE(eonce, next_once);
		mm_free(eonce);
	}

	if (base->evsel != NULL && base->evsel->dealloc != NULL)
		base->evsel->dealloc(base);

	for (i = 0; i < base->nactivequeues; ++i)
		EVUTIL_ASSERT(TAILQ_EMPTY(&base->activequeues[i]));

	if (base->timeout_queue) {
		EVUTIL_ASSERT(! timeouts_pending(base->timeout_queue));
		EVUTIL_ASSERT(! timeouts_expired(base->timeout_queue));
		timeouts_close(base->timeout_queue);
		base->timeout_queue = NULL;
	}

	mm_free(base->activequeues);

	evmap_io_clear_(&base->io);
	evmap_signal_clear_(&base->sigmap);
	event_changelist_freemem_(&base->changelist);

	EVTHREAD_FREE_LOCK(base->th_base_lock, 0);
	EVTHREAD_FREE_COND(base->current_event_cond);

	/* If we're freeing current_base, there won't be a current_base. */
	if (base == current_base)
		current_base = NULL;
	mm_free(base);
}

void
event_base_free_nofinalize(struct event_base *base)
{
	event_base_free_(base, 0);
}

void
event_base_free(struct event_base *base)
{
	event_base_free_(base, 1);
}

/* Fake eventop; used to disable the backend temporarily inside event_reinit
 * so that we can call event_del() on an event without telling the backend.
 */
static int
nil_backend_del(struct event_base *b, evutil_socket_t fd, short old,
    short events, void *fdinfo)
{
	return 0;
}
const struct eventop nil_eventop = {
	"nil",
	NULL, /* init: unused. */
	NULL, /* add: unused. */
	nil_backend_del, /* del: used, so needs to be killed. */
	NULL, /* dispatch: unused. */
	NULL, /* dealloc: unused. */
	0, 0, 0
};

/* reinitialize the event base after a fork */
int
event_reinit(struct event_base *base)
{
	const struct eventop *evsel;
	int res = 0;
	int was_notifiable = 0;
	int had_signal_added = 0;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	evsel = base->evsel;

	/* check if this event mechanism requires reinit on the backend */
	if (evsel->need_reinit) {
		/* We're going to call event_del() on our notify events (the
		 * ones that tell about signals and wakeup events).  But we
		 * don't actually want to tell the backend to change its
		 * state, since it might still share some resource (a kqueue,
		 * an epoll fd) with the parent process, and we don't want to
		 * delete the fds from _that_ backend, we temporarily stub out
		 * the evsel with a replacement.
		 */
		base->evsel = &nil_eventop;
	}

	/* We need to re-create a new signal-notification fd and a new
	 * thread-notification fd.  Otherwise, we'll still share those with
	 * the parent process, which would make any notification sent to them
	 * get received by one or both of the event loops, more or less at
	 * random.
	 */
	if (base->sig.ev_signal_added) {
		event_del_nolock_(&base->sig.ev_signal, EVENT_DEL_AUTOBLOCK);
		event_debug_unassign(&base->sig.ev_signal);
		memset(&base->sig.ev_signal, 0, sizeof(base->sig.ev_signal));
		had_signal_added = 1;
		base->sig.ev_signal_added = 0;
	}
	if (base->sig.ev_signal_pair[0] != -1)
		EVUTIL_CLOSESOCKET(base->sig.ev_signal_pair[0]);
	if (base->sig.ev_signal_pair[1] != -1)
		EVUTIL_CLOSESOCKET(base->sig.ev_signal_pair[1]);
	if (base->th_notify_fn != NULL) {
		was_notifiable = 1;
		base->th_notify_fn = NULL;
	}
	if (base->th_notify_fd[0] != -1) {
		event_del_nolock_(&base->th_notify, EVENT_DEL_AUTOBLOCK);
		EVUTIL_CLOSESOCKET(base->th_notify_fd[0]);
		if (base->th_notify_fd[1] != -1)
			EVUTIL_CLOSESOCKET(base->th_notify_fd[1]);
		base->th_notify_fd[0] = -1;
		base->th_notify_fd[1] = -1;
		event_debug_unassign(&base->th_notify);
	}

	/* Replace the original evsel. */
        base->evsel = evsel;

	if (evsel->need_reinit) {
		/* Reconstruct the backend through brute-force, so that we do
		 * not share any structures with the parent process. For some
		 * backends, this is necessary: epoll and kqueue, for
		 * instance, have events associated with a kernel
		 * structure. If didn't reinitialize, we'd share that
		 * structure with the parent process, and any changes made by
		 * the parent would affect our backend's behavior (and vice
		 * versa).
		 */
		if (base->evsel->dealloc != NULL)
			base->evsel->dealloc(base);
		base->evbase = evsel->init(base);
		if (base->evbase == NULL) {
			event_errx(1,
			   "%s: could not reinitialize event mechanism",
			   __func__);
			res = -1;
			goto done;
		}

		/* Empty out the changelist (if any): we are starting from a
		 * blank slate. */
		event_changelist_freemem_(&base->changelist);

		/* Tell the event maps to re-inform the backend about all
		 * pending events. This will make the signal notification
		 * event get re-created if necessary. */
		if (evmap_reinit_(base) < 0)
			res = -1;
	} else {
		res = evsig_init_(base);
		if (res == 0 && had_signal_added) {
			res = event_add_nolock_(&base->sig.ev_signal, NULL, 0);
			if (res == 0)
				base->sig.ev_signal_added = 1;
		}
	}

	/* If we were notifiable before, and nothing just exploded, become
	 * notifiable again. */
	if (was_notifiable && res == 0)
		res = evthread_make_base_notifiable_nolock_(base);

done:
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return (res);
}

/* Get the monotonic time for this event_base' timer */
int
event_gettime_monotonic(struct event_base *base, struct timeval *tv)
{
  int rv = -1;

  if (base && tv) {
    EVBASE_ACQUIRE_LOCK(base, th_base_lock);
    rv = evutil_gettime_monotonic_(&(base->monotonic_timer), tv);
    EVBASE_RELEASE_LOCK(base, th_base_lock);
  }

  return rv;
}

const char **
event_get_supported_methods(void)
{
	static const char **methods = NULL;
	const struct eventop **method;
	const char **tmp;
	int i = 0, k;

	/* count all methods */
	for (method = &eventops[0]; *method != NULL; ++method) {
		++i;
	}

	/* allocate one more than we need for the NULL pointer */
	tmp = mm_calloc((i + 1), sizeof(char *));
	if (tmp == NULL)
		return (NULL);

	/* populate the array with the supported methods */
	for (k = 0, i = 0; eventops[k] != NULL; ++k) {
		tmp[i++] = eventops[k]->name;
	}
	tmp[i] = NULL;

	if (methods != NULL)
		mm_free((char**)methods);

	methods = tmp;

	return (methods);
}

struct event_config *
event_config_new(void)
{
	struct event_config *cfg = mm_calloc(1, sizeof(*cfg));

	if (cfg == NULL)
		return (NULL);

	TAILQ_INIT(&cfg->entries);
	cfg->max_dispatch_interval.tv_sec = -1;
	cfg->max_dispatch_callbacks = INT_MAX;
	cfg->limit_callbacks_after_prio = 1;

	return (cfg);
}

static void
event_config_entry_free(struct event_config_entry *entry)
{
	if (entry->avoid_method != NULL)
		mm_free((char *)entry->avoid_method);
	mm_free(entry);
}

void
event_config_free(struct event_config *cfg)
{
	struct event_config_entry *entry;

	while ((entry = TAILQ_FIRST(&cfg->entries)) != NULL) {
		TAILQ_REMOVE(&cfg->entries, entry, next);
		event_config_entry_free(entry);
	}
	mm_free(cfg);
}

int
event_config_set_flag(struct event_config *cfg, int flag)
{
	if (!cfg)
		return -1;
	cfg->flags |= flag;
	return 0;
}

int
event_config_avoid_method(struct event_config *cfg, const char *method)
{
	struct event_config_entry *entry = mm_malloc(sizeof(*entry));
	if (entry == NULL)
		return (-1);

	if ((entry->avoid_method = mm_strdup(method)) == NULL) {
		mm_free(entry);
		return (-1);
	}

	TAILQ_INSERT_TAIL(&cfg->entries, entry, next);

	return (0);
}

int
event_config_require_features(struct event_config *cfg,
    int features)
{
	if (!cfg)
		return (-1);
	cfg->require_features = features;
	return (0);
}

int
event_config_set_num_cpus_hint(struct event_config *cfg, int cpus)
{
	if (!cfg)
		return (-1);
	cfg->n_cpus_hint = cpus;
	return (0);
}

int
event_config_set_max_dispatch_interval(struct event_config *cfg,
    const struct timeval *max_interval, int max_callbacks, int min_priority)
{
	if (max_interval)
		memcpy(&cfg->max_dispatch_interval, max_interval,
		    sizeof(struct timeval));
	else
		cfg->max_dispatch_interval.tv_sec = -1;
	cfg->max_dispatch_callbacks =
	    max_callbacks >= 0 ? max_callbacks : INT_MAX;
	if (min_priority < 0)
		min_priority = 0;
	cfg->limit_callbacks_after_prio = min_priority;
	return (0);
}

int
event_priority_init(int npriorities)
{
	return event_base_priority_init(current_base, npriorities);
}

int
event_base_priority_init(struct event_base *base, int npriorities)
{
	int i, r;
	r = -1;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (N_ACTIVE_CALLBACKS(base) || npriorities < 1
	    || npriorities >= EVENT_MAX_PRIORITIES)
		goto err;

	if (npriorities == base->nactivequeues)
		goto ok;

	if (base->nactivequeues) {
		mm_free(base->activequeues);
		base->nactivequeues = 0;
	}

	/* Allocate our priority queues */
	base->activequeues = (struct evcallback_list *)
	  mm_calloc(npriorities, sizeof(struct evcallback_list));
	if (base->activequeues == NULL) {
		event_warn("%s: calloc", __func__);
		goto err;
	}
	base->nactivequeues = npriorities;

	for (i = 0; i < base->nactivequeues; ++i) {
		TAILQ_INIT(&base->activequeues[i]);
	}

ok:
	r = 0;
err:
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return (r);
}

int
event_base_get_npriorities(struct event_base *base)
{

	int n;
	if (base == NULL)
		base = current_base;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	n = base->nactivequeues;
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return (n);
}

int
event_base_get_num_events(struct event_base *base, unsigned int type)
{
	int r = 0;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (type & EVENT_BASE_COUNT_ACTIVE)
		r += base->event_count_active;

	if (type & EVENT_BASE_COUNT_VIRTUAL)
		r += base->virtual_event_count;

	if (type & EVENT_BASE_COUNT_ADDED)
		r += base->event_count;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	return r;
}

int
event_base_get_max_events(struct event_base *base, unsigned int type, int clear)
{
	int r = 0;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (type & EVENT_BASE_COUNT_ACTIVE) {
		r += base->event_count_active_max;
		if (clear)
			base->event_count_active_max = 0;
	}

	if (type & EVENT_BASE_COUNT_VIRTUAL) {
		r += base->virtual_event_count_max;
		if (clear)
			base->virtual_event_count_max = 0;
	}

	if (type & EVENT_BASE_COUNT_ADDED) {
		r += base->event_count_max;
		if (clear)
			base->event_count_max = 0;
	}

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	return r;
}

/* Returns true iff we're currently watching any events. */
static int
event_haveevents(struct event_base *base)
{
	/* Caller must hold th_base_lock */
	return (base->virtual_event_count > 0 || base->event_count > 0);
}

/* "closure" function called when processing active signal events */
static inline void
event_signal_closure(struct event_base *base, struct event *ev)
{
	short ncalls;
	int should_break;

	/* Allows deletes to work */
	ncalls = ev->ev_ncalls;
	if (ncalls != 0)
		ev->ev_pncalls = &ncalls;
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	while (ncalls) {
		ncalls--;
		ev->ev_ncalls = ncalls;
		if (ncalls == 0)
			ev->ev_pncalls = NULL;
		(*ev->ev_callback)(ev->ev_fd, ev->ev_res, ev->ev_arg);

		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		should_break = base->event_break;
		EVBASE_RELEASE_LOCK(base, th_base_lock);

		if (should_break) {
			if (ncalls != 0)
				ev->ev_pncalls = NULL;
			return;
		}
	}
}

const struct timeval *
event_base_init_common_timeout(struct event_base *base,
    const struct timeval *duration)
{
	return duration;
}

/* Closure function invoked when we're activating a persistent event. */
static inline void
event_persist_closure(struct event_base *base, struct event *ev)
{
	void (*evcb_callback)(evutil_socket_t, short, void *);

        // Other fields of *ev that must be stored before executing
        evutil_socket_t evcb_fd;
        short evcb_res;
        void *evcb_arg;

	/* reschedule the persistent event if we have a timeout. */
	if (ev->ev_io_timeout.tv_sec || ev->ev_io_timeout.tv_usec) {
		/* If there was a timeout, we want it to run at an interval of
		 * ev_io_timeout after the last time it was _scheduled_ for,
		 * not ev_io_timeout after _now_.  If it fired for another
		 * reason, though, the timeout ought to start ticking _now_. */
		struct timeval run_at, relative_to, delay, now;
		ev_uint32_t usec_mask = 0;
		gettime(base, &now);
		if (1) {
			delay = ev->ev_io_timeout;
			if (ev->ev_res & EV_TIMEOUT) {
				relative_to = ev->ev_timeout;
			} else {
				relative_to = now;
			}
		}
		evutil_timeradd(&relative_to, &delay, &run_at);
		if (evutil_timercmp(&run_at, &now, <)) {
			/* Looks like we missed at least one invocation due to
			 * a clock jump, not running the event loop for a
			 * while, really slow callbacks, or
			 * something. Reschedule relative to now.
			 */
			evutil_timeradd(&now, &delay, &run_at);
		}
		run_at.tv_usec |= usec_mask;
		event_add_nolock_(ev, &run_at, 1);
	}

	// Save our callback before we release the lock
	evcb_callback = ev->ev_callback;
        evcb_fd = ev->ev_fd;
        evcb_res = ev->ev_res;
        evcb_arg = ev->ev_arg;

	// Release the lock
 	EVBASE_RELEASE_LOCK(base, th_base_lock);

	// Execute the callback
        (evcb_callback)(evcb_fd, evcb_res, evcb_arg);
}

/*
  Helper for event_process_active to process all the events in a single queue,
  releasing the lock as we go.  This function requires that the lock be held
  when it's invoked.  Returns -1 if we get a signal or an event_break that
  means we should stop processing any active events now.  Otherwise returns
  the number of non-internal event_callbacks that we processed.
*/
static int
event_process_active_single_queue(struct event_base *base,
    struct evcallback_list *activeq,
    int max_to_process, const struct timeval *endtime)
{
	struct event_callback *evcb;
	int count = 0;

	EVUTIL_ASSERT(activeq != NULL);

	for (evcb = TAILQ_FIRST(activeq); evcb; evcb = TAILQ_FIRST(activeq)) {
		struct event *ev=NULL;
		if (evcb->evcb_flags & EVLIST_INIT) {
			ev = event_callback_to_event(evcb);

			if (ev->ev_events & EV_PERSIST || ev->ev_flags & EVLIST_FINALIZING)
				event_queue_remove_active(base, evcb);
			else
				event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
			event_debug((
			    "event_process_active: event: %p, %s%s%scall %p",
			    ev,
			    ev->ev_res & EV_READ ? "EV_READ " : " ",
			    ev->ev_res & EV_WRITE ? "EV_WRITE " : " ",
			    ev->ev_res & EV_CLOSED ? "EV_CLOSED " : " ",
			    ev->ev_callback));
		} else {
			event_queue_remove_active(base, evcb);
			event_debug(("event_process_active: event_callback %p, "
				"closure %d, call %p",
				evcb, evcb->evcb_closure, evcb->evcb_cb_union.evcb_callback));
		}

		if (!(evcb->evcb_flags & EVLIST_INTERNAL))
			++count;


		base->current_event = evcb;
#ifndef EVENT__DISABLE_THREAD_SUPPORT
		base->current_event_waiters = 0;
#endif

		switch (evcb->evcb_closure) {
		case EV_CLOSURE_EVENT_SIGNAL:
			EVUTIL_ASSERT(ev != NULL);
			event_signal_closure(base, ev);
			break;
		case EV_CLOSURE_EVENT_PERSIST:
			EVUTIL_ASSERT(ev != NULL);
			event_persist_closure(base, ev);
			break;
		case EV_CLOSURE_EVENT: {
			void (*evcb_callback)(evutil_socket_t, short, void *);
			EVUTIL_ASSERT(ev != NULL);
			evcb_callback = *ev->ev_callback;
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			evcb_callback(ev->ev_fd, ev->ev_res, ev->ev_arg);
		}
		break;
		case EV_CLOSURE_CB_SELF: {
			void (*evcb_selfcb)(struct event_callback *, void *) = evcb->evcb_cb_union.evcb_selfcb;
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			evcb_selfcb(evcb, evcb->evcb_arg);
		}
		break;
		case EV_CLOSURE_EVENT_FINALIZE:
		case EV_CLOSURE_EVENT_FINALIZE_FREE: {
			void (*evcb_evfinalize)(struct event *, void *);
			int evcb_closure = evcb->evcb_closure;
			EVUTIL_ASSERT(ev != NULL);
			base->current_event = NULL;
			evcb_evfinalize = ev->ev_evcallback.evcb_cb_union.evcb_evfinalize;
			EVUTIL_ASSERT((evcb->evcb_flags & EVLIST_FINALIZING));
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			evcb_evfinalize(ev, ev->ev_arg);
			event_debug_note_teardown_(ev);
			if (evcb_closure == EV_CLOSURE_EVENT_FINALIZE_FREE)
				mm_free(ev);
		}
		break;
		case EV_CLOSURE_CB_FINALIZE: {
			void (*evcb_cbfinalize)(struct event_callback *, void *) = evcb->evcb_cb_union.evcb_cbfinalize;
			base->current_event = NULL;
			EVUTIL_ASSERT((evcb->evcb_flags & EVLIST_FINALIZING));
			EVBASE_RELEASE_LOCK(base, th_base_lock);
			evcb_cbfinalize(evcb, evcb->evcb_arg);
		}
		break;
		default:
			EVUTIL_ASSERT(0);
		}

		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		base->current_event = NULL;
#ifndef EVENT__DISABLE_THREAD_SUPPORT
		if (base->current_event_waiters) {
			base->current_event_waiters = 0;
			EVTHREAD_COND_BROADCAST(base->current_event_cond);
		}
#endif

		if (base->event_break)
			return -1;
		if (count >= max_to_process)
			return count;
		if (count && endtime) {
			struct timeval now;
			update_time_cache(base);
			gettime(base, &now);
			if (evutil_timercmp(&now, endtime, >=))
				return count;
		}
		if (base->event_continue)
			break;
	}
	return count;
}

/*
 * Active events are stored in priority queues.  Lower priorities are always
 * process before higher priorities.  Low priority events can starve high
 * priority ones.
 */

static int
event_process_active(struct event_base *base)
{
	/* Caller must hold th_base_lock */
	struct evcallback_list *activeq = NULL;
	int i, c = 0;
	const struct timeval *endtime;
	struct timeval tv;
	const int maxcb = base->max_dispatch_callbacks;
	const int limit_after_prio = base->limit_callbacks_after_prio;
	if (base->max_dispatch_time.tv_sec >= 0) {
		update_time_cache(base);
		gettime(base, &tv);
		evutil_timeradd(&base->max_dispatch_time, &tv, &tv);
		endtime = &tv;
	} else {
		endtime = NULL;
	}

	for (i = 0; i < base->nactivequeues; ++i) {
		if (TAILQ_FIRST(&base->activequeues[i]) != NULL) {
			base->event_running_priority = i;
			activeq = &base->activequeues[i];
			if (i < limit_after_prio)
				c = event_process_active_single_queue(base, activeq,
				    INT_MAX, NULL);
			else
				c = event_process_active_single_queue(base, activeq,
				    maxcb, endtime);
			if (c < 0) {
				goto done;
			} else if (c > 0)
				break; /* Processed a real event; do not
					* consider lower-priority events */
			/* If we get here, all of the events we processed
			 * were internal.  Continue. */
		}
	}

done:
	base->event_running_priority = -1;

	return c;
}

/*
 * Wait continuously for events.  We exit only if no events are left.
 */

int
event_dispatch(void)
{
	return (event_loop(0));
}

int
event_base_dispatch(struct event_base *event_base)
{
	return (event_base_loop(event_base, 0));
}

const char *
event_base_get_method(const struct event_base *base)
{
	EVUTIL_ASSERT(base);
	return (base->evsel->name);
}

/** Callback: used to implement event_base_loopexit by telling the event_base
 * that it's time to exit its loop. */
static void
event_loopexit_cb(evutil_socket_t fd, short what, void *arg)
{
	struct event_base *base = arg;
	base->event_gotterm = 1;
}

int
event_loopexit(const struct timeval *tv)
{
	return (event_once(-1, EV_TIMEOUT, event_loopexit_cb,
		    current_base, tv));
}

int
event_base_loopexit(struct event_base *event_base, const struct timeval *tv)
{
	return (event_base_once(event_base, -1, EV_TIMEOUT, event_loopexit_cb,
		    event_base, tv));
}

int
event_loopbreak(void)
{
	return (event_base_loopbreak(current_base));
}

int
event_base_loopbreak(struct event_base *event_base)
{
	int r = 0;
	if (event_base == NULL)
		return (-1);

	EVBASE_ACQUIRE_LOCK(event_base, th_base_lock);
	event_base->event_break = 1;

	if (EVBASE_NEED_NOTIFY(event_base)) {
		r = evthread_notify_base(event_base);
	} else {
		r = (0);
	}
	EVBASE_RELEASE_LOCK(event_base, th_base_lock);
	return r;
}

int
event_base_loopcontinue(struct event_base *event_base)
{
	int r = 0;
	if (event_base == NULL)
		return (-1);

	EVBASE_ACQUIRE_LOCK(event_base, th_base_lock);
	event_base->event_continue = 1;

	if (EVBASE_NEED_NOTIFY(event_base)) {
		r = evthread_notify_base(event_base);
	} else {
		r = (0);
	}
	EVBASE_RELEASE_LOCK(event_base, th_base_lock);
	return r;
}

int
event_base_got_break(struct event_base *event_base)
{
	int res;
	EVBASE_ACQUIRE_LOCK(event_base, th_base_lock);
	res = event_base->event_break;
	EVBASE_RELEASE_LOCK(event_base, th_base_lock);
	return res;
}

int
event_base_got_exit(struct event_base *event_base)
{
	int res;
	EVBASE_ACQUIRE_LOCK(event_base, th_base_lock);
	res = event_base->event_gotterm;
	EVBASE_RELEASE_LOCK(event_base, th_base_lock);
	return res;
}

/* not thread safe */

int
event_loop(int flags)
{
	return event_base_loop(current_base, flags);
}

int
event_base_loop(struct event_base *base, int flags)
{
	const struct eventop *evsel = base->evsel;
	struct timeval tv;
	struct timeval *tv_p;
	int res, done, retval = 0;

	/* Grab the lock.  We will release it inside evsel.dispatch, and again
	 * as we invoke user callbacks. */
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	if (base->running_loop) {
		event_warnx("%s: reentrant invocation.  Only one event_base_loop"
		    " can run on each event_base at once.", __func__);
		EVBASE_RELEASE_LOCK(base, th_base_lock);
		return -1;
	}

	base->running_loop = 1;

	clear_time_cache(base);

	if (base->sig.ev_signal_added && base->sig.ev_n_signals_added)
		evsig_set_base_(base);

	done = 0;

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	base->th_owner_id = EVTHREAD_GET_ID();
#endif

	base->event_gotterm = base->event_break = 0;

	while (!done) {
		base->event_continue = 0;
		base->n_deferreds_queued = 0;

		/* Terminate the loop if we have been asked to */
		if (base->event_gotterm) {
			break;
		}

		if (base->event_break) {
			break;
		}

		tv_p = &tv;
		if (!N_ACTIVE_CALLBACKS(base) && !(flags & EVLOOP_NONBLOCK)) {
			timeout_next(base, &tv_p);
		} else {
			/*
			 * if we have active events, we just poll new events
			 * without waiting.
			 */
			evutil_timerclear(&tv);
		}

		/* If we have no events, we just exit */
		if (0==(flags&EVLOOP_NO_EXIT_ON_EMPTY) &&
		    !event_haveevents(base) && !N_ACTIVE_CALLBACKS(base)) {
			event_debug(("%s: no events registered.", __func__));
			retval = 1;
			goto done;
		}

		event_queue_make_later_events_active(base);

		clear_time_cache(base);

		res = evsel->dispatch(base, tv_p);

		if (res == -1) {
			event_debug(("%s: dispatch returned unsuccessfully.",
				__func__));
			retval = -1;
			goto done;
		}

		update_time_cache(base);

		timeout_process(base);

		if (N_ACTIVE_CALLBACKS(base)) {
			int n = event_process_active(base);
			if ((flags & EVLOOP_ONCE)
			    && N_ACTIVE_CALLBACKS(base) == 0
			    && n != 0)
				done = 1;
		} else if (flags & EVLOOP_NONBLOCK)
			done = 1;
	}
	event_debug(("%s: asked to terminate loop.", __func__));

done:
	clear_time_cache(base);
	base->running_loop = 0;

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	return (retval);
}

/* One-time callback to implement event_base_once: invokes the user callback,
 * then deletes the allocated storage */
static void
event_once_cb(evutil_socket_t fd, short events, void *arg)
{
	struct event_once *eonce = arg;

	(*eonce->cb)(fd, events, eonce->arg);
	EVBASE_ACQUIRE_LOCK(eonce->ev.ev_base, th_base_lock);
	LIST_REMOVE(eonce, next_once);
	EVBASE_RELEASE_LOCK(eonce->ev.ev_base, th_base_lock);
	event_debug_unassign(&eonce->ev);
	mm_free(eonce);
}

/* not threadsafe, event scheduled once. */
int
event_once(evutil_socket_t fd, short events,
    void (*callback)(evutil_socket_t, short, void *),
    void *arg, const struct timeval *tv)
{
	return event_base_once(current_base, fd, events, callback, arg, tv);
}

/* Schedules an event once */
int
event_base_once(struct event_base *base, evutil_socket_t fd, short events,
    void (*callback)(evutil_socket_t, short, void *),
    void *arg, const struct timeval *tv)
{
	struct event_once *eonce;
	int res = 0;
	int activate = 0;

	/* We cannot support signals that just fire once, or persistent
	 * events. */
	if (events & (EV_SIGNAL|EV_PERSIST))
		return (-1);

	if ((eonce = mm_calloc(1, sizeof(struct event_once))) == NULL)
		return (-1);

	eonce->cb = callback;
	eonce->arg = arg;

	if ((events & (EV_TIMEOUT|EV_SIGNAL|EV_READ|EV_WRITE|EV_CLOSED)) == EV_TIMEOUT) {
		evtimer_assign(&eonce->ev, base, event_once_cb, eonce);

		if (tv == NULL || ! evutil_timerisset(tv)) {
			/* If the event is going to become active immediately,
			 * don't put it on the timeout queue.  This is one
			 * idiom for scheduling a callback, so let's make
			 * it fast (and order-preserving). */
			activate = 1;
		}
	} else if (events & (EV_READ|EV_WRITE|EV_CLOSED)) {
		events &= EV_READ|EV_WRITE|EV_CLOSED;

		event_assign(&eonce->ev, base, fd, events, event_once_cb, eonce);
	} else {
		/* Bad event combination */
		mm_free(eonce);
		return (-1);
	}

	if (res == 0) {
		EVBASE_ACQUIRE_LOCK(base, th_base_lock);
		if (activate)
			event_active_nolock_(&eonce->ev, EV_TIMEOUT, 1);
		else
			res = event_add_nolock_(&eonce->ev, tv, 0);

		if (res != 0) {
			mm_free(eonce);
			return (res);
		} else {
			LIST_INSERT_HEAD(&base->once_events, eonce, next_once);
		}
		EVBASE_RELEASE_LOCK(base, th_base_lock);
	}

	return (0);
}

int
event_assign(struct event *ev, struct event_base *base, evutil_socket_t fd, short events, void (*callback)(evutil_socket_t, short, void *), void *arg)
{
	if (!base)
		base = current_base;
	if (arg == &event_self_cbarg_ptr_)
		arg = ev;

	event_debug_assert_not_added_(ev);

	ev->ev_base = base;

	ev->ev_callback = callback;
	ev->ev_arg = arg;
	ev->ev_fd = fd;
	ev->ev_events = events;
	ev->ev_res = 0;
	ev->ev_flags = EVLIST_INIT;
	ev->ev_ncalls = 0;
	ev->ev_pncalls = NULL;

	if (events & EV_SIGNAL) {
		if ((events & (EV_READ|EV_WRITE|EV_CLOSED)) != 0) {
			event_warnx("%s: EV_SIGNAL is not compatible with "
			    "EV_READ, EV_WRITE or EV_CLOSED", __func__);
			return -1;
		}
		ev->ev_closure = EV_CLOSURE_EVENT_SIGNAL;
	} else {
		if (events & EV_PERSIST) {
			evutil_timerclear(&ev->ev_io_timeout);
			ev->ev_closure = EV_CLOSURE_EVENT_PERSIST;
		} else {
			ev->ev_closure = EV_CLOSURE_EVENT;
		}
	}

	ev->ev_timeout_obj = NULL;

	if (base != NULL) {
		/* by default, we put new events into the middle priority */
		ev->ev_pri = base->nactivequeues / 2;
	}

	event_debug_note_setup_(ev);

	return 0;
}

int
event_base_set(struct event_base *base, struct event *ev)
{
	/* Only innocent events may be assigned to a different base */
	if (ev->ev_flags != EVLIST_INIT)
		return (-1);

	event_debug_assert_is_setup_(ev);

	ev->ev_base = base;
	ev->ev_pri = base->nactivequeues/2;

	return (0);
}

void
event_set(struct event *ev, evutil_socket_t fd, short events,
	  void (*callback)(evutil_socket_t, short, void *), void *arg)
{
	int r;
	r = event_assign(ev, current_base, fd, events, callback, arg);
	EVUTIL_ASSERT(r == 0);
}

void *
event_self_cbarg(void)
{
	return &event_self_cbarg_ptr_;
}

struct event *
event_base_get_running_event(struct event_base *base)
{
	struct event *ev = NULL;
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	if (EVBASE_IN_THREAD(base)) {
		struct event_callback *evcb = base->current_event;
		if (evcb->evcb_flags & EVLIST_INIT)
			ev = event_callback_to_event(evcb);
	}
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return ev;
}

struct event *
event_new(struct event_base *base, evutil_socket_t fd, short events, void (*cb)(evutil_socket_t, short, void *), void *arg)
{
	struct event *ev;
	ev = mm_malloc(sizeof(struct event));
	if (ev == NULL)
		return (NULL);
	if (event_assign(ev, base, fd, events, cb, arg) < 0) {
		mm_free(ev);
		return (NULL);
	}

	return (ev);
}

void
event_free(struct event *ev)
{
	/* This is disabled, so that events which have been finalized be a
	 * valid target for event_free(). That's */
	// event_debug_assert_is_setup_(ev);

	/* make sure that this event won't be coming back to haunt us. */
	event_del(ev);
	event_debug_note_teardown_(ev);
	mm_free(ev);

}

void
event_debug_unassign(struct event *ev)
{
	event_debug_assert_not_added_(ev);
	event_debug_note_teardown_(ev);

	ev->ev_flags &= ~EVLIST_INIT;
}

#define EVENT_FINALIZE_FREE_ 0x10000
static int
event_finalize_nolock_(struct event_base *base, unsigned flags, struct event *ev, event_finalize_callback_fn cb)
{
	ev_uint8_t closure = (flags & EVENT_FINALIZE_FREE_) ?
	    EV_CLOSURE_EVENT_FINALIZE_FREE : EV_CLOSURE_EVENT_FINALIZE;

	event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
	ev->ev_closure = closure;
	ev->ev_evcallback.evcb_cb_union.evcb_evfinalize = cb;
	event_active_nolock_(ev, EV_FINALIZE, 1);
	ev->ev_flags |= EVLIST_FINALIZING;
	return 0;
}

static int
event_finalize_impl_(unsigned flags, struct event *ev, event_finalize_callback_fn cb)
{
	int r;
	struct event_base *base = ev->ev_base;
	if (EVUTIL_FAILURE_CHECK(!base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return -1;
	}

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	r = event_finalize_nolock_(base, flags, ev, cb);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

int
event_finalize(unsigned flags, struct event *ev, event_finalize_callback_fn cb)
{
	return event_finalize_impl_(flags, ev, cb);
}

int
event_free_finalize(unsigned flags, struct event *ev, event_finalize_callback_fn cb)
{
	return event_finalize_impl_(flags|EVENT_FINALIZE_FREE_, ev, cb);
}

void
event_callback_finalize_nolock_(struct event_base *base, unsigned flags, struct event_callback *evcb, void (*cb)(struct event_callback *, void *))
{
	struct event *ev = NULL;
	if (evcb->evcb_flags & EVLIST_INIT) {
		ev = event_callback_to_event(evcb);
		event_del_nolock_(ev, EVENT_DEL_NOBLOCK);
	} else {
		event_callback_cancel_nolock_(base, evcb, 0); /*XXX can this fail?*/
	}

	evcb->evcb_closure = EV_CLOSURE_CB_FINALIZE;
	evcb->evcb_cb_union.evcb_cbfinalize = cb;
	event_callback_activate_nolock_(base, evcb); /* XXX can this really fail?*/
	evcb->evcb_flags |= EVLIST_FINALIZING;
}

void
event_callback_finalize_(struct event_base *base, unsigned flags, struct event_callback *evcb, void (*cb)(struct event_callback *, void *))
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	event_callback_finalize_nolock_(base, flags, evcb, cb);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

/** Internal: Finalize all of the n_cbs callbacks in evcbs.  The provided
 * callback will be invoked on *one of them*, after they have *all* been
 * finalized. */
int
event_callback_finalize_many_(struct event_base *base, int n_cbs, struct event_callback **evcbs, void (*cb)(struct event_callback *, void *))
{
	int n_pending = 0, i;

	if (base == NULL)
		base = current_base;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	event_debug(("%s: %d events finalizing", __func__, n_cbs));

	/* At most one can be currently executing; the rest we just
	 * cancel... But we always make sure that the finalize callback
	 * runs. */
	for (i = 0; i < n_cbs; ++i) {
		struct event_callback *evcb = evcbs[i];
		if (evcb == base->current_event) {
			event_callback_finalize_nolock_(base, 0, evcb, cb);
			++n_pending;
		} else {
			event_callback_cancel_nolock_(base, evcb, 0);
		}
	}

	if (n_pending == 0) {
		/* Just do the first one. */
		event_callback_finalize_nolock_(base, 0, evcbs[0], cb);
	}

	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return 0;
}

/*
 * Set's the priority of an event - if an event is already scheduled
 * changing the priority is going to fail.
 */

int
event_priority_set(struct event *ev, int pri)
{
	event_debug_assert_is_setup_(ev);

	if (ev->ev_flags & EVLIST_ACTIVE)
		return (-1);
	if (pri < 0 || pri >= ev->ev_base->nactivequeues)
		return (-1);

	ev->ev_pri = pri;

	return (0);
}

/*
 * Checks if a specific event is pending or scheduled.
 */

int
event_pending(const struct event *ev, short event, struct timeval *tv)
{
	int flags = 0;

	if (EVUTIL_FAILURE_CHECK(ev->ev_base == NULL)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return 0;
	}

	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);
	event_debug_assert_is_setup_(ev);

	if (ev->ev_flags & EVLIST_INSERTED)
		flags |= (ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL));
	if (ev->ev_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))
		flags |= ev->ev_res;
	if (ev->ev_flags & EVLIST_TIMEOUT)
		flags |= EV_TIMEOUT;

	event &= (EV_TIMEOUT|EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL);

	/* See if there is a timeout that we should report */
	if (tv != NULL && (flags & event & EV_TIMEOUT)) {
		struct timeval tmp = ev->ev_timeout;
		/* correctly remamp to real time */
		evutil_timeradd(&ev->ev_base->tv_clock_diff, &tmp, tv);
	}

	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

	return (flags & event);
}

int
event_initialized(const struct event *ev)
{
	if (!(ev->ev_flags & EVLIST_INIT))
		return 0;

	return 1;
}

void
event_get_assignment(const struct event *event, struct event_base **base_out, evutil_socket_t *fd_out, short *events_out, event_callback_fn *callback_out, void **arg_out)
{
	event_debug_assert_is_setup_(event);

	if (base_out)
		*base_out = event->ev_base;
	if (fd_out)
		*fd_out = event->ev_fd;
	if (events_out)
		*events_out = event->ev_events;
	if (callback_out)
		*callback_out = event->ev_callback;
	if (arg_out)
		*arg_out = event->ev_arg;
}

size_t
event_get_struct_event_size(void)
{
	return sizeof(struct event);
}

evutil_socket_t
event_get_fd(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_fd;
}

struct event_base *
event_get_base(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_base;
}

short
event_get_events(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_events;
}

event_callback_fn
event_get_callback(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_callback;
}

void *
event_get_callback_arg(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_arg;
}

int
event_get_priority(const struct event *ev)
{
	event_debug_assert_is_setup_(ev);
	return ev->ev_pri;
}

int
event_add(struct event *ev, const struct timeval *tv)
{
	int res;

	if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return -1;
	}

	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);

	res = event_add_nolock_(ev, tv, 0);

	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

	return (res);
}

/* Helper callback: wake an event_base from another thread.  This version
 * works by writing a byte to one end of a socketpair, so that the event_base
 * listening on the other end will wake up as the corresponding event
 * triggers */
static int
evthread_notify_base_default(struct event_base *base)
{
	char buf[1];
	int r;
	buf[0] = (char) 0;
#ifdef _WIN32
	r = send(base->th_notify_fd[1], buf, 1, 0);
#else
	r = write(base->th_notify_fd[1], buf, 1);
#endif
	return (r < 0 && ! EVUTIL_ERR_IS_EAGAIN(errno)) ? -1 : 0;
}

#ifdef EVENT__HAVE_EVENTFD
/* Helper callback: wake an event_base from another thread.  This version
 * assumes that you have a working eventfd() implementation. */
static int
evthread_notify_base_eventfd(struct event_base *base)
{
	ev_uint64_t msg = 1;
	int r;
	do {
		r = write(base->th_notify_fd[0], (void*) &msg, sizeof(msg));
	} while (r < 0 && errno == EAGAIN);

	return (r < 0) ? -1 : 0;
}
#endif


/** Tell the thread currently running the event_loop for base (if any) that it
 * needs to stop waiting in its dispatch function (if it is) and process all
 * active callbacks. */
static int
evthread_notify_base(struct event_base *base)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (!base->th_notify_fn)
		return -1;
	if (base->is_notify_pending)
		return 0;
	base->is_notify_pending = 1;
	return base->th_notify_fn(base);
}

/* Implementation function to remove a timeout on a currently pending event.
 */
int
event_remove_timer_nolock_(struct event *ev)
{
	struct event_base *base = ev->ev_base;

	EVENT_BASE_ASSERT_LOCKED(base);
	event_debug_assert_is_setup_(ev);

	event_debug(("event_remove_timer_nolock: event: %p", ev));

	/* If it's not pending on a timeout, we don't need to do anything. */
	if (ev->ev_flags & EVLIST_TIMEOUT) {
		event_queue_remove_timeout(base, ev, 1);
		evutil_timerclear(&ev->ev_.ev_io.ev_timeout);
	}

	return (0);
}

int
event_remove_timer(struct event *ev)
{
	int res;

	if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return -1;
	}

	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);

	res = event_remove_timer_nolock_(ev);

	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

	return (res);
}

/* Implementation function to add an event.  Works just like event_add,
 * except: 1) it requires that we have the lock.  2) if tv_is_absolute is set,
 * we treat tv as an absolute time, not as an interval to add to the current
 * time */
int
event_add_nolock_(struct event *ev, const struct timeval *tv,
    int tv_is_absolute)
{
	struct event_base *base = ev->ev_base;
	int res = 0;
	int notify = 0;

	EVENT_BASE_ASSERT_LOCKED(base);
	event_debug_assert_is_setup_(ev);

	event_debug((
		 "event_add: event: %p (fd "EV_SOCK_FMT"), %s%s%s%scall %p",
		 ev,
		 EV_SOCK_ARG(ev->ev_fd),
		 ev->ev_events & EV_READ ? "EV_READ " : " ",
		 ev->ev_events & EV_WRITE ? "EV_WRITE " : " ",
		 ev->ev_events & EV_CLOSED ? "EV_CLOSED " : " ",
		 tv ? "EV_TIMEOUT " : " ",
		 ev->ev_callback));

	EVUTIL_ASSERT(!(ev->ev_flags & ~EVLIST_ALL));

	if (ev->ev_flags & EVLIST_FINALIZING) {
		/* XXXX debug */
		return (-1);
	}

	/*
	 * prepare for timeout insertion further below, if we get a
	 * failure on any step, we should not change any state.
	 */
	if (tv != NULL && !ev->ev_timeout_obj) {
		if (event_queue_alloc_timeout(ev) < 0) {
			return (-1); /* ENOMEM */
		}
	}

	/* If the main thread is currently executing a signal event's
	 * callback, and we are not the main thread, then we want to wait
	 * until the callback is done before we mess with the event, or else
	 * we can race on ev_ncalls and ev_pncalls below. */
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (base->current_event == event_to_event_callback(ev) &&
	    (ev->ev_events & EV_SIGNAL)
	    && !EVBASE_IN_THREAD(base)) {
		++base->current_event_waiters;
		EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
	}
#endif

	if ((ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED|EV_SIGNAL)) &&
	    !(ev->ev_flags & (EVLIST_INSERTED|EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))) {
		if (ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED))
			res = evmap_io_add_(base, ev->ev_fd, ev);
		else if (ev->ev_events & EV_SIGNAL)
			res = evmap_signal_add_(base, (int)ev->ev_fd, ev);
		if (res != -1)
			event_queue_insert_inserted(base, ev);
		if (res == 1) {
			/* evmap says we need to notify the main thread. */
			notify = 1;
			res = 0;
		}
	}

	/*
	 * we should change the timeout state only if the previous event
	 * addition succeeded.
	 */
	if (res != -1 && tv != NULL) {
		struct timeval now;
		timeout_t timeout_pre, timeout_post;

		/*
		 * for persistent timeout events, we remember the
		 * timeout value and re-add the event.
		 *
		 * If tv_is_absolute, this was already set.
		 */
		if (ev->ev_closure == EV_CLOSURE_EVENT_PERSIST && !tv_is_absolute)
			ev->ev_io_timeout = *tv;

		if (ev->ev_flags & EVLIST_TIMEOUT) {
			event_queue_remove_timeout(base, ev, 0);
		}

		/* Check if it is active due to a timeout.  Rescheduling
		 * this timeout before the callback can be executed
		 * removes it from the active list. */
		if ((ev->ev_flags & EVLIST_ACTIVE) &&
		    (ev->ev_res & EV_TIMEOUT)) {
			if (ev->ev_events & EV_SIGNAL) {
				/* See if we are just active executing
				 * this event in a loop
				 */
				if (ev->ev_ncalls && ev->ev_pncalls) {
					/* Abort loop */
					*ev->ev_pncalls = 0;
				}
			}

			event_queue_remove_active(base, event_to_event_callback(ev));
		}

		gettime(base, &now);

		if (tv_is_absolute) {
			ev->ev_timeout = *tv;
		} else {
			evutil_timeradd(&now, tv, &ev->ev_timeout);
		}

		event_debug((
			 "event_add: event %p, timeout in %d seconds %d useconds, call %p",
			 ev, (int)tv->tv_sec, (int)tv->tv_usec, ev->ev_callback));

		timeout_pre = timeouts_timeout(base->timeout_queue);
		event_queue_insert_timeout(base, ev);
		timeout_post = timeouts_timeout(base->timeout_queue);

		if (timeout_post < timeout_pre) {
			/* This event is scheduled earlier than the previous
			 * event. */
			notify = 1;
		}
	}

	/* if we are not in the right thread, we need to wake up the loop */
	if (res != -1 && notify && EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);

	event_debug_note_add_(ev);

	return (res);
}

static int
event_del_(struct event *ev, int blocking)
{
	int res;

	if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return -1;
	}

	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);

	res = event_del_nolock_(ev, blocking);

	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);

	return (res);
}

int
event_del(struct event *ev)
{
	return event_del_(ev, EVENT_DEL_AUTOBLOCK);
}

int
event_del_block(struct event *ev)
{
	return event_del_(ev, EVENT_DEL_BLOCK);
}

int
event_del_noblock(struct event *ev)
{
	return event_del_(ev, EVENT_DEL_NOBLOCK);
}

/** Helper for event_del: always called with th_base_lock held.
 *
 * "blocking" must be one of the EVENT_DEL_{BLOCK, NOBLOCK, AUTOBLOCK,
 * EVEN_IF_FINALIZING} values. See those for more information.
 */
int
event_del_nolock_(struct event *ev, int blocking)
{
	struct event_base *base;
	int res = 0, notify = 0;

	event_debug(("event_del: %p (fd "EV_SOCK_FMT"), callback %p",
		ev, EV_SOCK_ARG(ev->ev_fd), ev->ev_callback));

	/* An event without a base has not been added */
	if (ev->ev_base == NULL)
		return (-1);

	EVENT_BASE_ASSERT_LOCKED(ev->ev_base);

	if (blocking != EVENT_DEL_EVEN_IF_FINALIZING) {
		if (ev->ev_flags & EVLIST_FINALIZING) {
			/* XXXX Debug */
			return 0;
		}
	}

	/* If the main thread is currently executing this event's callback,
	 * and we are not the main thread, then we want to wait until the
	 * callback is done before we start removing the event.  That way,
	 * when this function returns, it will be safe to free the
	 * user-supplied argument. */
	base = ev->ev_base;
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (blocking != EVENT_DEL_NOBLOCK &&
	    base->current_event == event_to_event_callback(ev) &&
	    !EVBASE_IN_THREAD(base) &&
	    (blocking == EVENT_DEL_BLOCK || !(ev->ev_events & EV_FINALIZE))) {
		++base->current_event_waiters;
		EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
	}
#endif

	EVUTIL_ASSERT(!(ev->ev_flags & ~EVLIST_ALL));

	/* See if we are just active executing this event in a loop */
	if (ev->ev_events & EV_SIGNAL) {
		if (ev->ev_ncalls && ev->ev_pncalls) {
			/* Abort loop */
			*ev->ev_pncalls = 0;
		}
	}

	if (ev->ev_flags & EVLIST_TIMEOUT) {
		/* NOTE: We never need to notify the main thread because of a
		 * deleted timeout event: all that could happen if we don't is
		 * that the dispatch loop might wake up too early.  But the
		 * point of notifying the main thread _is_ to wake up the
		 * dispatch loop early anyway, so we wouldn't gain anything by
		 * doing it.
		 */
		event_queue_remove_timeout(base, ev, 1);
	}

	if (ev->ev_flags & EVLIST_ACTIVE)
		event_queue_remove_active(base, event_to_event_callback(ev));
	else if (ev->ev_flags & EVLIST_ACTIVE_LATER)
		event_queue_remove_active_later(base, event_to_event_callback(ev));

	if (ev->ev_flags & EVLIST_INSERTED) {
		event_queue_remove_inserted(base, ev);
		if (ev->ev_events & (EV_READ|EV_WRITE|EV_CLOSED))
			res = evmap_io_del_(base, ev->ev_fd, ev);
		else
			res = evmap_signal_del_(base, (int)ev->ev_fd, ev);
		if (res == 1) {
			/* evmap says we need to notify the main thread. */
			notify = 1;
			res = 0;
		}
	}

	/* if we are not in the right thread, we need to wake up the loop */
	if (res != -1 && notify && EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);

	event_debug_note_del_(ev);

	return (res);
}

void
event_active(struct event *ev, int res, short ncalls)
{
	if (EVUTIL_FAILURE_CHECK(!ev->ev_base)) {
		event_warnx("%s: event has no event_base set.", __func__);
		return;
	}

	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);

	event_debug_assert_is_setup_(ev);

	event_active_nolock_(ev, res, ncalls);

	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);
}


void
event_active_nolock_(struct event *ev, int res, short ncalls)
{
	struct event_base *base;

	event_debug(("event_active: %p (fd "EV_SOCK_FMT"), res %d, callback %p",
		ev, EV_SOCK_ARG(ev->ev_fd), (int)res, ev->ev_callback));

	base = ev->ev_base;
	EVENT_BASE_ASSERT_LOCKED(base);

	if (ev->ev_flags & EVLIST_FINALIZING) {
		/* XXXX debug */
		return;
	}

	switch ((ev->ev_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))) {
	default:
	case EVLIST_ACTIVE|EVLIST_ACTIVE_LATER:
		EVUTIL_ASSERT(0);
		break;
	case EVLIST_ACTIVE:
		/* We get different kinds of events, add them together */
		ev->ev_res |= res;
		return;
	case EVLIST_ACTIVE_LATER:
		ev->ev_res |= res;
		break;
	case 0:
		ev->ev_res = res;
		break;
	}

	if (ev->ev_pri < base->event_running_priority)
		base->event_continue = 1;

	if (ev->ev_events & EV_SIGNAL) {
#ifndef EVENT__DISABLE_THREAD_SUPPORT
		if (base->current_event == event_to_event_callback(ev) &&
		    !EVBASE_IN_THREAD(base)) {
			++base->current_event_waiters;
			EVTHREAD_COND_WAIT(base->current_event_cond, base->th_base_lock);
		}
#endif
		ev->ev_ncalls = ncalls;
		ev->ev_pncalls = NULL;
	}

	event_callback_activate_nolock_(base, event_to_event_callback(ev));
}

void
event_active_later_(struct event *ev, int res)
{
	EVBASE_ACQUIRE_LOCK(ev->ev_base, th_base_lock);
	event_active_later_nolock_(ev, res);
	EVBASE_RELEASE_LOCK(ev->ev_base, th_base_lock);
}

void
event_active_later_nolock_(struct event *ev, int res)
{
	struct event_base *base = ev->ev_base;
	EVENT_BASE_ASSERT_LOCKED(base);

	if (ev->ev_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER)) {
		/* We get different kinds of events, add them together */
		ev->ev_res |= res;
		return;
	}

	ev->ev_res = res;

	event_callback_activate_later_nolock_(base, event_to_event_callback(ev));
}

int
event_callback_activate_(struct event_base *base,
    struct event_callback *evcb)
{
	int r;
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	r = event_callback_activate_nolock_(base, evcb);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

int
event_callback_activate_nolock_(struct event_base *base,
    struct event_callback *evcb)
{
	int r = 1;

	if (evcb->evcb_flags & EVLIST_FINALIZING)
		return 0;

	switch (evcb->evcb_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER)) {
	default:
		EVUTIL_ASSERT(0);
	case EVLIST_ACTIVE_LATER:
		event_queue_remove_active_later(base, evcb);
		r = 0;
		break;
	case EVLIST_ACTIVE:
		return 0;
	case 0:
		break;
	}

	event_queue_insert_active(base, evcb);

	if (EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);

	return r;
}

int
event_callback_activate_later_nolock_(struct event_base *base,
    struct event_callback *evcb)
{
	if (evcb->evcb_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))
		return 0;

	event_queue_insert_active_later(base, evcb);
	if (EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);
	return 1;
}

void
event_callback_init_(struct event_base *base,
    struct event_callback *cb)
{
	memset(cb, 0, sizeof(*cb));
	cb->evcb_pri = base->nactivequeues - 1;
}

int
event_callback_cancel_(struct event_base *base,
    struct event_callback *evcb)
{
	int r;
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	r = event_callback_cancel_nolock_(base, evcb, 0);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

int
event_callback_cancel_nolock_(struct event_base *base,
    struct event_callback *evcb, int even_if_finalizing)
{
	if ((evcb->evcb_flags & EVLIST_FINALIZING) && !even_if_finalizing)
		return 0;

	if (evcb->evcb_flags & EVLIST_INIT)
		return event_del_nolock_(event_callback_to_event(evcb),
		    even_if_finalizing ? EVENT_DEL_EVEN_IF_FINALIZING : EVENT_DEL_AUTOBLOCK);

	switch ((evcb->evcb_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER))) {
	default:
	case EVLIST_ACTIVE|EVLIST_ACTIVE_LATER:
		EVUTIL_ASSERT(0);
		break;
	case EVLIST_ACTIVE:
		/* We get different kinds of events, add them together */
		event_queue_remove_active(base, evcb);
		return 0;
	case EVLIST_ACTIVE_LATER:
		event_queue_remove_active_later(base, evcb);
		break;
	case 0:
		break;
	}

	return 0;
}

void
event_deferred_cb_init_(struct event_callback *cb, ev_uint8_t priority, deferred_cb_fn fn, void *arg)
{
	memset(cb, 0, sizeof(*cb));
	cb->evcb_cb_union.evcb_selfcb = fn;
	cb->evcb_arg = arg;
	cb->evcb_pri = priority;
	cb->evcb_closure = EV_CLOSURE_CB_SELF;
}

void
event_deferred_cb_set_priority_(struct event_callback *cb, ev_uint8_t priority)
{
	cb->evcb_pri = priority;
}

void
event_deferred_cb_cancel_(struct event_base *base, struct event_callback *cb)
{
	if (!base)
		base = current_base;
	event_callback_cancel_(base, cb);
}

#define MAX_DEFERREDS_QUEUED 32
int
event_deferred_cb_schedule_(struct event_base *base, struct event_callback *cb)
{
	int r = 1;
	if (!base)
		base = current_base;
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	if (base->n_deferreds_queued > MAX_DEFERREDS_QUEUED) {
		r = event_callback_activate_later_nolock_(base, cb);
	} else {
		r = event_callback_activate_nolock_(base, cb);
		if (r) {
			++base->n_deferreds_queued;
		}
	}
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

static int
timeout_next(struct event_base *base, struct timeval **tv_p)
{
	/* Caller must hold th_base_lock */
	struct timeval now;
	struct timeval *tv = *tv_p;
	int res = 0;
	timeout_t how_long_to_wait, now64;
	struct event_timeouts *timeouts = base->timeout_queue;

	if (!timeouts_pending(timeouts) && !timeouts_expired(timeouts)) {
		/* We have no timeouts */
		*tv_p = NULL;
		goto out;
	}

	if (gettime(base, &now) == -1) {
		res = -1;
		goto out;
	}
	now64 = TV_TO_TIMEOUT(&now);
	timeouts_update(timeouts, now64);
	how_long_to_wait = timeouts_timeout(base->timeout_queue);

	TIMEOUT_TO_TV(tv, how_long_to_wait);

out:
	return (res);
}

/* Activate every event whose timeout has elapsed. */
static void
timeout_process(struct event_base *base)
{
	/* Caller must hold lock. */
	struct timeval now;
	struct event_timeout *timeout;
	struct event_timeouts *timeouts = base->timeout_queue;
	timeout_t now64;

	if (!timeouts_pending(timeouts) && !timeouts_expired(timeouts)) {
		return;
	}

	gettime(base, &now);
	now64 = TV_TO_TIMEOUT(&now);
	timeouts_update(timeouts, now64);

	while ((timeout = timeouts_get(timeouts))) {
		/* Find the associated event */
		struct event *ev = timeout->callback.arg;
		EVUTIL_ASSERT(ev);

		/* delete this event from the I/O queues */
		event_del_nolock_(ev, EVENT_DEL_NOBLOCK);

		event_debug(("timeout_process: event: %p, call %p",
			 ev, ev->ev_callback));
		event_active_nolock_(ev, EV_TIMEOUT, 1);
	}
}

#if (EVLIST_INTERNAL >> 4) != 1
#error "Mismatch for value of EVLIST_INTERNAL"
#endif

#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif

#define MAX_EVENT_COUNT(var, v) var = MAX(var, v)

/* These are a fancy way to spell
     if (flags & EVLIST_INTERNAL)
         base->event_count--/++;
*/
#define DECR_EVENT_COUNT(base,flags) \
	((base)->event_count -= (~((flags) >> 4) & 1))
#define INCR_EVENT_COUNT(base,flags) do {					\
	((base)->event_count += (~((flags) >> 4) & 1));				\
	MAX_EVENT_COUNT((base)->event_count_max, (base)->event_count);		\
} while (0)

static void
event_queue_remove_inserted(struct event_base *base, struct event *ev)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (EVUTIL_FAILURE_CHECK(!(ev->ev_flags & EVLIST_INSERTED))) {
		event_errx(1, "%s: %p(fd "EV_SOCK_FMT") not on queue %x", __func__,
		    ev, EV_SOCK_ARG(ev->ev_fd), EVLIST_INSERTED);
		return;
	}
	DECR_EVENT_COUNT(base, ev->ev_flags);
	ev->ev_flags &= ~EVLIST_INSERTED;
}
static void
event_queue_remove_active(struct event_base *base, struct event_callback *evcb)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (EVUTIL_FAILURE_CHECK(!(evcb->evcb_flags & EVLIST_ACTIVE))) {
		event_errx(1, "%s: %p not on queue %x", __func__,
			   evcb, EVLIST_ACTIVE);
		return;
	}
	DECR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags &= ~EVLIST_ACTIVE;
	base->event_count_active--;

	TAILQ_REMOVE(&base->activequeues[evcb->evcb_pri],
	    evcb, evcb_active_next);
}
static void
event_queue_remove_active_later(struct event_base *base, struct event_callback *evcb)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (EVUTIL_FAILURE_CHECK(!(evcb->evcb_flags & EVLIST_ACTIVE_LATER))) {
		event_errx(1, "%s: %p not on queue %x", __func__,
			   evcb, EVLIST_ACTIVE_LATER);
		return;
	}
	DECR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags &= ~EVLIST_ACTIVE_LATER;
	base->event_count_active--;

	TAILQ_REMOVE(&base->active_later_queue, evcb, evcb_active_next);
}
static int
event_queue_alloc_timeout(struct event *ev)
{
	ev->ev_timeout_obj = mm_malloc(sizeof(struct event_timeout));
	if (! ev->ev_timeout_obj)
		return -1;
	timeout_init(ev->ev_timeout_obj, TIMEOUT_ABS);
	ev->ev_timeout_obj->callback.arg = ev;
	return 0;
}

static void
event_queue_remove_timeout(struct event_base *base, struct event *ev,
    int should_free)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (EVUTIL_FAILURE_CHECK(!(ev->ev_flags & EVLIST_TIMEOUT))) {
		event_errx(1, "%s: %p(fd "EV_SOCK_FMT") not on queue %x", __func__,
		    ev, EV_SOCK_ARG(ev->ev_fd), EVLIST_TIMEOUT);
		return;
	}
	DECR_EVENT_COUNT(base, ev->ev_flags);
	ev->ev_flags &= ~EVLIST_TIMEOUT;

	EVUTIL_ASSERT(ev->ev_timeout_obj);
	EVUTIL_ASSERT(ev->ev_timeout_obj->callback.arg == ev);
	timeout_del(ev->ev_timeout_obj);
	if (should_free) {
		mm_free(ev->ev_timeout_obj);
		ev->ev_timeout_obj = NULL;
	}
}

static void
event_queue_insert_inserted(struct event_base *base, struct event *ev)
{
	EVENT_BASE_ASSERT_LOCKED(base);

	if (EVUTIL_FAILURE_CHECK(ev->ev_flags & EVLIST_INSERTED)) {
		event_errx(1, "%s: %p(fd "EV_SOCK_FMT") already inserted", __func__,
		    ev, EV_SOCK_ARG(ev->ev_fd));
		return;
	}

	INCR_EVENT_COUNT(base, ev->ev_flags);

	ev->ev_flags |= EVLIST_INSERTED;
}

static void
event_queue_insert_active(struct event_base *base, struct event_callback *evcb)
{
	EVENT_BASE_ASSERT_LOCKED(base);

	if (evcb->evcb_flags & EVLIST_ACTIVE) {
		/* Double insertion is possible for active events */
		return;
	}

	INCR_EVENT_COUNT(base, evcb->evcb_flags);

	evcb->evcb_flags |= EVLIST_ACTIVE;

	base->event_count_active++;
	MAX_EVENT_COUNT(base->event_count_active_max, base->event_count_active);
	EVUTIL_ASSERT(evcb->evcb_pri < base->nactivequeues);
	TAILQ_INSERT_TAIL(&base->activequeues[evcb->evcb_pri],
	    evcb, evcb_active_next);
}

static void
event_queue_insert_active_later(struct event_base *base, struct event_callback *evcb)
{
	EVENT_BASE_ASSERT_LOCKED(base);
	if (evcb->evcb_flags & (EVLIST_ACTIVE_LATER|EVLIST_ACTIVE)) {
		/* Double insertion is possible */
		return;
	}

	INCR_EVENT_COUNT(base, evcb->evcb_flags);
	evcb->evcb_flags |= EVLIST_ACTIVE_LATER;
	base->event_count_active++;
	MAX_EVENT_COUNT(base->event_count_active_max, base->event_count_active);
	EVUTIL_ASSERT(evcb->evcb_pri < base->nactivequeues);
	TAILQ_INSERT_TAIL(&base->active_later_queue, evcb, evcb_active_next);
}

static void
event_queue_insert_timeout(struct event_base *base, struct event *ev)
{
	struct event_timeout *timeout;
	timeout_t expiry;

	EVENT_BASE_ASSERT_LOCKED(base);

	if (EVUTIL_FAILURE_CHECK(ev->ev_flags & EVLIST_TIMEOUT)) {
		event_errx(1, "%s: %p(fd "EV_SOCK_FMT") already on timeout", __func__,
		    ev, EV_SOCK_ARG(ev->ev_fd));
		return;
	}

	INCR_EVENT_COUNT(base, ev->ev_flags);

	ev->ev_flags |= EVLIST_TIMEOUT;

	timeout = ev->ev_timeout_obj;
	EVUTIL_ASSERT(timeout);
	expiry = TV_TO_TIMEOUT(&ev->ev_timeout);
	timeouts_add(ev->ev_base->timeout_queue, timeout, expiry);
}

static void
event_queue_make_later_events_active(struct event_base *base)
{
	struct event_callback *evcb;
	EVENT_BASE_ASSERT_LOCKED(base);

	while ((evcb = TAILQ_FIRST(&base->active_later_queue))) {
		TAILQ_REMOVE(&base->active_later_queue, evcb, evcb_active_next);
		evcb->evcb_flags = (evcb->evcb_flags & ~EVLIST_ACTIVE_LATER) | EVLIST_ACTIVE;
		EVUTIL_ASSERT(evcb->evcb_pri < base->nactivequeues);
		TAILQ_INSERT_TAIL(&base->activequeues[evcb->evcb_pri], evcb, evcb_active_next);
		base->n_deferreds_queued += (evcb->evcb_closure == EV_CLOSURE_CB_SELF);
	}
}

/* Functions for debugging */

const char *
event_get_version(void)
{
	return (EVENT__VERSION);
}

ev_uint32_t
event_get_version_number(void)
{
	return (EVENT__NUMERIC_VERSION);
}

/*
 * No thread-safe interface needed - the information should be the same
 * for all threads.
 */

const char *
event_get_method(void)
{
	return (current_base->evsel->name);
}

#ifndef EVENT__DISABLE_MM_REPLACEMENT
static void *(*mm_malloc_fn_)(size_t sz) = NULL;
static void *(*mm_realloc_fn_)(void *p, size_t sz) = NULL;
static void (*mm_free_fn_)(void *p) = NULL;

void *
event_mm_malloc_(size_t sz)
{
	if (sz == 0)
		return NULL;

	if (mm_malloc_fn_)
		return mm_malloc_fn_(sz);
	else
		return malloc(sz);
}

void *
event_mm_calloc_(size_t count, size_t size)
{
	if (count == 0 || size == 0)
		return NULL;

	if (mm_malloc_fn_) {
		size_t sz = count * size;
		void *p = NULL;
		if (count > EV_SIZE_MAX / size)
			goto error;
		p = mm_malloc_fn_(sz);
		if (p)
			return memset(p, 0, sz);
	} else {
		void *p = calloc(count, size);
#ifdef _WIN32
		/* Windows calloc doesn't reliably set ENOMEM */
		if (p == NULL)
			goto error;
#endif
		return p;
	}

error:
	errno = ENOMEM;
	return NULL;
}

char *
event_mm_strdup_(const char *str)
{
	if (!str) {
		errno = EINVAL;
		return NULL;
	}

	if (mm_malloc_fn_) {
		size_t ln = strlen(str);
		void *p = NULL;
		if (ln == EV_SIZE_MAX)
			goto error;
		p = mm_malloc_fn_(ln+1);
		if (p)
			return memcpy(p, str, ln+1);
	} else
#ifdef _WIN32
		return _strdup(str);
#else
		return strdup(str);
#endif

error:
	errno = ENOMEM;
	return NULL;
}

void *
event_mm_realloc_(void *ptr, size_t sz)
{
	if (mm_realloc_fn_)
		return mm_realloc_fn_(ptr, sz);
	else
		return realloc(ptr, sz);
}

void
event_mm_free_(void *ptr)
{
	if (mm_free_fn_)
		mm_free_fn_(ptr);
	else
		free(ptr);
}

void
event_set_mem_functions(void *(*malloc_fn)(size_t sz),
			void *(*realloc_fn)(void *ptr, size_t sz),
			void (*free_fn)(void *ptr))
{
	mm_malloc_fn_ = malloc_fn;
	mm_realloc_fn_ = realloc_fn;
	mm_free_fn_ = free_fn;
}
#endif

#ifdef EVENT__HAVE_EVENTFD
static void
evthread_notify_drain_eventfd(evutil_socket_t fd, short what, void *arg)
{
	ev_uint64_t msg;
	ev_ssize_t r;
	struct event_base *base = arg;

	r = read(fd, (void*) &msg, sizeof(msg));
	if (r<0 && errno != EAGAIN) {
		event_sock_warn(fd, "Error reading from eventfd");
	}
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	base->is_notify_pending = 0;
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}
#endif

static void
evthread_notify_drain_default(evutil_socket_t fd, short what, void *arg)
{
	unsigned char buf[1024];
	struct event_base *base = arg;
#ifdef _WIN32
	while (recv(fd, (char*)buf, sizeof(buf), 0) > 0)
		;
#else
	while (read(fd, (char*)buf, sizeof(buf)) > 0)
		;
#endif

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	base->is_notify_pending = 0;
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

int
evthread_make_base_notifiable(struct event_base *base)
{
	int r;
	if (!base)
		return -1;

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	r = evthread_make_base_notifiable_nolock_(base);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}

static int
evthread_make_base_notifiable_nolock_(struct event_base *base)
{
	void (*cb)(evutil_socket_t, short, void *);
	int (*notify)(struct event_base *);

	if (base->th_notify_fn != NULL) {
		/* The base is already notifiable: we're doing fine. */
		return 0;
	}

#if defined(EVENT__HAVE_WORKING_KQUEUE)
	if (base->evsel == &kqops && event_kq_add_notify_event_(base) == 0) {
		base->th_notify_fn = event_kq_notify_base_;
		/* No need to add an event here; the backend can wake
		 * itself up just fine. */
		return 0;
	}
#endif

#ifdef EVENT__HAVE_EVENTFD
	base->th_notify_fd[0] = evutil_eventfd_(0,
	    EVUTIL_EFD_CLOEXEC|EVUTIL_EFD_NONBLOCK);
	if (base->th_notify_fd[0] >= 0) {
		base->th_notify_fd[1] = -1;
		notify = evthread_notify_base_eventfd;
		cb = evthread_notify_drain_eventfd;
	} else
#endif
	if (evutil_make_internal_pipe_(base->th_notify_fd) == 0) {
		notify = evthread_notify_base_default;
		cb = evthread_notify_drain_default;
	} else {
		return -1;
	}

	base->th_notify_fn = notify;

	/* prepare an event that we can use for wakeup */
	event_assign(&base->th_notify, base, base->th_notify_fd[0],
				 EV_READ|EV_PERSIST, cb, base);

	/* we need to mark this as internal event */
	base->th_notify.ev_flags |= EVLIST_INTERNAL;
	event_priority_set(&base->th_notify, 0);

	return event_add_nolock_(&base->th_notify, NULL, 0);
}

struct timeouts_foreach_cb_arg {
	struct event_base *base;
	event_base_foreach_event_cb cb;
	void *arg;
};

static int
event_base_foreach_event_timeout_cb(struct event_timeout *timeout, void *arg)
{
	struct timeouts_foreach_cb_arg *cb_arg = arg;
	struct event *ev = timeout->callback.arg;
	
	if (ev->ev_flags & EVLIST_INSERTED) {
		/* we already processed this one */
		return 0;
	}

	return cb_arg->cb(cb_arg->base, timeout->callback.arg, cb_arg->arg);
}

int
event_base_foreach_event_nolock_(struct event_base *base,
    event_base_foreach_event_cb fn, void *arg)
{
	int r, i;
	struct event *ev;
	struct timeouts_foreach_cb_arg timeouts_arg = { base, fn, arg };

	/* Start out with all the EVLIST_INSERTED events. */
	if ((r = evmap_foreach_event_(base, fn, arg)))
		return r;

	if ((r = timeouts_foreach(base->timeout_queue, event_base_foreach_event_timeout_cb, &timeouts_arg)))
		return r;

	/* Finally, we deal wit all the active events that we haven't touched
	 * yet. */
	for (i = 0; i < base->nactivequeues; ++i) {
		struct event_callback *evcb;
		TAILQ_FOREACH(evcb, &base->activequeues[i], evcb_active_next) {
			if ((evcb->evcb_flags & (EVLIST_INIT|EVLIST_INSERTED|EVLIST_TIMEOUT)) != EVLIST_INIT) {
				/* This isn't an event (evlist_init clear), or
				 * we already processed it. (inserted or
				 * timeout set */
				continue;
			}
			ev = event_callback_to_event(evcb);
			if ((r = fn(base, ev, arg)))
				return r;
		}
	}

	return 0;
}

/* Helper for event_base_dump_events: called on each event in the event base;
 * dumps only the inserted events. */
static int
dump_inserted_event_fn(const struct event_base *base, const struct event *e, void *arg)
{
	FILE *output = arg;
	const char *gloss = (e->ev_events & EV_SIGNAL) ?
	    "sig" : "fd ";

	if (! (e->ev_flags & (EVLIST_INSERTED|EVLIST_TIMEOUT)))
		return 0;

	fprintf(output, "  %p [%s "EV_SOCK_FMT"]%s%s%s%s%s%s",
	    (void*)e, gloss, EV_SOCK_ARG(e->ev_fd),
	    (e->ev_events&EV_READ)?" Read":"",
	    (e->ev_events&EV_WRITE)?" Write":"",
	    (e->ev_events&EV_CLOSED)?" EOF":"",
	    (e->ev_events&EV_SIGNAL)?" Signal":"",
	    (e->ev_events&EV_PERSIST)?" Persist":"",
	    (e->ev_flags&EVLIST_INTERNAL)?" Internal":"");
	if (e->ev_flags & EVLIST_TIMEOUT) {
		struct timeval tv;
		tv.tv_sec = e->ev_timeout.tv_sec;
		tv.tv_usec = e->ev_timeout.tv_usec;
		evutil_timeradd(&tv, &base->tv_clock_diff, &tv);
		fprintf(output, " Timeout=%ld.%06d",
		    (long)tv.tv_sec, (int)(tv.tv_usec));
	}
	fputc('\n', output);

	return 0;
}

/* Helper for event_base_dump_events: called on each event in the event base;
 * dumps only the active events. */
static int
dump_active_event_fn(const struct event_base *base, const struct event *e, void *arg)
{
	FILE *output = arg;
	const char *gloss = (e->ev_events & EV_SIGNAL) ?
	    "sig" : "fd ";

	if (! (e->ev_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER)))
		return 0;

	fprintf(output, "  %p [%s "EV_SOCK_FMT", priority=%d]%s%s%s%s%s active%s%s\n",
	    (void*)e, gloss, EV_SOCK_ARG(e->ev_fd), e->ev_pri,
	    (e->ev_res&EV_READ)?" Read":"",
	    (e->ev_res&EV_WRITE)?" Write":"",
	    (e->ev_res&EV_CLOSED)?" EOF":"",
	    (e->ev_res&EV_SIGNAL)?" Signal":"",
	    (e->ev_res&EV_TIMEOUT)?" Timeout":"",
	    (e->ev_flags&EVLIST_INTERNAL)?" [Internal]":"",
	    (e->ev_flags&EVLIST_ACTIVE_LATER)?" [NextTime]":"");

	return 0;
}

int
event_base_foreach_event(struct event_base *base,
    event_base_foreach_event_cb fn, void *arg)
{
	int r;
	if ((!fn) || (!base)) {
		return -1;
	}
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	r = event_base_foreach_event_nolock_(base, fn, arg);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
	return r;
}


void
event_base_dump_events(struct event_base *base, FILE *output)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	fprintf(output, "Inserted events:\n");
	event_base_foreach_event_nolock_(base, dump_inserted_event_fn, output);

	fprintf(output, "Active events:\n");
	event_base_foreach_event_nolock_(base, dump_active_event_fn, output);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

void
event_base_active_by_fd(struct event_base *base, evutil_socket_t fd, short events)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	evmap_io_active_(base, fd, events & (EV_READ|EV_WRITE|EV_CLOSED));
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

void
event_base_active_by_signal(struct event_base *base, int sig)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	evmap_signal_active_(base, sig, 1);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}


void
event_base_add_virtual_(struct event_base *base)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	base->virtual_event_count++;
	MAX_EVENT_COUNT(base->virtual_event_count_max, base->virtual_event_count);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

void
event_base_del_virtual_(struct event_base *base)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	EVUTIL_ASSERT(base->virtual_event_count > 0);
	base->virtual_event_count--;
	if (base->virtual_event_count == 0 && EVBASE_NEED_NOTIFY(base))
		evthread_notify_base(base);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

static void
event_free_debug_globals_locks(void)
{
#ifndef EVENT__DISABLE_THREAD_SUPPORT
#ifndef EVENT__DISABLE_DEBUG_MODE
	if (event_debug_map_lock_ != NULL) {
		EVTHREAD_FREE_LOCK(event_debug_map_lock_, 0);
		event_debug_map_lock_ = NULL;
		evthreadimpl_disable_lock_debugging_();
	}
#endif /* EVENT__DISABLE_DEBUG_MODE */
#endif /* EVENT__DISABLE_THREAD_SUPPORT */
	return;
}

static void
event_free_debug_globals(void)
{
	event_free_debug_globals_locks();
}

static void
event_free_evsig_globals(void)
{
	evsig_free_globals_();
}

static void
event_free_evutil_globals(void)
{
	evutil_free_globals_();
}

static void
event_free_globals(void)
{
	event_free_debug_globals();
	event_free_evsig_globals();
	event_free_evutil_globals();
}

void
libevent_global_shutdown(void)
{
	event_disable_debug_mode();
	event_free_globals();
}

#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
event_global_setup_locks_(const int enable_locks)
{
#ifndef EVENT__DISABLE_DEBUG_MODE
	EVTHREAD_SETUP_GLOBAL_LOCK(event_debug_map_lock_, 0);
#endif
	if (evsig_global_setup_locks_(enable_locks) < 0)
		return -1;
	if (evutil_global_setup_locks_(enable_locks) < 0)
		return -1;
	if (evutil_secure_rng_global_setup_locks_(enable_locks) < 0)
		return -1;
	return 0;
}
#endif

void
event_base_assert_ok_(struct event_base *base)
{
	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
	event_base_assert_ok_nolock_(base);
	EVBASE_RELEASE_LOCK(base, th_base_lock);
}

void
event_base_assert_ok_nolock_(struct event_base *base)
{
	int i;
	int count;

	/* First do checks on the per-fd and per-signal lists */
	evmap_check_integrity_(base);

	EVUTIL_ASSERT(timeouts_check(base->timeout_queue, NULL));

	/* Check the active queues. */
	count = 0;
	for (i = 0; i < base->nactivequeues; ++i) {
		struct event_callback *evcb;
		EVUTIL_ASSERT_TAILQ_OK(&base->activequeues[i], event_callback, evcb_active_next);
		TAILQ_FOREACH(evcb, &base->activequeues[i], evcb_active_next) {
			EVUTIL_ASSERT((evcb->evcb_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER)) == EVLIST_ACTIVE);
			EVUTIL_ASSERT(evcb->evcb_pri == i);
			++count;
		}
	}

	{
		struct event_callback *evcb;
		TAILQ_FOREACH(evcb, &base->active_later_queue, evcb_active_next) {
			EVUTIL_ASSERT((evcb->evcb_flags & (EVLIST_ACTIVE|EVLIST_ACTIVE_LATER)) == EVLIST_ACTIVE_LATER);
			++count;
		}
	}
	EVUTIL_ASSERT(count == base->event_count_active);
}
