#ifndef ATOMIC_INTERNAL_H_INCLUDED_
#define ATOMIC_INTERNAL_H_INCLUDED_

/*
 * Defines atomic macros/functions for intptr_t sized variables.
 * _load, _store, _exchange, _compare_exchange_strong are included.
 * Use atomic_init_ptr to declare variables.
 *
 * Microsoft explicitly excludes stdatomic.h from the list of supported
 * C11 features on Windows. Implement equivalent functions using the
 * Interlocked API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <stdatomic.h>
#endif

#include "event2/event-config.h"

#if defined(_MSC_VER)
#if EVENT__SIZEOF_UINTPTR_T == 8
#define _Interlocked(f) _Interlocked # f # 64
#elif EVENT__SIZEOF_UINTPTR_T == 4
#define _Interlocked(f) _Interlocked # f
#else
#error "invalid value for EVENT__SIZEOF_UINTPTR_T"
#endif

static inline bool atomic_compare_exchange_strong(intptr_t volatile *p, intptr_t *expected, intptr_t desired)
{
	intptr_t old = _Interlocked(CompareExchange)(p, desired, *expected);
	if (old == *expected)
		return true;

	*expected = old;
	return false;
}

static inline void *atomic_load(intptr_t volatile *p)
{
	intptr_t x;
	intptr_t comparand = *p;
	do {
		x = comparand;
		comparand = _Interlocked(CompareExchange)(p, x, comparand);
	} while (comparand != x);
	return (void *) x;
}

static inline intptr_t atomic_exchange(intptr_t volatile *p, intptr_t v)
{
	return _Interlocked(Exchange)(p, v);
}

static inline void atomic_store(intptr_t volatile *p, intptr_t v)
{
	atomic_exchange(p, v);
}
#endif

#if defined(_MSC_VER)
#define atomic_init_ptr(t,n,v) t volatile *n = (v)
#else
#define atomic_init_ptr(t,n,v) _Atomic(t *) n = (v)
#endif

#ifdef __cplusplus
}
#endif

#endif
