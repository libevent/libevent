/*
 * Copyright (c) 2008 Niels Provos <provos@citi.umich.edu>
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
#ifndef _EVTHREAD_INTERNAL_H_
#define _EVTHREAD_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "event-config.h"

struct event_base;
#ifndef _EVENT_DISABLE_THREAD_SUPPORT
#define EVTHREAD_USE_LOCKS(base) \
	(base != NULL && (base)->th_lock != NULL)

#define EVTHREAD_IN_THREAD(base) \
	((base)->th_get_id == NULL || \
	(base)->th_owner_id == (*(base)->th_get_id)())

#define EVTHREAD_GET_ID(base) \
	(*(base)->th_get_id)()

#define EVTHREAD_ACQUIRE_LOCK(base, mode, lock) do {	\
		if (EVTHREAD_USE_LOCKS(base))		\
			(*(base)->th_lock)(EVTHREAD_LOCK | mode, \
			    (base)->lock);			 \
	} while (0)

#define EVTHREAD_RELEASE_LOCK(base, mode, lock) do {	\
		if (EVTHREAD_USE_LOCKS(base))		\
			(*(base)->th_lock)(EVTHREAD_UNLOCK | mode, \
			    (base)->lock);			   \
	} while (0)
#else /* _EVENT_DISABLE_THREAD_SUPPORT */
#define EVTHREAD_USE_LOCKS(base)
#define EVTHREAD_IN_THREAD(base)	1
#define EVTHREAD_GET_ID(base)
#define EVTHREAD_ACQUIRE_LOCK(base, mode, lock)
#define EVTHREAD_RELEASE_LOCK(base, mode, lock)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EVTHREAD_INTERNAL_H_ */
