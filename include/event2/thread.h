/*
 * Copyright (c) 2008-2009 Niels Provos and Nick Mathewson
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
#ifndef _EVENT2_THREAD_H_
#define _EVENT2_THREAD_H_

/** @file thread.h

  Functions for multi-threaded applications using Libevent.

  When using a multi-threaded application in which multiple threads
  add and delete events from a single event base, Libevent needs to
  lock its data structures.

  Like the memory-management function hooks, all of the threading functions
  _must_ be set up before an event_base is created if you want the base to
  use them.

  A multi-threaded application must provide locking functions to
  Libevent via evthread_set_locking_callback().  Libevent will invoke
  this callback whenever a lock needs to be acquired or released.

  The total number of locks employed by Libevent can be determined
  via the evthread_num_locks() function.  An application must provision
  that many locks.

  If the owner of an event base is waiting for events to happen,
  Libevent may signal the thread via a special file descriptor to wake
  up.   To enable this feature, an application needs to provide a
  thread identity function via evthread_set_id_callback().

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>

/* combine (lock|unlock) with (read|write) */
#define EVTHREAD_LOCK	0x01
#define EVTHREAD_UNLOCK	0x02
#define EVTHREAD_WRITE	0x04
#define EVTHREAD_READ	0x08

#ifndef _EVENT_DISABLE_THREAD_SUPPORT

/**
   Sets the functions Libevent should use for allocating and freeing
   locks.  This needs to be called in addition to
   evthread_set_locking_callback() before using Libevent in a
   multi-threaded application.

   Locks must be recursive.  That is, it must be safe for a thread to
   acquire a lock that it already holds.

   @param alloc_fn function to be called when allocating a new lock
   @param free_fn function to be called to a free a lock
*/
void evthread_set_lock_create_callbacks(
    void *(*alloc_fn)(void), void (*free_fn)(void *));

/**
   Sets the function Libevent should use for locking.

   @param locking_fn the function that Libevent should invoke to acquire
     or release a lock.  mode has either EVTHREAD_LOCK or EVTHREAD_UNLOCK
     set, and in addition, either EVTHREAD_WRITE or EVTHREAD_READ.
 */
void evthread_set_locking_callback(
    void (*locking_fn)(int mode, void *lock));

/**
   Sets the function for determining the thread id.

   @param base the event base for which to set the id function
   @param id_fn the identify function Libevent should invoke to
     determine the identity of a thread.
*/
void evthread_set_id_callback(
    unsigned long (*id_fn)(void));

#if defined(WIN32) && !defined(_EVENT_DISABLE_THREAD_SUPPORT)
/** Sets up Libevent for use with Windows builtin locking and thread ID
	functions.  Unavailable if Libevent is not built for Windows.

	@return 0 on success, -1 on failure. */
int evthread_use_windows_threads(void);
#define EVTHREAD_USE_WINDOWS_THREADS_IMPLEMENTED 1
#endif

#if defined(_EVENT_HAVE_PTHREADS)
/** Sets up Libevent for use with Pthreads locking and thread ID functions.
	Unavailable if Libevent is not build for use with pthreads.  Requires
	libraries to link against Libevent_pthreads as well as Libevent.

	@return 0 on success, -1 on failure. */
int evthread_use_pthreads(void);
#define EVTHREAD_USE_PTHREADS_IMPLEMENTED 1
#endif

#endif /* _EVENT_DISABLE_THREAD_SUPPORT */

/** Make sure it's safe to tell an event base to wake up from another thread.
    or a signal handler.

	@return 0 on success, -1 on failure.
 */
int evthread_make_base_notifiable(struct event_base *base);

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_THREAD_H_ */
