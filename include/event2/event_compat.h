/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
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
#ifndef _EVENT2_EVENT_COMPAT_H_
#define _EVENT2_EVENT_COMPAT_H_

/** @file event_compat.h

  Potentially non-threadsafe versions of the functions in event.h: provided
  only for backwards compatibility.

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

/**
  Initialize the event API.

  The event API needs to be initialized with event_init() before it can be
  used.  Sets the current_base global representing the default base for
  events that have no base associated with them.

  @deprecated This function is deprecated because it relaces the "current"
    event_base, and is totally unsafe for multithreaded use.  The replacement
    is event_base_new().

  @see event_base_set(), event_base_new()
 */
struct event_base *event_init(void);

/**
  Loop to process events.

  In order to process events, an application needs to call
  event_dispatch().  This function only returns on error, and should
  replace the event core of the application program.

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_dispatch().

  @see event_base_dispatch()
 */
int event_dispatch(void);

/**
  Handle events.

  This is a more flexible version of event_dispatch().

  @deprecated This function is deprecated because it uses the event base from
    the last call to event_init, and is therefore not safe for multithreaded
    use.  The replacement is event_base_loop().

  @param flags any combination of EVLOOP_ONCE | EVLOOP_NONBLOCK
  @return 0 if successful, -1 if an error occurred, or 1 if no events were
    registered.
  @see event_base_loopexit(), event_base_loop()
*/
int event_loop(int);


/**
  Exit the event loop after the specified time.

  The next event_loop() iteration after the given timer expires will
  complete normally (handling all queued events) then exit without
  blocking for events again.

  Subsequent invocations of event_loop() will proceed normally.

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_loopexit().

  @param tv the amount of time after which the loop should terminate.
  @return 0 if successful, or -1 if an error occurred
  @see event_loop(), event_base_loop(), event_base_loopexit()
  */
int event_loopexit(const struct timeval *);


/**
  Abort the active event_loop() immediately.

  event_loop() will abort the loop after the next event is completed;
  event_loopbreak() is typically invoked from this event's callback.
  This behavior is analogous to the "break;" statement.

  Subsequent invocations of event_loop() will proceed normally.

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_loopbreak().

  @return 0 if successful, or -1 if an error occurred
  @see event_base_loopbreak(), event_loopexit()
 */
int event_loopbreak(void);

/**
  Schedule a one-time event to occur.

  The function event_once() is similar to event_set().  However, it schedules
  a callback to be called exactly once and does not require the caller to
  prepare an event structure.

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_once().

  @param fd a file descriptor to monitor
  @param events event(s) to monitor; can be any of EV_TIMEOUT | EV_READ |
         EV_WRITE
  @param callback callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function
  @param timeout the maximum amount of time to wait for the event, or NULL
         to wait forever
  @return 0 if successful, or -1 if an error occurred
  @see event_set()

 */
int event_once(evutil_socket_t , short,
    void (*)(evutil_socket_t, short, void *), void *, const struct timeval *);


/**
  Get the kernel event notification mechanism used by libevent.

  @return a string identifying the kernel event mechanism (kqueue, epoll, etc.)

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_get_method().
 */
const char *event_get_method(void);


/**
  Set the number of different event priorities.

  By default libevent schedules all active events with the same priority.
  However, some time it is desirable to process some events with a higher
  priority than others.  For that reason, libevent supports strict priority
  queues.  Active events with a lower priority are always processed before
  events with a higher priority.

  The number of different priorities can be set initially with the
  event_priority_init() function.  This function should be called before the
  first call to event_dispatch().  The event_priority_set() function can be
  used to assign a priority to an event.  By default, libevent assigns the
  middle priority to all events unless their priority is explicitly set.

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_priority_init().

  @param npriorities the maximum number of priorities
  @return 0 if successful, or -1 if an error occurred
  @see event_base_priority_init(), event_priority_set()

 */
int	event_priority_init(int);


/**
 * Add a timeout event.
 *
 * @param ev the event struct to be disabled
 * @param tv the timeout value, in seconds
 *
 * @deprecated This macro is deprecated because its naming is inconsistent.
 *    The recommend macro is evtimer_add().
 */
#define timeout_add(ev, tv)		event_add(ev, tv)


/**
 * Define a timeout event.
 *
 * @param ev the event struct to be defined
 * @param cb the callback to be invoked when the timeout expires
 * @param arg the argument to be passed to the callback
 *
 * @deprecated This macro is deprecated because its naming is inconsistent.
 *    The recommend macro is evtimer_set().
 */
#define timeout_set(ev, cb, arg)	event_set(ev, -1, 0, cb, arg)

/**
 * Disable a timeout event.
 *
 * @param ev the timeout event to be disabled
 *
 * @deprecated This macro is deprecated because its naming is inconsistent.
 *    The recommend macro is evtimer_del().
 */
#define timeout_del(ev)			event_del(ev)

/**
   @deprecated This macro is deprecated because its naming is inconsistent.
   The recommend macro is evtimer_pending().
*/
#define timeout_pending(ev, tv)		event_pending(ev, EV_TIMEOUT, tv)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
   The recommend macro is evtimer_initialized().
*/
#define timeout_initialized(ev)		_event_initialized((ev), 0)

/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_add().
*/
#define signal_add(ev, tv)		event_add(ev, tv)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_set().
*/
#define signal_set(ev, x, cb, arg)	\
	event_set(ev, x, EV_SIGNAL|EV_PERSIST, cb, arg)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_assign().
*/
#define signal_assign(ev, b, x, cb, arg)                    \
	event_assign(ev, b, x, EV_SIGNAL|EV_PERSIST, cb, arg)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_new().
*/
#define signal_new(b, x, cb, arg) \
	event_new(b, x, EV_SIGNAL|EV_PERSIST, cb, arg)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_del().
*/
#define signal_del(ev)			event_del(ev)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_pending().
*/
#define signal_pending(ev, tv)		event_pending(ev, EV_SIGNAL, tv)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_initialized().
*/
#define signal_initialized(ev)		_event_initialized((ev), 0)

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_EVENT_COMPAT_H_ */
