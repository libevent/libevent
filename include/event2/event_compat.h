/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
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

#include <event2/event-config.h>
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* For int types. */
#include <event2/util.h>

/**
  Initialize the event API.

  The event API needs to be initialized with event_init() before it can be
  used.  Sets the global current base that gets used for events that have no
  base associated with them.

  @deprecated This function is deprecated because it replaces the "current"
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
  Get the kernel event notification mechanism used by Libevent.

  @return a string identifying the kernel event mechanism (kqueue, epoll, etc.)

  @deprecated This function is deprecated because it is easily confused by
    multiple calls to event_init(), and because it is not safe for
    multithreaded use.  The replacement is event_base_get_method().
 */
const char *event_get_method(void);


/**
  Set the number of different event priorities.

  By default Libevent schedules all active events with the same priority.
  However, some time it is desirable to process some events with a higher
  priority than others.  For that reason, Libevent supports strict priority
  queues.  Active events with a lower priority are always processed before
  events with a higher priority.

  The number of different priorities can be set initially with the
  event_priority_init() function.  This function should be called before the
  first call to event_dispatch().  The event_priority_set() function can be
  used to assign a priority to an event.  By default, Libevent assigns the
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
  Prepare an event structure to be added.

  The function event_set() prepares the event structure ev to be used in
  future calls to event_add() and event_del().  The event will be prepared to
  call the function specified by the fn argument with an int argument
  indicating the file descriptor, a short argument indicating the type of
  event, and a void * argument given in the arg argument.  The fd indicates
  the file descriptor that should be monitored for events.  The events can be
  either EV_READ, EV_WRITE, or both.  Indicating that an application can read
  or write from the file descriptor respectively without blocking.

  The function fn will be called with the file descriptor that triggered the
  event and the type of event which will be either EV_TIMEOUT, EV_SIGNAL,
  EV_READ, or EV_WRITE.  The additional flag EV_PERSIST makes an event_add()
  persistent until event_del() has been called.

  For read and write events, edge-triggered behavior can be requested
  with the EV_ET flag.  Not all backends support edge-triggered
  behavior.  When an edge-triggered event is activated, the EV_ET flag
  is added to its events argument.

  @param ev an event struct to be modified
  @param fd the file descriptor to be monitored
  @param event desired events to monitor; can be EV_READ and/or EV_WRITE
  @param fn callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function

  @see event_add(), event_del(), event_once()

  @deprecated event_set() is not recommended for new code, because it requires
     a subsequent call to event_base_set() to be safe under many circumstances.
     Use event_assign() or event_new() instead.
 */
void event_set(struct event *, evutil_socket_t, short, void (*)(evutil_socket_t, short, void *), void *);

#define evtimer_set(ev, cb, arg)	event_set((ev), -1, 0, (cb), (arg))
#define evsignal_set(ev, x, cb, arg)	\
	event_set((ev), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))


/**
 * Add a timeout event.
 *
 * @param ev the event struct to be disabled
 * @param tv the timeout value, in seconds
 *
 * @deprecated This macro is deprecated because its naming is inconsistent.
 *    The recommend macro is evtimer_add().
 */
#define timeout_add(ev, tv)		event_add((ev), (tv))


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
#define timeout_set(ev, cb, arg)	event_set((ev), -1, 0, (cb), (arg))

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
#define timeout_pending(ev, tv)		event_pending((ev), EV_TIMEOUT, (tv))
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
   The recommend macro is evtimer_initialized().
*/
#define timeout_initialized(ev)		event_initialized(ev)

/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_add().
*/
#define signal_add(ev, tv)		event_add((ev), (tv))
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_set().
*/
#define signal_set(ev, x, cb, arg)				\
	event_set((ev), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_del().
*/
#define signal_del(ev)			event_del(ev)
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_pending().
*/
#define signal_pending(ev, tv)		event_pending((ev), EV_SIGNAL, (tv))
/**
   @deprecated This macro is deprecated because its naming is inconsistent.
    The recommend macro is evsignal_initialized().
*/
#define signal_initialized(ev)		event_initialized(ev)

#ifndef EVENT_FD
/* These macros are obsolete; use event_get_fd and event_get_signal instead. */
#define EVENT_FD(ev)		((int)event_get_fd(ev))
#define EVENT_SIGNAL(ev)	event_get_signal(ev)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_EVENT_COMPAT_H_ */
