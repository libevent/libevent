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
#ifndef _EVENT2_EVENT_H_
#define _EVENT2_EVENT_H_

/** @file event2/event.h

  Core functions for waiting for and receiving events, and using event bases.

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

#include <stdio.h>

/* For int types. */
#include <event2/util.h>

struct event_base;
struct event;
struct event_config;

/** Enable some relatively expensive debugging checks in Libevent that would
 * normally be turned off.  Generally, these cause code that would otherwise
 * crash mysteriously to fail earlier with an assertion failure.  Note that
 * this method MUST be called before any events or event_bases have been
 * created.
 *
 * Debug mode can currently catch the following errors:
 *    An event is re-assigned while it is added
 *    Any function is called on a non-assigned event
 *
 * Note that debugging mode uses memory to track every event that has been
 * initialized (via event_assign, event_set, or event_new) but not yet
 * released (via event_free or event_debug_unassign).  If you want to use
 * debug mode, and you find yourself running out of memory, you will need
 * to use event_debug_unassign to explicitly stop tracking events that
 * are no longer considered set-up.
 */
void event_enable_debug_mode(void);

/**
 * When debugging mode is enabled, informs Libevent that an event should no
 * longer be considered as assigned. When debugging mode is not enabled, does
 * nothing.
 *
 * This function must only be called on a non-added event.
 */
void event_debug_unassign(struct event *);

/**
  Initialize the event API.

  Use event_base_new() to initialize a new event base.

  @see event_base_set(), event_base_free(),
    event_base_new_with_config()
 */
struct event_base *event_base_new(void);

/**
  Reinitialized the event base after a fork

  Some event mechanisms do not survive across fork.   The event base needs
  to be reinitialized with the event_reinit() function.

  @param base the event base that needs to be re-initialized
  @return 0 if successful, or -1 if some events could not be re-added.
  @see event_base_new(), event_init()
*/
int event_reinit(struct event_base *base);

/**
  Threadsafe event dispatching loop.

  @param eb the event_base structure returned by event_init()
  @see event_init(), event_dispatch()
 */
int event_base_dispatch(struct event_base *);

/**
 Get the kernel event notification mechanism used by Libevent.

 @param eb the event_base structure returned by event_base_new()
 @return a string identifying the kernel event mechanism (kqueue, epoll, etc.)
 */
const char *event_base_get_method(const struct event_base *);

/**
   Gets all event notification mechanisms supported by Libevent.

   This functions returns the event mechanism in order preferred by
   Libevent.  Note that this list will include all backends that
   Libevent has compiled-in support for, and will not necessarily check
   your OS to see whether it has the required resources.

   @return an array with pointers to the names of support methods.
     The end of the array is indicated by a NULL pointer.  If an
     error is encountered NULL is returned.
*/
const char **event_get_supported_methods(void);

/**
   Allocates a new event configuration object.

   The event configuration object can be used to change the behavior of
   an event base.

   @return an event_config object that can be used to store configuration or
     NULL when an error is encountered.
*/

struct event_config *event_config_new(void);

/**
   Deallocates all memory associated with an event configuration object

   @param cfg the event configuration object to be freed.
*/
void event_config_free(struct event_config *cfg);

/**
   Enters an event method that should be avoided into the configuration.

   This can be used to avoid event mechanisms that do not support certain
   file descriptor types.  An application can make use of multiple event
   bases to accommodate incompatible file descriptor types.

   @param cfg the event configuration object
   @param method the event method to avoid
   @return 0 on success, -1 on failure.
*/
int event_config_avoid_method(struct event_config *cfg, const char *method);

enum event_method_feature {
    /* Require an event method that allows edge-triggered events with EV_ET. */
    EV_FEATURE_ET = 0x01,
    /* Require an event method where having one event triggered among
     * many is [approximately] an O(1) operation. This excludes (for
     * example) select and poll, which are approximately O(N) for N
     * equal to the total number of possible events. */
    EV_FEATURE_O1 = 0x02,
    /* Require an event method that allows file descriptors as well as
     * sockets. */
    EV_FEATURE_FDS = 0x04
};

enum event_base_config_flag {
	/** Do not allocate a lock for the event base, even if we have
	    locking set up. */
	EVENT_BASE_FLAG_NOLOCK = 0x01,
	/** Do not check the EVENT_* environment variables when configuring
	    an event_base  */
	EVENT_BASE_FLAG_IGNORE_ENV = 0x02,
	/** Windows only: enable the IOCP dispatcher at startup */
	EVENT_BASE_FLAG_STARTUP_IOCP = 0x04,
	/** Instead of checking the current time every time the event loop is
	    ready to run timeout callbacks, check after each timeout callback.
	 */
	EVENT_BASE_FLAG_NO_CACHE_TIME = 0x08,

	/** If we are using the epoll backend, this flag says that it is
	    safe to use Libevent's internal change-list code to batch up
	    adds and deletes in order to try to do as few syscalls as
	    possible.  Setting this flag can make your code run faster, but
	    it may trigger a Linux bug: it is not safe to use this flag
	    if you have any fds cloned by dup() or its variants.  Doing so
	    will produce strange and hard-to-diagnose bugs.

	    This flag can also be activated by settnig the
	    EVENT_EPOLL_USE_CHANGELIST environment variable.

	    This flag has no effect if you wind up using a backend other than
	    epoll.
	 */
	EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST = 0x10
};

/**
 Return a bitmask of the features implemented by an event base.
 */
int event_base_get_features(const struct event_base *base);

/**
   Enters a required event method feature that the application demands.

   Note that not every feature or combination of features is supported
   on every platform.  Code that requests features should be prepared
   to handle the case where event_base_new_with_config() returns NULL, as in:
   <pre>
     event_config_require_features(cfg, EV_FEATURE_ET);
     base = event_base_new_with_config(cfg);
     if (base == NULL) {
       // We can't get edge-triggered behavior here.
       event_config_require_features(cfg, 0);
       base = event_base_new_with_config(cfg);
     }
   </pre>

   @param cfg the event configuration object
   @param feature a bitfield of one or more event_method_feature values.
          Replaces values from previous calls to this function.
   @return 0 on success, -1 on failure.
*/
int event_config_require_features(struct event_config *cfg, int feature);

/** Sets one or more flags to configure what parts of the eventual event_base
 * will be initialized, and how they'll work. */
int event_config_set_flag(struct event_config *cfg, int flag);

/**
 * Records a hint for the number of CPUs in the system. This is used for
 * tuning thread pools, etc, for optimal performance.  In Libevent 2.0,
 * it is only on Windows, and only when IOCP is in use.
 *
 * @param cfg the event configuration object
 * @param cpus the number of cpus
 * @return 0 on success, -1 on failure.
 */
int event_config_set_num_cpus_hint(struct event_config *cfg, int cpus);

/**
  Initialize the event API.

  Use event_base_new_with_config() to initialize a new event base, taking
  the specified configuration under consideration.  The configuration object
  can currently be used to avoid certain event notification mechanisms.

  @param cfg the event configuration object
  @return an initialized event_base that can be used to registering events,
     or NULL if no event base can be created with the requested event_config.
  @see event_base_new(), event_base_free(), event_init(), event_assign()
*/
struct event_base *event_base_new_with_config(const struct event_config *);

/**
  Deallocate all memory associated with an event_base, and free the base.

  Note that this function will not close any fds or free any memory passed
  to event_set as the argument to callback.

  @param eb an event_base to be freed
 */
void event_base_free(struct event_base *);

#define _EVENT_LOG_DEBUG 0
#define _EVENT_LOG_MSG   1
#define _EVENT_LOG_WARN  2
#define _EVENT_LOG_ERR   3

/*
  A callback function used to intercept Libevent's log messages.
 */
typedef void (*event_log_cb)(int severity, const char *msg);
/**
  Redirect Libevent's log messages.

  @param cb a function taking two arguments: an integer severity between
     _EVENT_LOG_DEBUG and _EVENT_LOG_ERR, and a string.  If cb is NULL,
	 then the default log is used.

  NOTE: The function you provide *must not* call any other libevent
  functionality.  Doing so can produce undefined behavior.
  */
void event_set_log_callback(event_log_cb cb);

/**
 Override Libevent's behavior in the event of a fatal internal error.

 By default, Libevent will call exit(1) if a programming error makes it
 impossible to continue correct operation.  This function allows you to supply
 another callback instead.  Note that if the function is ever invoked,
 something is wrong with your program, or with Libevent: any subsequent calls
 to Libevent may result in undefined behavior.

 Libevent will (almost) always log an _EVENT_LOG_ERR message before calling
 this function; look at the last log message to see why Libevent has died.
 */
typedef void (*event_fatal_cb)(int err);
void event_set_fatal_callback(event_fatal_cb cb);

/**
  Associate a different event base with an event.

  @param eb the event base
  @param ev the event
 */
int event_base_set(struct event_base *, struct event *);

/**
 event_loop() flags
 */
/*@{*/
/** Block until we have an active event, then exit once all active events
 * have had their callbacks run. */
#define EVLOOP_ONCE	0x01
/** Do not block: see which events are ready now, run the callbacks
 * highest-priority ones, then exit. */
#define EVLOOP_NONBLOCK	0x02
/*@}*/

/**
  Handle events (threadsafe version).

  This is a more flexible version of event_base_dispatch().

  @param eb the event_base structure returned by event_init()
  @param flags any combination of EVLOOP_ONCE | EVLOOP_NONBLOCK
  @return 0 if successful, -1 if an error occurred, or 1 if no events were
    registered.
  @see event_loopexit(), event_base_loop()
  */
int event_base_loop(struct event_base *, int);

/**
  Exit the event loop after the specified time (threadsafe variant).

  The next event_base_loop() iteration after the given timer expires will
  complete normally (handling all queued events) then exit without
  blocking for events again.

  Subsequent invocations of event_base_loop() will proceed normally.

  @param eb the event_base structure returned by event_init()
  @param tv the amount of time after which the loop should terminate.
  @return 0 if successful, or -1 if an error occurred
  @see event_loopexit()
 */
int event_base_loopexit(struct event_base *, const struct timeval *);

/**
  Abort the active event_base_loop() immediately.

  event_base_loop() will abort the loop after the next event is completed;
  event_base_loopbreak() is typically invoked from this event's callback.
  This behavior is analogous to the "break;" statement.

  Subsequent invocations of event_loop() will proceed normally.

  @param eb the event_base structure returned by event_init()
  @return 0 if successful, or -1 if an error occurred
  @see event_base_loopexit
 */
int event_base_loopbreak(struct event_base *);

/**
  Checks if the event loop was told to exit by event_loopexit().

  This function will return true for an event_base at every point after
  event_loopexit() is called, until the event loop is next entered.

  @param eb the event_base structure returned by event_init()
  @return true if event_base_loopexit() was called on this event base,
    or 0 otherwise
  @see event_base_loopexit
  @see event_base_got_break
 */
int event_base_got_exit(struct event_base *);

/**
  Checks if the event loop was told to abort immediately by event_loopbreak().

  This function will return true for an event_base at every point after
  event_loopbreak() is called, until the event loop is next entered.

  @param eb the event_base structure returned by event_init()
  @return true if event_base_loopbreak() was called on this event base,
    or 0 otherwise
  @see event_base_loopbreak
  @see event_base_got_exit
 */
int event_base_got_break(struct event_base *);

/* Flags to pass to event_set(), event_new(), event_assign(),
 * event_pending(), and anything else with an argument of the form
 * "short events" */
#define EV_TIMEOUT	0x01
#define EV_READ		0x02
#define EV_WRITE	0x04
#define EV_SIGNAL	0x08
/** Persistent event: won't get removed automatically when activated. */
#define EV_PERSIST	0x10
/** Select edge-triggered behavior, if supported by the backend. */
#define EV_ET       0x20

/**
  Define a timer event.

  @param ev event struct to be modified
  @param b an event_base
  @param cb callback function
  @param arg argument that will be passed to the callback function
 */
#define evtimer_assign(ev, b, cb, arg) \
	event_assign((ev), (b), -1, 0, (cb), (arg))
#define evtimer_new(b, cb, arg)	       event_new((b), -1, 0, (cb), (arg))

/**
  Add a timer event.

  @param ev the event struct
  @param tv timeval struct
 */
#define evtimer_add(ev, tv)		event_add((ev), (tv))

/**
 * Delete a timer event.
 *
 * @param ev the event struct to be disabled
 */
#define evtimer_del(ev)			event_del(ev)
#define evtimer_pending(ev, tv)		event_pending((ev), EV_TIMEOUT, (tv))
#define evtimer_initialized(ev)		event_initialized(ev)

#define evsignal_add(ev, tv)		event_add((ev), (tv))
#define evsignal_assign(ev, b, x, cb, arg)			\
	event_assign((ev), (b), (x), EV_SIGNAL|EV_PERSIST, cb, (arg))
#define evsignal_new(b, x, cb, arg)				\
	event_new((b), (x), EV_SIGNAL|EV_PERSIST, (cb), (arg))
#define evsignal_del(ev)		event_del(ev)
#define evsignal_pending(ev, tv)	event_pending((ev), EV_SIGNAL, (tv))
#define evsignal_initialized(ev)	event_initialized(ev)

typedef void (*event_callback_fn)(evutil_socket_t, short, void *);

/**
  Prepare an event structure to be added.

  The function event_assign() prepares the event structure ev to be used in
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

  Note that using event_assign() request that you have already allocated the
  event struct.  Doing so will often require your code to depend on the size
  of the structure, and will create possible incompatibility with future
  versions of Libevent.  If this seems like a bad idea to you, use event_new()
  and event_free() instead.

  @param ev an event struct to be modified
  @param base the event base to which ev should be attached.
  @param fd the file descriptor to be monitored
  @param event desired events to monitor; can be EV_READ and/or EV_WRITE
  @param fn callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function

  @return 0 if success, or -1 on invalid arguments.

  @see event_add(), event_del(), event_once()

  */
int event_assign(struct event *, struct event_base *, evutil_socket_t, short, event_callback_fn, void *);

/**
  Create and allocate a new event structure, ready to be added.

  Arguments are as for event_assign; returns a newly allocated struct event *
  that must later be deallocated with event_free().

 */
struct event *event_new(struct event_base *, evutil_socket_t, short, event_callback_fn, void *);

/**
   Deallocate a struct event * returned by event_new().
 */
void event_free(struct event *);

/**
  Schedule a one-time event

  The function event_base_once() is similar to event_set().  However, it
  schedules a callback to be called exactly once and does not require the
  caller to prepare an event structure.

  @param base an event_base returned by event_init()
  @param fd a file descriptor to monitor
  @param events event(s) to monitor; can be any of EV_TIMEOUT | EV_READ |
         EV_WRITE
  @param callback callback function to be invoked when the event occurs
  @param arg an argument to be passed to the callback function
  @param timeout the maximum amount of time to wait for the event, or NULL
         to wait forever
  @return 0 if successful, or -1 if an error occurred
  @see event_once()
 */
int event_base_once(struct event_base *, evutil_socket_t, short, event_callback_fn, void *, const struct timeval *);

/**
  Add an event to the set of monitored events.

  The function event_add() schedules the execution of the ev event when the
  event specified in event_set() occurs or in at least the time specified in
  the tv.  If tv is NULL, no timeout occurs and the function will only be
  called if a matching event occurs on the file descriptor.  The event in the
  ev argument must be already initialized by event_set() and may not be used
  in calls to event_set() until it has timed out or been removed with
  event_del().  If the event in the ev argument already has a scheduled
  timeout, the old timeout will be replaced by the new one.

  @param ev an event struct initialized via event_set()
  @param timeout the maximum amount of time to wait for the event, or NULL
         to wait forever
  @return 0 if successful, or -1 if an error occurred
  @see event_del(), event_set()
  */
int event_add(struct event *, const struct timeval *);

/**
  Remove an event from the set of monitored events.

  The function event_del() will cancel the event in the argument ev.  If the
  event has already executed or has never been added the call will have no
  effect.

  @param ev an event struct to be removed from the working set
  @return 0 if successful, or -1 if an error occurred
  @see event_add()
 */
int event_del(struct event *);


/**
  Make an event active.

  @param ev an event to make active.
  @param res a set of flags to pass to the event's callback.
  @param ncalls
 **/
void event_active(struct event *, int, short);


/**
  Checks if a specific event is pending or scheduled.

  @param ev an event struct previously passed to event_add()
  @param what the requested event type; any of EV_TIMEOUT|EV_READ|
         EV_WRITE|EV_SIGNAL
  @param tv if this field is not NULL, and the event has a timeout,
         this field is set to hold the time at which the timeout will
	 expire.

  @return true if the event is pending on any of the events in 'what', (that
  is to say, it has been added), or 0 if the event is not added.

 */
int event_pending(const struct event *, short, struct timeval *);


/**
  Test if an event structure might be initialized.

  The event_initialized() function can be used to check if an event has been
  initialized.

  Warning: This function is only useful for distinguishing a a zeroed-out
    piece of memory from an initialized event, it can easily be confused by
    uninitialized memory.  Thus, it should ONLY be used to distinguish an
    initialized event from zero.

  @param ev an event structure to be tested
  @return 1 if the structure might be initialized, or 0 if it has not been
          initialized
 */
int event_initialized(const struct event *ev);

/**
   Get the signal number assigned to an event.
*/
#define event_get_signal(ev) ((int)event_get_fd(ev))

/**
   Get the socket assigned to an event.
*/
evutil_socket_t event_get_fd(const struct event *ev);

/**
   Get the event_base assigned to an event.
*/
struct event_base *event_get_base(const struct event *ev);

/**
   Return the events (EV_READ, EV_WRITE, etc) assigned to an event.
*/
short event_get_events(const struct event *ev);

/**
   Return the callback assigned to an event.
*/
event_callback_fn event_get_callback(const struct event *ev);

/**
   Return the callback argument assigned to an event.
*/
void *event_get_callback_arg(const struct event *ev);

/**
   Extract _all_ of arguments given to construct a given event.  The
   event_base is copied into *base_out, the fd is copied into *fd_out, and so
   on.

   If any of the "_out" arguments is NULL, it will be ignored.
 */
void event_get_assignment(const struct event *event,
    struct event_base **base_out, evutil_socket_t *fd_out, short *events_out,
    event_callback_fn *callback_out, void **arg_out);

/**
   Return the size of struct event that the Libevent library was compiled
   with.

   This will be NO GREATER than sizeof(struct event) if you're running with
   the same version of Libevent that your application was built with, but
   otherwise might not.

   Note that it might be SMALLER than sizeof(struct event) if some future
   version of Libevent adds extra padding to the end of struct event.
   We might do this to help ensure ABI-compatibility between different
   versions of Libevent.
 */
size_t event_get_struct_event_size(void);

/**
   Get the Libevent version.

   Note that this will give you the version of the library that you're
   currently linked against, not the version of the headers that you've
   compiled against.

   @return a string containing the version number of Libevent
*/
const char *event_get_version(void);

/**
   Return a numeric representation of Libevent's version.

   Note that this will give you the version of the library that you're
   currently linked against, not the version of the headers you've used to
   compile.

   The format uses one byte each for the major, minor, and patchlevel parts of
   the version number.  The low-order byte is unused.  For example, version
   2.0.1-alpha has a numeric representation of 0x02000100
*/
ev_uint32_t event_get_version_number(void);

/** As event_get_version, but gives the version of Libevent's headers. */
#define LIBEVENT_VERSION _EVENT_VERSION
/** As event_get_version_number, but gives the version number of Libevent's
 * headers. */
#define LIBEVENT_VERSION_NUMBER _EVENT_NUMERIC_VERSION

#define EVENT_MAX_PRIORITIES 256
/**
  Set the number of different event priorities (threadsafe variant).

  See the description of event_priority_init() for more information.

  @param eb the event_base structure returned by event_init()
  @param npriorities the maximum number of priorities
  @return 0 if successful, or -1 if an error occurred
  @see event_priority_init(), event_priority_set()
 */
int	event_base_priority_init(struct event_base *, int);


/**
  Assign a priority to an event.

  @param ev an event struct
  @param priority the new priority to be assigned
  @return 0 if successful, or -1 if an error occurred
  @see event_priority_init()
  */
int	event_priority_set(struct event *, int);

/**
   Prepare Libevent to use a large number of timeouts with the same duration.

   Libevent's default scheduling algorithm is optimized for having a large
   number of timeouts with their durations more or less randomly distributed.
   If you have a large number of timeouts that all have the same duration (for
   example, if you have a large number of connections that all have a
   10-second timeout), then you can improve Libevent's performance by telling
   Libevent about it.

   To do this, call this function with the common duration.  It will return a
   pointer to a different, opaque timeout value.  (Don't depend on its actual
   contents!)  When you use this timeout value in event_add(), Libevent will
   schedule the event more efficiently.

   (This optimization probably will not be worthwhile until you have thousands
   or tens of thousands of events with the same timeout.)
 */
const struct timeval *event_base_init_common_timeout(struct event_base *base,
    const struct timeval *duration);

#ifndef _EVENT_DISABLE_MM_REPLACEMENT
/**
 Override the functions that Libevent uses for memory management.

 Usually, Libevent uses the standard libc functions malloc, realloc, and
 free to allocate memory.  Passing replacements for those functions to
 event_set_mem_functions() overrides this behavior.  To restore the default
 behavior, pass NULLs as the arguments to this function.

 Note that all memory returned from Libevent will be allocated by the
 replacement functions rather than by malloc() and realloc().  Thus, if you
 have replaced those functions, it may not be appropriate to free() memory
 that you get from Libevent.

 @param malloc_fn A replacement for malloc.
 @param realloc_fn A replacement for realloc
 @param free_fn A replacement for free.
 **/
void event_set_mem_functions(
	void *(*malloc_fn)(size_t sz),
	void *(*realloc_fn)(void *ptr, size_t sz),
	void (*free_fn)(void *ptr));
#define EVENT_SET_MEM_FUNCTIONS_IMPLEMENTED
#endif

void event_base_dump_events(struct event_base *, FILE *);

/** Sets 'tv' to the current time (as returned by gettimeofday()),
    looking at the cached value in 'base' if possible, and calling
    gettimeofday() or clock_gettime() as appropriate if there is no
    cached time.

    Generally, this value will only be cached while actually
    processing event callbacks, and may be very inaccuate if your
    callbacks take a long time to execute.

    Returns 0 on success, negative on failure.
 */
int event_base_gettimeofday_cached(struct event_base *base,
    struct timeval *tv);

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_EVENT_H_ */
