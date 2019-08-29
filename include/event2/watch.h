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
#ifndef EVENT2_WATCH_H_INCLUDED_
#define EVENT2_WATCH_H_INCLUDED_

/** @file event2/watch.h

  @brief "Prepare" and "check" watchers.

  "Prepare" and "check" watchers. A "prepare" watcher is a callback that fires
  immediately before polling for I/O. A "check" watcher is a callback that
  fires immediately after polling and before processing any active events. This
  may be useful for embedding other libraries' event loops (e.g. UI toolkits)
  into libevent's.

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event2/visibility.h>

struct event_base;
struct evwatch;
struct evwatch_prepare_cb_info;
struct evwatch_check_cb_info;
struct timeval;

/**
  Prepare callback, invoked by event_base_loop immediately before polling for
  I/O.

  @param watcher the prepare watcher that invoked this callback.
  @param info contextual information passed from event_base_loop.
  @param arg additional user-defined argument, set in `evwatch_prepare_new`.
 */
typedef void (*evwatch_prepare_cb)(struct evwatch *, const struct evwatch_prepare_cb_info *, void *);

/**
  Check callback, invoked by event_base_loop immediately after polling for I/O
  and before processing any active events.

  @param watcher the check watcher that invoked this callback.
  @param info contextual information passed from event_base_loop.
  @param arg additional user-defined argument, set in `evwatch_check_new`.
 */
typedef void (*evwatch_check_cb)(struct evwatch *, const struct evwatch_check_cb_info *, void *);

/**
  Register a new "prepare" watcher, to be called in the event loop prior to
  polling for events. Watchers will be called in the order they were
  registered.

  @param base the event_base to operate on.
  @param callback the callback function to invoke.
  @param arg additional user-defined argument provided to the callback.
  @return a pointer to the newly allocated event watcher.
 */
EVENT2_EXPORT_SYMBOL
struct evwatch *evwatch_prepare_new(struct event_base *base, evwatch_prepare_cb callback, void *arg);

/**
  Register a new "check" watcher, to be called in the event loop after polling
  for events and before handling them. Watchers will be called in the order
  they were registered.

  @param base the event_base to operate on.
  @param callback the callback function to invoke.
  @param arg additional user-defined argument provided to the callback.
  @return a pointer to the newly allocated event watcher.
 */
EVENT2_EXPORT_SYMBOL
struct evwatch *evwatch_check_new(struct event_base *base, evwatch_check_cb callback, void *arg);

/**
  Get the event_base that a given evwatch is registered with.

  @param watcher the watcher to get the event_base for.
  @return the event_base for the given watcher.
 */
EVENT2_EXPORT_SYMBOL
struct event_base *evwatch_base(struct evwatch *watcher);

/**
  Deregister and deallocate a watcher. Any watchers not freed using
  evwatch_free will eventually be deallocated in event_base_free
  (calling evwatch_free on a watcher after event_base_free has been
  called on its corresponding event_base is an error).

  @param watcher the watcher to deregister and deallocate.
 */
EVENT2_EXPORT_SYMBOL
void evwatch_free(struct evwatch *watcher);

/**
  Get the timeout (the expected polling duration) passed to the underlying
  implementation's `dispatch`. This value will only be set if there are pending
  EV_TIMEOUT events and if the event_base isn't in EVLOOP_NONBLOCK mode. It may
  be a useful performance statistic to compare the expected polling duration
  against the actual polling duration (that is, the time difference measured
  between this prepare callback and the following check callback).

  @param info the "prepare" callback info.
  @param timeout address of a timeval to write the polling duration to.
  @return 1 if a value was written to *timeout, or 0 if not.
 */
EVENT2_EXPORT_SYMBOL
int evwatch_prepare_get_timeout(const struct evwatch_prepare_cb_info *info, struct timeval *timeout);

#ifdef __cplusplus
}
#endif

#endif /* EVENT2_WATCH_H_INCLUDED_ */
