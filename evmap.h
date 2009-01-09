/*
 * Copyright (c) 2007 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
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
#ifndef _EVMAP_H_
#define _EVMAP_H_

/** @file evmap.h
 *
 * An event_map is a utility structure to map each fd or signal to zero or
 * more events.  Functions to manipulate event_maps should only be used from
 * inside libevent.
 **/

struct event_map;
struct event_base;
struct event;

/** Remove all entries from an event_map.

	@param ctx the map to clear.
 */
void evmap_clear(struct event_map* ctx);

/** Add an IO event (some combination of EV_READ or EV_WRITE) to an
	event_base's list of events on a given file descriptor, and tell the
	underlying eventops about the fd if its state has changed.

	@param base the event_base to operate on.
	@param fd the file descriptor corresponding to ev.
	@param ev the event to add.
 */
int evmap_io_add(struct event_base *base, evutil_socket_t fd, struct event *ev);
/** Remove an IO event (some combination of EV_READ or EV_WRITE) to an
	event_base's list of events on a given file descriptor, and tell the
	underlying eventops about the fd if its state has changed.

	@param base the event_base to operate on.
	@param fd the file descriptor corresponding to ev.
	@param ev the event to remove.
 */
int evmap_io_del(struct event_base *base, evutil_socket_t fd, struct event *ev);
/** Active the set of events waiting on an event_base for a given fd.

	@param base the event_base to operate on.
	@param fd the file descriptor that has become active.
	@param events a bitmask of EV_READ|EV_WRITE|EV_ET.
 */
void evmap_io_active(struct event_base *base, evutil_socket_t fd, short events);

int evmap_signal_add(struct event_base *base, int signum, struct event *ev);
int evmap_signal_del(struct event_base *base, int signum, struct event *ev);
void evmap_signal_active(struct event_base *base, int fd, int ncalls);

#endif /* _EVMAP_H_ */
