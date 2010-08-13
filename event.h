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
#ifndef _EVENT_H_
#define _EVENT_H_

/** @mainpage

  @section intro Introduction

  libevent is an event notification library for developing scalable network
  servers.  The libevent API provides a mechanism to execute a callback
  function when a specific event occurs on a file descriptor or after a
  timeout has been reached. Furthermore, libevent also support callbacks due
  to signals or regular timeouts.

  libevent is meant to replace the event loop found in event driven network
  servers. An application just needs to call event_dispatch() and then add or
  remove events dynamically without having to change the event loop.

  Currently, libevent supports /dev/poll, kqueue(2), select(2), poll(2) and
  epoll(4). It also has experimental support for real-time signals. The
  internal event mechanism is completely independent of the exposed event API,
  and a simple update of libevent can provide new functionality without having
  to redesign the applications. As a result, Libevent allows for portable
  application development and provides the most scalable event notification
  mechanism available on an operating system. Libevent can also be used for
  multi-threaded applications; see Steven Grimm's explanation. Libevent should
  compile on Linux, *BSD, Mac OS X, Solaris and Windows.

  @section usage Standard usage

  Every program that uses libevent must include the <event.h> header, and pass
  the -levent flag to the linker.  Before using any of the functions in the
  library, you must call event_init() or event_base_new() to perform one-time
  initialization of the libevent library.

  @section event Event notification

  For each file descriptor that you wish to monitor, you must declare an event
  structure and call event_set() to initialize the members of the structure.
  To enable notification, you add the structure to the list of monitored
  events by calling event_add().  The event structure must remain allocated as
  long as it is active, so it should be allocated on the heap. Finally, you
  call event_dispatch() to loop and dispatch events.

  @section bufferevent I/O Buffers

  libevent provides an abstraction on top of the regular event callbacks. This
  abstraction is called a buffered event. A buffered event provides input and
  output buffers that get filled and drained automatically. The user of a
  buffered event no longer deals directly with the I/O, but instead is reading
  from input and writing to output buffers.

  Once initialized via bufferevent_new(), the bufferevent structure can be
  used repeatedly with bufferevent_enable() and bufferevent_disable().
  Instead of reading and writing directly to a socket, you would call
  bufferevent_read() and bufferevent_write().

  When read enabled the bufferevent will try to read from the file descriptor
  and call the read callback. The write callback is executed whenever the
  output buffer is drained below the write low watermark, which is 0 by
  default.

  @section timers Timers

  libevent can also be used to create timers that invoke a callback after a
  certain amount of time has expired. The evtimer_set() function prepares an
  event struct to be used as a timer. To activate the timer, call
  evtimer_add(). Timers can be deactivated by calling evtimer_del().

  @section timeouts Timeouts

  In addition to simple timers, libevent can assign timeout events to file
  descriptors that are triggered whenever a certain amount of time has passed
  with no activity on a file descriptor.  The timeout_set() function
  initializes an event struct for use as a timeout. Once initialized, the
  event must be activated by using timeout_add().  To cancel the timeout, call
  timeout_del().

  @section evdns Asynchronous DNS resolution

  libevent provides an asynchronous DNS resolver that should be used instead
  of the standard DNS resolver functions.  These functions can be imported by
  including the <evdns.h> header in your program. Before using any of the
  resolver functions, you must call evdns_init() to initialize the library. To
  convert a hostname to an IP address, you call the evdns_resolve_ipv4()
  function.  To perform a reverse lookup, you would call the
  evdns_resolve_reverse() function.  All of these functions use callbacks to
  avoid blocking while the lookup is performed.

  @section evhttp Event-driven HTTP servers

  libevent provides a very simple event-driven HTTP server that can be
  embedded in your program and used to service HTTP requests.

  To use this capability, you need to include the <evhttp.h> header in your
  program.  You create the server by calling evhttp_new(). Add addresses and
  ports to listen on with evhttp_bind_socket(). You then register one or more
  callbacks to handle incoming requests.  Each URI can be assigned a callback
  via the evhttp_set_cb() function.  A generic callback function can also be
  registered via evhttp_set_gencb(); this callback will be invoked if no other
  callbacks have been registered for a given URI.

  @section evrpc A framework for RPC servers and clients

  libevent provides a framework for creating RPC servers and clients.  It
  takes care of marshaling and unmarshaling all data structures.

  @section api API Reference

  To browse the complete documentation of the libevent API, click on any of
  the following links.

  event2/event.h
  The primary libevent header

  event2/buffer.h
  Buffer management for network reading and writing

  event2/dns.h
  Asynchronous DNS resolution

  event2/http.h
  An embedded libevent-based HTTP server

  evrpc.h
  A framework for creating RPC servers and clients

 */

/** @file libevent/event.h

  A library for writing event-driven network servers

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
#ifdef _EVENT_HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdarg.h>

/* For int types. */
#include <evutil.h>

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
typedef unsigned char u_char;
typedef unsigned short u_short;
#endif

#include <event2/event_struct.h>
#include <event2/event.h>
#include <event2/event_compat.h>
#include <event2/buffer.h>
#include <event2/buffer_compat.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/bufferevent_compat.h>
#include <event2/tag.h>
#include <event2/tag_compat.h>

#ifdef __cplusplus
}
#endif

#endif /* _EVENT_H_ */
