/*
 * Copyright (c) 2009 Niels Provos and Nick Mathewson
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

#ifndef _EVENT_IOCP_INTERNAL_H
#define _EVENT_IOCP_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

struct event_overlapped;
typedef void (*iocp_callback)(struct event_overlapped *, uintptr_t, ssize_t);

struct event_overlapped {
	OVERLAPPED overlapped;
	iocp_callback cb;
};

struct event_iocp_port {
	HANDLE port;
	int n_threads;
	int shutdown;
	long ms;
};

struct evbuffer;
void event_overlapped_init(struct event_overlapped *, iocp_callback cb);
int evbuffer_launch_read(struct evbuffer *, size_t n);
int evbuffer_launch_write(struct evbuffer *, ssize_t n);

struct event_iocp_port *event_iocp_port_launch(void);
int event_iocp_port_associate(struct event_iocp_port *port, evutil_socket_t fd,
    uintptr_t key);
void event_iocp_shutdown(struct event_iocp_port *port);

#ifdef __cplusplus
}
#endif

#endif
