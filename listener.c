/*
 * Copyright (c) 2009 Niels Provos, Nick Mathewson
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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#endif
#include <errno.h>
#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef _EVENT_HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include "mm-internal.h"
#include "util-internal.h"
#include "log-internal.h"

struct evconnlistener {
	struct event listener;
	evconnlistener_cb cb;
	void *user_data;
	unsigned flags;
};

static void listener_read_cb(evutil_socket_t, short, void *);

struct evconnlistener *
evconnlistener_new(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	struct evconnlistener *lev;
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			return NULL;
	}
	lev = mm_calloc(1, sizeof(struct evconnlistener));
	if (!lev)
		return NULL;
	lev->cb = cb;
	lev->user_data = ptr;
	lev->flags = flags;
	event_assign(&lev->listener, base, fd, EV_READ|EV_PERSIST,
	    listener_read_cb, lev);
	evconnlistener_enable(lev);
	return lev;
}

struct evconnlistener *
evconnlistener_new_bind(struct event_base *base, evconnlistener_cb cb, void *ptr,
    unsigned flags, int backlog, const struct sockaddr *sa, int socklen)
{
	evutil_socket_t fd;
	int on = 1;
	int family = sa ? sa->sa_family : AF_UNSPEC;

	if (backlog == 0)
		return NULL;
	fd = socket(family, SOCK_STREAM, 0);
	if (fd == -1)
		return NULL;
	if (evutil_make_socket_nonblocking(fd) < 0)
		return NULL;

#ifndef WIN32
	if (flags & LEV_OPT_CLOSE_ON_EXEC) {
		if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
			EVUTIL_CLOSESOCKET(fd);
			return NULL;
		}
	}
#endif

	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on));
	if (flags & LEV_OPT_REUSEABLE) {
		evutil_make_listen_socket_reuseable(fd);
	}

	if (sa) {
		if (bind(fd, sa, socklen)<0) {
			EVUTIL_CLOSESOCKET(fd);
			return NULL;
		}
	}

	return evconnlistener_new(base, cb, ptr, flags, backlog, fd);
}

void
evconnlistener_free(struct evconnlistener *lev)
{
	event_del(&lev->listener);
	if (lev->flags & LEV_OPT_CLOSE_ON_FREE)
		EVUTIL_CLOSESOCKET(event_get_fd(&lev->listener));
	mm_free(lev);
}

int
evconnlistener_enable(struct evconnlistener *lev)
{
	return event_add(&lev->listener, NULL);
}

int
evconnlistener_disable(struct evconnlistener *lev)
{
	return event_del(&lev->listener);
}

struct event_base *
evconnlistener_get_base(struct evconnlistener *lev)
{
	return event_get_base(&lev->listener);
}

static void
listener_read_cb(evutil_socket_t fd, short what, void *p)
{
	struct evconnlistener *lev = p;
	int err;
	while (1) {
		struct sockaddr_storage ss;
		socklen_t socklen = sizeof(ss);

		evutil_socket_t new_fd = accept(fd, (struct sockaddr*)&ss, &socklen);
		if (new_fd < 0)
			break;

		if (!(lev->flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
			evutil_make_socket_nonblocking(new_fd);

		lev->cb(lev, new_fd, (struct sockaddr*)&ss, (int)socklen,
		    lev->user_data);
	}
	err = evutil_socket_geterror(fd);
	if (EVUTIL_ERR_ACCEPT_RETRIABLE(err))
		return;
	event_sock_warn(fd, "Error from accept() call");
}
