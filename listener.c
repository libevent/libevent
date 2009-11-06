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

#include "event-config.h"

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
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
#ifdef WIN32
#include "iocp-internal.h"
#include "defer-internal.h"
#endif

struct evconnlistener_ops {
	int (*enable)(struct evconnlistener *);
	int (*disable)(struct evconnlistener *);
	void (*destroy)(struct evconnlistener *);
	evutil_socket_t (*getfd)(struct evconnlistener *);
	struct event_base *(*getbase)(struct evconnlistener *);
};

struct evconnlistener {
	const struct evconnlistener_ops *ops;
	evconnlistener_cb cb;
	void *user_data;
	unsigned flags;
};

struct evconnlistener_event {
	struct evconnlistener base;
	struct event listener;
};

#ifdef WIN32
struct evconnlistener_iocp {
	struct evconnlistener base;
	evutil_socket_t fd;
	struct event_base *event_base;
	struct event_iocp_port *port;
	CRITICAL_SECTION lock;
	int n_accepting;
	struct accepting_socket **accepting;
};
#endif

struct evconnlistener *
evconnlistener_new_async(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd); /* XXXX export this? */

static int event_listener_enable(struct evconnlistener *);
static int event_listener_disable(struct evconnlistener *);
static void event_listener_destroy(struct evconnlistener *);
static evutil_socket_t event_listener_getfd(struct evconnlistener *);
static struct event_base *event_listener_getbase(struct evconnlistener *);

static const struct evconnlistener_ops evconnlistener_event_ops = {
	event_listener_enable,
	event_listener_disable,
	event_listener_destroy,
	event_listener_getfd,
	event_listener_getbase
};

static void listener_read_cb(evutil_socket_t, short, void *);

struct evconnlistener *
evconnlistener_new(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	struct evconnlistener_event *lev;
#ifdef WIN32
	if (event_base_get_iocp(base)) {
		const struct win32_extension_fns *ext =
		    event_get_win32_extension_fns();
		if (ext->AcceptEx && ext->GetAcceptExSockaddrs)
			return evconnlistener_new_async(base, cb, ptr, flags,
			    backlog, fd);
	}
#endif
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			return NULL;
	}
	lev = mm_calloc(1, sizeof(struct evconnlistener_event));
	if (!lev)
		return NULL;
	lev->base.ops = &evconnlistener_event_ops;
	lev->base.cb = cb;
	lev->base.user_data = ptr;
	lev->base.flags = flags;
	event_assign(&lev->listener, base, fd, EV_READ|EV_PERSIST,
	    listener_read_cb, lev);
	evconnlistener_enable(&lev->base);
	return &lev->base;
}

struct evconnlistener *
evconnlistener_new_bind(struct event_base *base, evconnlistener_cb cb,
    void *ptr, unsigned flags, int backlog, const struct sockaddr *sa,
    int socklen)
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
	lev->ops->destroy(lev);
	mm_free(lev);
}

static void
event_listener_destroy(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	
	event_del(&lev_e->listener);
	if (lev->flags & LEV_OPT_CLOSE_ON_FREE)
		EVUTIL_CLOSESOCKET(event_get_fd(&lev_e->listener));
}

int
evconnlistener_enable(struct evconnlistener *lev)
{
	return lev->ops->enable(lev);
}

int
evconnlistener_disable(struct evconnlistener *lev)
{
	return lev->ops->disable(lev);
}

static int
event_listener_enable(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_add(&lev_e->listener, NULL);
}

static int
event_listener_disable(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_del(&lev_e->listener);
}

evutil_socket_t
evconnlistener_get_fd(struct evconnlistener *lev)
{
	return lev->ops->getfd(lev);
}

static evutil_socket_t
event_listener_getfd(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_fd(&lev_e->listener);
}

struct event_base *
evconnlistener_get_base(struct evconnlistener *lev)
{
	return lev->ops->getbase(lev);
}

static struct event_base *
event_listener_getbase(struct evconnlistener *lev)
{
	struct evconnlistener_event *lev_e =
	    EVUTIL_UPCAST(lev, struct evconnlistener_event, base);
	return event_get_base(&lev_e->listener);
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

#ifdef WIN32
struct accepting_socket {
	CRITICAL_SECTION lock;
	struct event_overlapped overlapped;
	SOCKET s;
	struct deferred_cb deferred;
	struct evconnlistener_iocp *lev;
	ev_uint8_t buflen;
	ev_uint8_t family;
	unsigned free_on_cb:1;
	char addrbuf[1];
};

static void accepted_socket_cb(struct event_overlapped *o, uintptr_t key,
    ev_ssize_t n, int ok);
static void accepted_socket_invoke_user_cb(struct deferred_cb *cb, void *arg);

static struct accepting_socket *
new_accepting_socket(struct evconnlistener_iocp *lev, int family)
{
	struct accepting_socket *res;
	int addrlen;
	int buflen;
	if (family == AF_INET)
		addrlen = sizeof(struct sockaddr_in);
	else if (family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else
		return NULL;
	buflen = (addrlen+16)*2;

	res = mm_calloc(1,sizeof(struct accepting_socket)-1+buflen);

	if (!res)
		return NULL;

	event_overlapped_init(&res->overlapped, accepted_socket_cb);
	res->s = INVALID_SOCKET;
	res->lev = lev;
	res->buflen = buflen;
	res->family = family;

	event_deferred_cb_init(&res->deferred, 
	    accepted_socket_invoke_user_cb, res);

	InitializeCriticalSection(&res->lock);

	return res;
}

static void
free_and_unlock_accepting_socket(struct accepting_socket *as)
{
	/* requires lock. */
	if (as->s != INVALID_SOCKET)
		closesocket(as->s);

	LeaveCriticalSection(&as->lock);
	DeleteCriticalSection(&as->lock);
	mm_free(as);
}

static int
start_accepting(struct accepting_socket *as)
{
	/* requires lock */
	int result = -1;
	const struct win32_extension_fns *ext =
	    event_get_win32_extension_fns();
	SOCKET s = socket(as->family, SOCK_STREAM, 0);
	DWORD pending = 0;
	if (s == INVALID_SOCKET)
		return -1;

	setsockopt(s,
	    SOL_SOCKET,
	    SO_UPDATE_ACCEPT_CONTEXT,
	    (char *)&as->lev->fd,
	    sizeof(&as->lev->fd));

	if (!(as->lev->base.flags & LEV_OPT_LEAVE_SOCKETS_BLOCKING))
		evutil_make_socket_nonblocking(s);

	if (event_iocp_port_associate(as->lev->port, s, 1) < 0)
		goto done;

	as->s = s;

	if (ext->AcceptEx(as->lev->fd, s, as->addrbuf, 0,
		as->buflen/2, as->buflen/2,
		&pending, &as->overlapped.overlapped)) {
		/* Immediate success! */
		accepted_socket_cb(&as->overlapped, 1, 0, 1);
		result = 0;
	} else {
		int err = WSAGetLastError();
		if (err == ERROR_IO_PENDING)
			result = 0;
		else
			event_warnx("AcceptEx: %s",
			    evutil_socket_error_to_string(err));
	}

done:
	return result;
}

static void
stop_accepting(struct accepting_socket *as)
{
	/* requires lock. */
	SOCKET s = as->s;
	as->s = INVALID_SOCKET;
	closesocket(s);
}

static void
accepted_socket_invoke_user_cb(struct deferred_cb *cb, void *arg)
{
	struct accepting_socket *as = arg;

	struct sockaddr *sa_local=NULL, *sa_remote=NULL;
	int socklen_local=0, socklen_remote=0;
	const struct win32_extension_fns *ext =
	    event_get_win32_extension_fns();

	EVUTIL_ASSERT(ext->GetAcceptExSockaddrs);

	EnterCriticalSection(&as->lock);
	if (as->free_on_cb) {
		free_and_unlock_accepting_socket(as);
		return;
	}

	ext->GetAcceptExSockaddrs(as->addrbuf, 0,
	    as->buflen/2, as->buflen/2,
	    &sa_local, &socklen_local,
	    &sa_remote, &socklen_remote);

	as->lev->base.cb(&as->lev->base, as->s, sa_remote,
	    socklen_remote, as->lev->base.user_data);

	as->s = INVALID_SOCKET;

	start_accepting(as);/*XXX handle error */
	LeaveCriticalSection(&as->lock);
}

static void
accepted_socket_cb(struct event_overlapped *o, uintptr_t key, ev_ssize_t n, int ok)
{
	struct accepting_socket *as =
	    EVUTIL_UPCAST(o, struct accepting_socket, overlapped);

	EnterCriticalSection(&as->lock);
	if (ok) {
		/* XXXX Don't do this if some EV_MT flag is set. */
		event_deferred_cb_schedule(
			event_base_get_deferred_cb_queue(as->lev->event_base),
			&as->deferred);
		LeaveCriticalSection(&as->lock);
	} else if (as->free_on_cb) {
		free_and_unlock_accepting_socket(as);
	} else if (as->s == INVALID_SOCKET) {
		/* This is okay; we were disabled by iocp_listener_disable. */
		LeaveCriticalSection(&as->lock);
	} else {
		/* Some error on accept that we couldn't actually handle. */
		event_sock_warn(as->s, "Unexpected error on AcceptEx");
		LeaveCriticalSection(&as->lock);
		/* XXXX recover better. */
	}
}

static int
iocp_listener_enable(struct evconnlistener *lev)
{
	int i;
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);

	EnterCriticalSection(&lev_iocp->lock);
	for (i = 0; i < lev_iocp->n_accepting; ++i) {
		struct accepting_socket *as = lev_iocp->accepting[i];
		if (!as)
			continue;
		EnterCriticalSection(&as->lock);
		if (!as->free_on_cb && as->s == INVALID_SOCKET)
			start_accepting(as); /* detect failure. */
		LeaveCriticalSection(&as->lock);
	}
	LeaveCriticalSection(&lev_iocp->lock);
	return 0;
}

static int
iocp_listener_disable_impl(struct evconnlistener *lev, int shutdown)
{
	int i;
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);

	EnterCriticalSection(&lev_iocp->lock);
	for (i = 0; i < lev_iocp->n_accepting; ++i) {
		struct accepting_socket *as = lev_iocp->accepting[i];
		if (!as)
			continue;
		EnterCriticalSection(&as->lock);
		if (!as->free_on_cb && as->s != INVALID_SOCKET) {
			if (shutdown)
				as->free_on_cb = 1;
			stop_accepting(as);
		}
		LeaveCriticalSection(&as->lock);
	}
	LeaveCriticalSection(&lev_iocp->lock);
	return 0;
}

static int
iocp_listener_disable(struct evconnlistener *lev)
{
	return iocp_listener_disable_impl(lev,0);
}
static void
iocp_listener_destroy(struct evconnlistener *lev)
{
	iocp_listener_disable_impl(lev,1);
}

static evutil_socket_t
iocp_listener_getfd(struct evconnlistener *lev)
{
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);
	return lev_iocp->fd;
}
static struct event_base *
iocp_listener_getbase(struct evconnlistener *lev)
{
	struct evconnlistener_iocp *lev_iocp =
	    EVUTIL_UPCAST(lev, struct evconnlistener_iocp, base);
	return lev_iocp->event_base;
}

static const struct evconnlistener_ops evconnlistener_iocp_ops = {
	iocp_listener_enable,
	iocp_listener_disable,
	iocp_listener_destroy,
	iocp_listener_getfd,
	iocp_listener_getbase
};

/* XXX define some way to override this. */
#define N_SOCKETS_PER_LISTENER 4

struct evconnlistener *
evconnlistener_new_async(struct event_base *base,
    evconnlistener_cb cb, void *ptr, unsigned flags, int backlog,
    evutil_socket_t fd)
{
	struct sockaddr_storage ss;
	int socklen = sizeof(ss);
	struct evconnlistener_iocp *lev;
	int i;

	if (!event_base_get_iocp(base))
		return NULL;

	/* XXXX duplicate code */
	if (backlog > 0) {
		if (listen(fd, backlog) < 0)
			return NULL;
	} else if (backlog < 0) {
		if (listen(fd, 128) < 0)
			return NULL;
	}
	if (getsockname(fd, (struct sockaddr*)&ss, &socklen)) {
		event_sock_warn(fd, "getsockname");
		return NULL;
	}
	lev = mm_calloc(1, sizeof(struct evconnlistener_event));
	if (!lev) {
		event_warn("calloc");
		return NULL;
	}
	lev->base.ops = &evconnlistener_iocp_ops;
	lev->base.cb = cb;
	lev->base.user_data = ptr;
	lev->base.flags = flags;

	lev->port = event_base_get_iocp(base);
	lev->fd = fd;
	lev->event_base = base;

	if (event_iocp_port_associate(lev->port, fd, 1) < 0)
		return NULL;

	InitializeCriticalSection(&lev->lock);

	lev->n_accepting = N_SOCKETS_PER_LISTENER;
	lev->accepting = mm_calloc(lev->n_accepting,
	    sizeof(struct accepting_socket *));
	if (!lev->accepting) {
		event_warn("calloc");
		mm_free(lev);
		closesocket(fd);
		return NULL;
	}
	for (i = 0; i < lev->n_accepting; ++i) {
		lev->accepting[i] = new_accepting_socket(lev, ss.ss_family);
		if (!lev->accepting[i]) {
			event_warnx("Couldn't create accepting socket");
			mm_free(lev->accepting);
			/* DeleteCriticalSection on lev->lock XXXX */
			/* XXXX free the other elements. */
			mm_free(lev);
			closesocket(fd);
			return NULL;
		}

		if (start_accepting(lev->accepting[i]) < 0) {
			event_warnx("Couldn't start accepting on socket");
			EnterCriticalSection(&lev->accepting[i]->lock);
			free_and_unlock_accepting_socket(lev->accepting[i]);
			mm_free(lev->accepting);
			mm_free(lev);
			closesocket(fd);
			DeleteCriticalSection(&lev->lock);
			return NULL;
		}
	}

	return &lev->base;
}

#endif
