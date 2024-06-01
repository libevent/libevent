/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
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
#include "util-internal.h"

#ifdef _WIN32
#ifdef EVENT__HAVE_AFUNIX_H
#include <afunix.h>
#endif
#include <io.h>
#include <winsock2.h>
#include <windows.h>
#include <winerror.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#ifdef EVENT__HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <unistd.h>
#endif
#ifdef EVENT__HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "event2/listener.h"
#include "event2/event.h"
#include "event2/util.h"
#ifndef EVENT__DISABLE_THREAD_SUPPORT
#include "event2/thread.h"
#include "regress_thread.h"
#endif

#include "strlcpy-internal.h"
#include "regress.h"
#include "tinytest.h"
#include "tinytest_macros.h"

#ifdef _WIN32
#define unlink _unlink
#define close _close
#endif

static void
acceptcb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	int *ptr = arg;
	--*ptr;
	TT_BLATHER(("Got one for %p", ptr));
	evutil_closesocket(fd);

	if (! *ptr)
		evconnlistener_disable(listener);
}

static void
regress_pick_a_port(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener1 = NULL, *listener2 = NULL;
	struct sockaddr_in sin;
	int count1 = 2, count2 = 1;
	struct sockaddr_storage ss1, ss2;
	struct sockaddr_in *sin1, *sin2;
	ev_socklen_t slen1 = sizeof(ss1), slen2 = sizeof(ss2);
	unsigned int flags =
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC;
	evutil_socket_t fd1, fd2, fd3;

	fd1 = fd2 = fd3 = EVUTIL_INVALID_SOCKET;

	if (data->setup_data && strstr((char*)data->setup_data, "ts")) {
		flags |= LEV_OPT_THREADSAFE;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	sin.sin_port = 0; /* "You pick!" */

	listener1 = evconnlistener_new_bind(base, acceptcb, &count1,
	    flags, -1, (struct sockaddr *)&sin, sizeof(sin));
	tt_assert(listener1);
	listener2 = evconnlistener_new_bind(base, acceptcb, &count2,
	    flags, -1, (struct sockaddr *)&sin, sizeof(sin));
	tt_assert(listener2);

	tt_assert(evconnlistener_get_fd(listener1) != EVUTIL_INVALID_SOCKET);
	tt_assert(evconnlistener_get_fd(listener2) != EVUTIL_INVALID_SOCKET);
	tt_assert(getsockname(evconnlistener_get_fd(listener1),
		(struct sockaddr*)&ss1, &slen1) == 0);
	tt_assert(getsockname(evconnlistener_get_fd(listener2),
		(struct sockaddr*)&ss2, &slen2) == 0);
	tt_int_op(ss1.ss_family, ==, AF_INET);
	tt_int_op(ss2.ss_family, ==, AF_INET);

	sin1 = (struct sockaddr_in*)&ss1;
	sin2 = (struct sockaddr_in*)&ss2;
	tt_int_op(ntohl(sin1->sin_addr.s_addr), ==, 0x7f000001);
	tt_int_op(ntohl(sin2->sin_addr.s_addr), ==, 0x7f000001);
	tt_int_op(sin1->sin_port, !=, sin2->sin_port);

	tt_ptr_op(evconnlistener_get_base(listener1), ==, base);
	tt_ptr_op(evconnlistener_get_base(listener2), ==, base);

	fd1 = fd2 = fd3 = EVUTIL_INVALID_SOCKET;
	evutil_socket_connect_(&fd1, (struct sockaddr*)&ss1, slen1);
	evutil_socket_connect_(&fd2, (struct sockaddr*)&ss1, slen1);
	evutil_socket_connect_(&fd3, (struct sockaddr*)&ss2, slen2);

#ifdef _WIN32
	Sleep(100); /* XXXX this is a stupid stopgap. */
#endif
	event_base_dispatch(base);

	tt_int_op(count1, ==, 0);
	tt_int_op(count2, ==, 0);

end:
	if (fd1>=0)
		EVUTIL_CLOSESOCKET(fd1);
	if (fd2>=0)
		EVUTIL_CLOSESOCKET(fd2);
	if (fd3>=0)
		EVUTIL_CLOSESOCKET(fd3);
	if (listener1)
		evconnlistener_free(listener1);
	if (listener2)
		evconnlistener_free(listener2);
}

static void
errorcb(struct evconnlistener *lis, void *data_)
{
	int *data = data_;
	*data = 1000;
	evconnlistener_disable(lis);
}

static void
regress_listener_error(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	int count = 1;
	unsigned int flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE;

	if (data->setup_data && strstr((char*)data->setup_data, "ts")) {
		flags |= LEV_OPT_THREADSAFE;
	}

	/* send, so that pair[0] will look 'readable'*/
	tt_int_op(send(data->pair[1], "hello", 5, 0), >, 0);

	/* Start a listener with a bogus socket. */
	listener = evconnlistener_new(base, acceptcb, &count,
	    flags, 0,
	    data->pair[0]);
	tt_assert(listener);

	evconnlistener_set_error_cb(listener, errorcb);

	tt_assert(listener);

	event_base_dispatch(base);
	tt_int_op(count,==,1000); /* set by error cb */

end:
	if (listener)
		evconnlistener_free(listener);
}

static void
acceptcb_free(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	int *ptr = arg;
	--*ptr;
	TT_BLATHER(("Got one for %p", ptr));
	evutil_closesocket(fd);

	if (! *ptr)
		evconnlistener_free(listener);
}
static void
regress_listener_close_accepted_fd(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen = sizeof(ss);
	int count = 1;
	unsigned int flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE;
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	sin.sin_port = 0; /* "You pick!" */

	/* Start a listener with a bogus socket. */
	listener = evconnlistener_new_bind(base, acceptcb_free, &count,
	    flags, -1, (struct sockaddr *)&sin, sizeof(sin));
	tt_assert(listener);

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);
	evutil_socket_connect_(&fd, (struct sockaddr*)&ss, slen);

	event_base_dispatch(base);

end:
	;
}

static void
regress_listener_immediate_close(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen = sizeof(ss);
	int count = 1;
	unsigned int flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE;
	evutil_socket_t fd1 = EVUTIL_INVALID_SOCKET, fd2 = EVUTIL_INVALID_SOCKET;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	sin.sin_port = 0; /* "You pick!" */

	/* Start a listener with a bogus socket. */
	listener = evconnlistener_new_bind(base, acceptcb, &count,
	    flags, -1, (struct sockaddr *)&sin, sizeof(sin));
	tt_assert(listener);

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);

	evutil_socket_connect_(&fd1, (struct sockaddr*)&ss, slen);
	evutil_socket_connect_(&fd2, (struct sockaddr*)&ss, slen);

	event_base_dispatch(base);

	tt_int_op(count, ==, 0);

end:
	if (listener)
		evconnlistener_free(listener);
}

#ifdef EVENT__HAVE_SETRLIMIT
static void
regress_listener_error_unlock(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	unsigned int flags =
		LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_THREADSAFE;

	tt_int_op(send(data->pair[1], "hello", 5, 0), >, 0);

	/* Start a listener with a bogus socket. */
	listener = evconnlistener_new(base, acceptcb, NULL, flags, 0, data->pair[0]);
	tt_assert(listener);

	/** accept() must errored out with EMFILE */
	{
		struct rlimit rl;
		rl.rlim_cur = rl.rlim_max = data->pair[1];
		if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
			TT_DIE(("Can't change RLIMIT_NOFILE"));
		}
	}

	event_base_loop(base, EVLOOP_ONCE);

	/** with lock debugging, can fail on lock->count assertion */

end:
	if (listener)
		evconnlistener_free(listener);
}
#endif

#ifndef EVENT__DISABLE_THREAD_SUPPORT

static THREAD_FN
disable_thread(void * arg)
{
	struct evconnlistener *lev = (struct evconnlistener *)arg;
	evconnlistener_disable(lev);
	THREAD_RETURN();
}

static void
acceptcb_for_thread_test(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
	THREAD_T *threadid_arg;
	THREAD_T threadid;
	struct timeval delay = { .tv_sec = 0, .tv_usec = 5000 };

	threadid_arg = (THREAD_T *)arg;

	evutil_closesocket(fd);

	/* We need to run evconnlistener_disable() from disable_thread
	 * in parallel with processing this callback to trigger deadlock regression
	 */
	THREAD_START(threadid, disable_thread, listener);
	evutil_usleep_(&delay);

	*threadid_arg = threadid;
}

static void
regress_listener_disable_in_thread(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	struct sockaddr_in sin;
	struct sockaddr_storage ss;
	ev_socklen_t slen = sizeof(ss);
	evutil_socket_t fd = EVUTIL_INVALID_SOCKET;
	unsigned int flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_THREADSAFE;
	THREAD_T threadid;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	sin.sin_port = 0; /* "You pick!" */


	listener = evconnlistener_new_bind(base, acceptcb_for_thread_test, (void*)(&threadid),
		flags, -1, (struct sockaddr *)&sin, sizeof(sin));

	tt_assert(listener);

	tt_assert(getsockname(evconnlistener_get_fd(listener),
		(struct sockaddr*)&ss, &slen) == 0);

	tt_assert(evutil_socket_connect_(&fd, (struct sockaddr*)&ss, slen) != -1);

	event_base_loop(base, EVLOOP_ONCE);

	THREAD_JOIN(threadid);
end:
	if (listener)
		evconnlistener_free(listener);
}

static void
errorcb_for_thread_test(struct evconnlistener *listener, void *arg)
{
	THREAD_T *threadid_arg;
	THREAD_T threadid;
	struct timeval delay = { .tv_sec = 0, .tv_usec = 5000 };

	threadid_arg = (THREAD_T *)arg;

	/* We need to run evconnlistener_disable() from disable_thread
	 * in parallel with processing this callback to trigger deadlock regression
	 */
	THREAD_START(threadid, disable_thread, listener);
	evutil_usleep_(&delay);

	*threadid_arg = threadid;
}

static void
acceptcb_for_thread_test_error(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *addr, int socklen, void *arg)
{
}

static void
regress_listener_disable_in_thread_error(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	unsigned int flags = LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE|LEV_OPT_THREADSAFE;
	THREAD_T threadid;

	/* send, so that pair[0] will look 'readable'*/
	tt_int_op(send(data->pair[1], "hello", 5, 0), >, 0);

	/* Start a listener with a bogus socket. */
	listener = evconnlistener_new(base, acceptcb_for_thread_test_error, (void*)&threadid,
	    flags, 0,
	    data->pair[0]);
	tt_assert(listener);

	evconnlistener_set_error_cb(listener, errorcb_for_thread_test);

	event_base_loop(base, EVLOOP_ONCE);

	THREAD_JOIN(threadid);
end:
	if (listener)
		evconnlistener_free(listener);
}
#endif

#ifdef EVENT__HAVE_STRUCT_SOCKADDR_UN

#ifdef _WIN32
static int
is_unicode_temp_path()
{
	DWORD n;
	WCHAR short_temp_path[MAX_PATH];
	WCHAR long_temp_path[MAX_PATH];
	n = GetTempPathW(MAX_PATH, short_temp_path);
	if (n == 0 || n > MAX_PATH)
		return 1;
	n = GetLongPathNameW(short_temp_path, long_temp_path, MAX_PATH);
	if (n == 0 || n > MAX_PATH)
		return 1;

	// If it contains valid wide characters, it is considered Unicode.
	for (const wchar_t* p = long_temp_path; *p != L'\0'; ++p) {
		if (*p > 127) { // Non-ASCII character
			return 1; // It's a Unicode path
		}
	}
	return 0; // No non-ASCII characters found, may not be Unicode
}
#endif

static void
empty_listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	printf("Empty listener, do nothing about it!\n");
}

static void
regress_listener_reuseport_on_unix_socket(void *arg)
{
	struct basic_test_data *data = arg;
	struct event_base *base = data->base;
	struct evconnlistener *listener = NULL;
	char *socket_path = NULL;
	int truncated_temp_file = 0;
	struct sockaddr_un addr;
	int tempfd;

	tempfd = regress_make_tmpfile("", 0, &socket_path);
	/* On Windows, if TMP environment variable is corrupted, we may not be
	 * able create temporary file, just skip it */
	if (tempfd < 0)
		tt_skip();
	TT_BLATHER(("Temporary socket path: %s, fd: %i", socket_path, tempfd));

#if defined(_WIN32) && defined(EVENT__HAVE_AFUNIX_H)
	if (evutil_check_working_afunix_() == 0)
		/* AF_UNIX is not available on the current Windows platform,
		 * just skip this test. */
		tt_skip();
#endif

	/* close fd to avoid leaks, since we only need a temporary file path
	 * for bind() to create a socket file. */
	close(tempfd);
	/* For security reason, we must delete any existing sockets in the filesystem.
	 * Besides, we will get EADDRINUSE error if the socket file already exists. */
	unlink(socket_path);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path)) >= sizeof(addr.sun_path))
		/* The temporary path exceeds the system limit, we may need to adjust some subsequent
		 * assertions accordingly to ensure the success of this test. */
		truncated_temp_file = 1;

	listener = evconnlistener_new_bind(base, empty_listener_cb, (void *)base,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
			(struct sockaddr*)&addr, sizeof(addr));
	tt_assert_msg(listener == NULL, "AF_UNIX listener shouldn't use SO_REUSEADDR!");

	listener = evconnlistener_new_bind(base, empty_listener_cb, (void *)base,
	    LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1,
			(struct sockaddr*)&addr, sizeof(addr));
	tt_assert_msg(listener == NULL, "AF_UNIX listener shouldn't use SO_REUSEPORT!");

	/* Create a AF_UNIX listener without reusing address or port. */
	listener = evconnlistener_new_bind(base, empty_listener_cb, (void *)base,
	    LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_CLOSE_ON_FREE, -1,
			(struct sockaddr*)&addr, sizeof(addr));
	if (truncated_temp_file) {
		tt_assert_msg(listener == NULL, "Should not create a AF_UNIX listener with truncated socket path!");
	} else {
#ifdef _WIN32
		if (listener == NULL && WSAENETDOWN == EVUTIL_SOCKET_ERROR() && is_unicode_temp_path())
			/* TODO(panjf2000): this error kept happening on the GitHub Runner of
			 * (windows-latest, UNOCODE_TEMPORARY_DIRECTORY) disturbingly and the
			 * root cause still remains unknown.
			 * Thus, we skip this for now, but try to dive deep and figure out the
			 * root cause later. */
			tt_skip();
#endif
		tt_assert_msg(listener, "Could not create a AF_UNIX listener normally!");
	}

end:
	if (socket_path) {
		unlink(socket_path);
		free(socket_path);
	}
	if (listener)
		evconnlistener_free(listener);
}

#endif

struct testcase_t listener_testcases[] = {

	{ "randport", regress_pick_a_port, TT_FORK|TT_NEED_BASE,
	  &basic_setup, NULL},

	{ "randport_ts", regress_pick_a_port, TT_FORK|TT_NEED_BASE,
	  &basic_setup, (char*)"ts"},

#ifdef EVENT__HAVE_SETRLIMIT
	{ "error_unlock", regress_listener_error_unlock,
	  TT_FORK|TT_NEED_BASE|TT_NEED_SOCKETPAIR|TT_NO_LOGS,
	  &basic_setup, NULL},
#endif

	{ "error", regress_listener_error,
	  TT_FORK|TT_NEED_BASE|TT_NEED_SOCKETPAIR,
	  &basic_setup, NULL},

	{ "error_ts", regress_listener_error,
	  TT_FORK|TT_NEED_BASE|TT_NEED_SOCKETPAIR,
	  &basic_setup, (char*)"ts"},

	{ "close_accepted_fd", regress_listener_close_accepted_fd,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL, },

	{ "immediate_close", regress_listener_immediate_close,
	  TT_FORK|TT_NEED_BASE, &basic_setup, NULL, },

#ifndef EVENT__DISABLE_THREAD_SUPPORT
	{ "disable_in_thread", regress_listener_disable_in_thread,
		TT_FORK|TT_NEED_BASE|TT_NEED_THREADS,
		&basic_setup, NULL, },

	{ "disable_in_thread_error", regress_listener_disable_in_thread_error,
		TT_FORK|TT_NEED_BASE|TT_NEED_THREADS|TT_NEED_SOCKETPAIR,
		&basic_setup, NULL, },
#endif

#ifdef EVENT__HAVE_STRUCT_SOCKADDR_UN
	{ "reuseport_on_unix_socket", regress_listener_reuseport_on_unix_socket,
		TT_FORK|TT_NEED_BASE,
		&basic_setup, NULL, },
#endif

	END_OF_TESTCASES,
};

struct testcase_t listener_iocp_testcases[] = {
	{ "randport", regress_pick_a_port,
	  TT_FORK|TT_NEED_BASE|TT_ENABLE_IOCP,
	  &basic_setup, NULL},

	{ "error", regress_listener_error,
	  TT_FORK|TT_NEED_BASE|TT_NEED_SOCKETPAIR|TT_ENABLE_IOCP,
	  &basic_setup, NULL},

	END_OF_TESTCASES,
};
