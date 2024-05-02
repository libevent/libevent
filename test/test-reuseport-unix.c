/*
 * Copyright (c) 2024 Andy Pan <i@andypan.me>
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

#include "../util-internal.h"

#include <string.h>
#include <stdio.h>
#ifdef _WIN32
#ifdef EVENT__HAVE_AFUNIX_H
#include <afunix.h>
#endif
#include <tchar.h>
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#include <sys/un.h>
#endif
#ifdef EVENT__HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <event2/listener.h>

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *sa, int socklen, void *user_data)
{
	printf("Empty listener, do nothing about it!\n");
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct sockaddr_un addr;

#ifdef _WIN32
	DWORD n;
	TCHAR tempPath[MAX_PATH];
	TCHAR longTempPath[MAX_PATH];
	WSADATA wsaData;
	int r;
	/* Initialize Winsock. */
	r = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (r) {
		fprintf(stderr, "WSAStartup failed with error: %d\n", r);
		return 1;
	}
#ifdef EVENT__HAVE_AFUNIX_H
	if (evutil_check_working_afunix_() == 0)
		return 0; /* AF_UNIX is not available on the current Windows platform, just mark this test as success. */
#endif
	n = GetTempPathW(MAX_PATH, tempPath);
	if (n == 0 || n < MAX_PATH)
		return 1;
	n = GetLongPathNameW(tempPath, longTempPath, MAX_PATH);
	if (n == 0 || n >= MAX_PATH)
		return 1;
	TCHAR socket_path[MAX_PATH];
	_stprintf(socket_path, _T("%stest-reuseport-unix.sock"), longTempPath);
	/* For security reason, we must delete any existing sockets in the filesystem. */
	DeleteFileW(socket_path);
#else
	char socket_path[] = "/tmp/test-reuseport-unix.sock";
	/* For security reason, we must delete any existing sockets in the filesystem. */
	unlink(socket_path);
#endif

	base = event_base_new();
	if (!base) {
		fprintf(stderr, "Could not initialize libevent!\n");
		return 1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);

	listener = evconnlistener_new_bind(base, listener_cb, (void *)base,
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
			(struct sockaddr*)&addr, sizeof(addr));

	if (listener) {
		fprintf(stderr, "AF_UNIX listener shouldn't use SO_REUSEADDR!\n");
		evconnlistener_free(listener);
		return 1;
	}

	listener = evconnlistener_new_bind(base, listener_cb, (void *)base,
	    LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1,
			(struct sockaddr*)&addr, sizeof(addr));

	if (listener) {
		fprintf(stderr, "AF_UNIX listener shouldn't use SO_REUSEPORT!\n");
		evconnlistener_free(listener);
		return 1;
	}

	event_base_free(base);
	printf("Tested successfully!\n");
}
