/*
 * Copyright 2008 Niels Provos <provos@citi.umich.edu>
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
 * 4. The name of the author may not be used to endorse or promote products
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#endif
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>
#include <evutil.h>
#include <evhttp.h>

static void http_basic_cb(struct evhttp_request *req, void *arg);

static char content[4096];

static void
http_basic_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = evbuffer_new();

	evbuffer_add(evb, content, sizeof(content));

	/* allow sending of an empty reply */
	evhttp_send_reply(req, HTTP_OK, "Everything is fine", evb);

	evbuffer_free(evb);
}

int
main (int argc, char **argv)
{
	struct event_base *base = event_base_new();
	struct evhttp *http = evhttp_new(base);
	struct evhttp *virtual = evhttp_new(base);
	int c;

	unsigned short port = 8080;
	while ((c = getopt(argc, argv, "p:")) != -1) {
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Illegal argument \"%c\"\n", c);
			exit(1);
		}
	}

#ifndef WIN32
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		return (1);
#endif

	evhttp_set_cb(http, "/index.html", http_basic_cb, NULL);
	evhttp_set_cb(virtual, "/index.html", http_basic_cb, NULL);
	evhttp_add_virtual_host(http, "foo.com", virtual);

	evhttp_bind_socket(http, "0.0.0.0", port);

	event_base_dispatch(base);

	/* NOTREACHED */
	return (0);
}
