/*
 * Copyright (c) 2000-2004 Niels Provos <provos@citi.umich.edu>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include "misc.h"
#endif
#include <sys/types.h>
#include <sys/tree.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#else 
#include <sys/_time.h>
#endif
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <assert.h>

#include "event.h"
#include "evrpc.h"
#include "evrpc-internal.h"
#include "evhttp.h"
#include "log.h"

struct evrpc_base *
evrpc_init(struct evhttp *http_server)
{
	struct evrpc_base* base = calloc(1, sizeof(struct evrpc_base));
	if (base == NULL)
		return (NULL);

	/* we rely on the tagging sub system */
	evtag_init();

	TAILQ_INIT(&base->registered_rpcs);
	base->http_server = http_server;

	return (base);
}

void
evrpc_free(struct evrpc_base *base)
{

}

void evrpc_request_cb(struct evhttp_request *, void *);
void evrpc_request_done(struct evrpc_req_generic*);

/*
 * Registers a new RPC with the HTTP server.   The evrpc object is expected
 * to have been filled in via the EVRPC_REGISTER_OBJECT macro which in turn
 * calls this function.
 */

char *
evrpc_construct_uri(const char *uri)
{
	char *constructed_uri;
	int constructed_uri_len;

	constructed_uri_len = strlen(EVRPC_URI_PREFIX) + strlen(uri) + 1;
	if ((constructed_uri = malloc(constructed_uri_len)) == NULL)
		event_err(1, "%s: failed to register rpc at %s",
		    __func__, uri);
	memcpy(constructed_uri, EVRPC_URI_PREFIX, strlen(EVRPC_URI_PREFIX));
	memcpy(constructed_uri + strlen(EVRPC_URI_PREFIX), uri, strlen(uri));
	constructed_uri[constructed_uri_len - 1] = '\0';

	return (constructed_uri);
}

int
evrpc_register_rpc(struct evrpc_base *base, struct evrpc *rpc,
    void (*cb)(struct evrpc_req_generic *, void *), void *cb_arg)
{
	char *constructed_uri = evrpc_construct_uri(rpc->uri);

	rpc->cb = cb;
	rpc->cb_arg = cb_arg;

	TAILQ_INSERT_TAIL(&base->registered_rpcs, rpc, next);

	evhttp_set_cb(base->http_server,
	    constructed_uri,
	    evrpc_request_cb,
	    rpc);
	
	free(constructed_uri);

	return (0);
}

void
evrpc_request_cb(struct evhttp_request *req, void *arg)
{
	struct evrpc *rpc = arg;
	struct evrpc_req_generic *rpc_state = NULL;

	/* let's verify the outside parameters */
	if (req->type != EVHTTP_REQ_POST ||
	    EVBUFFER_LENGTH(req->input_buffer) <= 0)
		goto error;

	rpc_state = calloc(1, sizeof(struct evrpc_req_generic));
	if (rpc_state == NULL)
		goto error;

	/* let's check that we can parse the request */
	rpc_state->request = rpc->request_new();
	if (rpc_state->request == NULL)
		goto error;

	rpc_state->rpc = rpc;

	if (rpc->request_unmarshal(
		    rpc_state->request, req->input_buffer) == -1) {
		/* we failed to parse the request; that's a bummer */
		goto error;
	}

	/* at this point, we have a well formed request, prepare the reply */

	rpc_state->reply = rpc->reply_new();
	if (rpc_state->reply == NULL)
		goto error;

	rpc_state->http_req = req;
	rpc_state->done = evrpc_request_done;

	/* give the rpc to the user; they can deal with it */
	rpc->cb(rpc_state, rpc->cb_arg);

	return;

error:
	evrpc_reqstate_free(rpc_state);
	evhttp_send_error(req, HTTP_SERVUNAVAIL, "Service Error");
	return;
}

void
evrpc_reqstate_free(struct evrpc_req_generic* rpc_state)
{
	/* clean up all memory */
	if (rpc_state != NULL) {
		struct evrpc *rpc = rpc_state->rpc;

		if (rpc_state->request != NULL)
			rpc->request_free(rpc_state->request);
		if (rpc_state->reply != NULL)
			rpc->reply_free(rpc_state->reply);
		free(rpc_state);
	}
}

void
evrpc_request_done(struct evrpc_req_generic* rpc_state)
{
	struct evhttp_request *req = rpc_state->http_req;
	struct evrpc *rpc = rpc_state->rpc;
	struct evbuffer* data;

	if (rpc->reply_complete(rpc_state->reply) == -1) {
		/* the reply was not completely filled in.  error out */
		goto error;
	}

	if ((data = evbuffer_new()) == NULL) {
		/* out of memory */
		goto error;
	}

	/* serialize the reply */
	rpc->reply_marshal(data, rpc_state->reply);

	evhttp_send_reply(req, HTTP_OK, "OK", data);

	evbuffer_free(data);

	evrpc_reqstate_free(rpc_state);

	return;

error:
	evrpc_reqstate_free(rpc_state);
	evhttp_send_error(req, HTTP_SERVUNAVAIL, "Service Error");
	return;
}

/* Client implementation of RPC site */

static int evrpc_schedule_request(struct evhttp_connection *connection,
    struct evrpc_request_wrapper *ctx);

struct evrpc_pool *
evrpc_pool_new()
{
	struct evrpc_pool *pool = calloc(1, sizeof(struct evrpc_pool));
	if (pool == NULL)
		return (NULL);

	TAILQ_INIT(&pool->connections);
	TAILQ_INIT(&pool->requests);

	return (pool);
}

void
evrpc_pool_free(struct evrpc_pool *pool)
{
	struct evhttp_connection *connection;
	struct evrpc_request_wrapper *request;

	while ((request = TAILQ_FIRST(&pool->requests)) != NULL) {
		TAILQ_REMOVE(&pool->requests, request, next);
		/* if this gets more complicated we need our own function */
		free(request->name);
		free(request);
	}

	while ((connection = TAILQ_FIRST(&pool->connections)) != NULL) {
		TAILQ_REMOVE(&pool->connections, connection, next);
		evhttp_connection_free(connection);
	}

	free(pool);
}

void
evrpc_pool_add_connection(struct evrpc_pool *pool,
    struct evhttp_connection *connection) {
	assert(connection->http_server == NULL);
	TAILQ_INSERT_TAIL(&pool->connections, connection, next);

	/* 
	 * if we have any requests, pending schedule them with the new
	 * connections.
	 */

	if (TAILQ_FIRST(&pool->requests) != NULL) {
		struct evrpc_request_wrapper *request = 
		    TAILQ_FIRST(&pool->requests);
		TAILQ_REMOVE(&pool->requests, request, next);
		evrpc_schedule_request(connection, request);
	}
}


static void evrpc_reply_done(struct evhttp_request *, void *);

/*
 * Finds a connection object associated with the pool that is currently
 * idle and can be used to make a request.
 */
static struct evhttp_connection *
evrpc_pool_find_connection(struct evrpc_pool *pool)
{
	struct evhttp_connection *connection;
	TAILQ_FOREACH(connection, &pool->connections, next) {
		if (TAILQ_FIRST(&connection->requests) == NULL)
			return (connection);
	}

	return (NULL);
}

/*
 * We assume that the ctx is no longer queued on the pool.
 */
static int
evrpc_schedule_request(struct evhttp_connection *connection,
    struct evrpc_request_wrapper *ctx)
{
	struct evbuffer *output;
	struct evhttp_request *req;
	if ((output = evbuffer_new()) == NULL)
		goto error;

	if ((req = evhttp_request_new(evrpc_reply_done, ctx)) == NULL)
		goto error;

	return (0);

error:
	(*ctx->cb)(ctx->request, ctx->reply, ctx->cb_arg);
	free(ctx);
	return (-1);
}

int
evrpc_make_request(struct evrpc_request_wrapper *ctx)
{
	struct evrpc_pool *pool = ctx->pool;
	struct evhttp_connection *connection;

	/* we better have some available connections on the pool */
	assert(TAILQ_FIRST(&pool->connections) != NULL);


	/* even if a connection might be available, we do FIFO */
	if (TAILQ_FIRST(&pool->requests) == NULL) {
		connection = evrpc_pool_find_connection(pool);
		if (connection != NULL)
			return evrpc_schedule_request(connection, ctx);
	}

	/* 
	 * if no connection is available, we queue the request on the pool,
	 * the next time a connection is empty, the rpc will be send on that.
	 */
	TAILQ_INSERT_TAIL(&pool->requests, ctx, next);
	return (0);
}

static void
evrpc_reply_done(struct evhttp_request *req, void *arg)
{
	struct evrpc_request_wrapper *ctx = arg;
}
