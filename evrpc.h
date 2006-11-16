/*
 * Copyright (c) 2006 Niels Provos <provos@citi.umich.edu>
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
#ifndef _EVRPC_H_
#define _EVRPC_H_

struct evbuffer;
struct evrpc_req_generic;

/* Encapsulates a request */
struct evrpc {
	TAILQ_ENTRY(evrpc) next;

	/* the URI at which the request handler lives */
	const char* uri;

	/* creates a new request structure */
	void *(*request_new)(void);

	/* creates a new request structure */
	void (*request_free)(void *);

	/* unmarshals the buffer into the proper request structure */
	int (*request_unmarshal)(void *, struct evbuffer *);

	/* verifies that the unmarshaled buffer is complete */
	int (*request_complete)(void *);

	/* creates a new reply structure */
	void *(*reply_new)(void);

	/* creates a new reply structure */
	void (*reply_free)(void *);

	/* verifies that the reply is valid */
	int (*reply_complete)(void *);
	
	/* marshals the reply into a buffer */
	void (*reply_marshal)(struct evbuffer*, void *);

	/* the callback invoked for each received rpc */
	void (*cb)(struct evrpc_req_generic *, void *);
	void *cb_arg;
};

#define EVRPC_STRUCT(rpcname) struct evrpc_req__##rpcname

struct evhttp_request;

/* We alias the RPC specific structs to this voided one */
struct evrpc_req_generic {
	/* the unmarshaled request object */
	void *request;

	/* the empty reply object that needs to be filled in */
	void *reply;

	/* 
	 * the static structure for this rpc; that can be used to
	 * automatically unmarshal and marshal the http buffers.
	 */
	struct evrpc* rpc;

	/*
	 * the http request structure on which we need to answer.
	 */
	struct evhttp_request* http_req;

	/*
	 * callback to reply and finish answering this rpc
	 */
	void (*done)(struct evrpc_req_generic* rpc); 
};

#define EVRPC_DEFINE(rpcname, reqstruct, rplystruct) \
EVRPC_STRUCT(rpcname) {	\
	struct reqstruct* request; \
	struct rplystruct* reply; \
	struct evrpc* rpc; \
	void (*done)(struct evrpc* rpc, void *request, void *reply); \
}

/* 
 * EVRPC_REQUEST_DONE is used to answer a request; the reply is expected
 * to have been filled in.  The request and reply pointers become invalid
 * after this call has finished.
 */
#define EVRPC_REQUEST_DONE(rpc_req) do { \
  struct evrpc_req_generic *req = (struct evrpc_req_generic)(rpc_req); \
  req->done(req); \
}
  

/* Takes a request object and fills it in with the right magic */
#define EVRPC_REGISTER_OBJECT(rpc, name, request, reply) \
  do { \
    (rpc)->uri = strdup(name); \
    if ((rpc)->uri == NULL) \
      event_err(1, "failed to register object"); \
    (rpc)->request_new = (void *(*)(void))request##_new; \
    (rpc)->request_free = (void (*)(void *))request##_free; \
    (rpc)->request_unmarshal = (int (*)(void *, struct evbuffer *))request##_unmarshal; \
    (rpc)->request_complete = (int (*)(void *))request##_complete; \
    (rpc)->reply_new = (void *(*)(void))reply##_new; \
    (rpc)->reply_free = (void (*)(void *))reply##_free; \
    (rpc)->reply_complete = (int (*)(void *))reply##_complete; \
    (rpc)->reply_marshal = (void (*)(struct evbuffer*, void *))reply##_marshal; \
  } while(0)

struct evrpc_base;
struct evhttp;

/* functions to start up the rpc system */
struct evrpc_base *evrpc_init(struct evhttp *server);

/* this macro is used to register RPCs with the HTTP Server */
#define EVRPC_REGISTER(base, name, request, reply, callback, cbarg) \
  do { \
    struct evrpc* rpc = calloc(1, sizeof(struct evrpc)); \
    EVRPC_REGISTER_OBJECT(rpc, name, request, reply); \
    evrpc_register_rpc(base, rpc, \
	(void (*)(struct evrpc_req_generic*, void *))callback, cbarg);	\
  } while (0)

int evrpc_register_rpc(struct evrpc_base *, struct evrpc *,
    void (*)(struct evrpc_req_generic*, void *), void *);

#endif /* _EVRPC_H_ */
