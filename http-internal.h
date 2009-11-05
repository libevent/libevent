/*
 * Copyright 2001-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2009 Niels Provos and Nick Mathewson
 *
 * This header file contains definitions for dealing with HTTP requests
 * that are internal to libevent.  As user of the library, you should not
 * need to know about these.
 */

#ifndef _HTTP_INTERNAL_H_
#define _HTTP_INTERNAL_H_

#include "event2/event_struct.h"
#include "util-internal.h"

#define HTTP_CONNECT_TIMEOUT	45
#define HTTP_WRITE_TIMEOUT	50
#define HTTP_READ_TIMEOUT	50

#define HTTP_PREFIX		"http://"
#define HTTP_DEFAULTPORT	80

enum message_read_status {
	ALL_DATA_READ = 1,
	MORE_DATA_EXPECTED = 0,
	DATA_CORRUPTED = -1,
	REQUEST_CANCELED = -2,
	DATA_TOO_LONG = -3
};

enum evhttp_connection_error {
	EVCON_HTTP_TIMEOUT,
	EVCON_HTTP_EOF,
	EVCON_HTTP_INVALID_HEADER,
	EVCON_HTTP_BUFFER_ERROR,
	EVCON_HTTP_REQUEST_CANCEL
};

struct evbuffer;
struct addrinfo;
struct evhttp_request;

/* A stupid connection object - maybe make this a bufferevent later */

enum evhttp_connection_state {
	EVCON_DISCONNECTED,	/**< not currently connected not trying either*/
	EVCON_CONNECTING,	/**< tries to currently connect */
	EVCON_IDLE,		/**< connection is established */
	EVCON_READING_FIRSTLINE,/**< reading Request-Line (incoming conn) or
				 **< Status-Line (outgoing conn) */
	EVCON_READING_HEADERS,	/**< reading request/response headers */
	EVCON_READING_BODY,	/**< reading request/response body */
	EVCON_READING_TRAILER,	/**< reading request/response chunked trailer */
	EVCON_WRITING		/**< writing request/response headers/body */
};

struct event_base;

struct evhttp_connection {
	/* we use tailq only if they were created for an http server */
	TAILQ_ENTRY(evhttp_connection) (next);

	evutil_socket_t fd;
	struct bufferevent *bufev;

	struct event retry_ev;		/* for retrying connects */

	char *bind_address;		/* address to use for binding the src */
	u_short bind_port;		/* local port for binding the src */

	char *address;			/* address to connect to */
	u_short port;

	size_t max_headers_size;
	ev_uint64_t max_body_size;

	int flags;
#define EVHTTP_CON_INCOMING	0x0001	/* only one request on it ever */
#define EVHTTP_CON_OUTGOING	0x0002  /* multiple requests possible */
#define EVHTTP_CON_CLOSEDETECT  0x0004  /* detecting if persistent close */

	int timeout;			/* timeout in seconds for events */
	int retry_cnt;			/* retry count */
	int retry_max;			/* maximum number of retries */

	enum evhttp_connection_state state;

	/* for server connections, the http server they are connected with */
	struct evhttp *http_server;

	TAILQ_HEAD(evcon_requestq, evhttp_request) requests;

	void (*cb)(struct evhttp_connection *, void *);
	void *cb_arg;

	void (*closecb)(struct evhttp_connection *, void *);
	void *closecb_arg;

	struct event_base *base;
};

struct evhttp_cb {
	TAILQ_ENTRY(evhttp_cb) next;

	char *what;

	void (*cb)(struct evhttp_request *req, void *);
	void *cbarg;
};

/* both the http server as well as the rpc system need to queue connections */
TAILQ_HEAD(evconq, evhttp_connection);

/* each bound socket is stored in one of these */
struct evhttp_bound_socket {
	TAILQ_ENTRY(evhttp_bound_socket) (next);

	struct event  bind_ev;
};

struct evhttp {
	TAILQ_ENTRY(evhttp) next;

	TAILQ_HEAD(boundq, evhttp_bound_socket) sockets;

	TAILQ_HEAD(httpcbq, evhttp_cb) callbacks;
        struct evconq connections;

	TAILQ_HEAD(vhostsq, evhttp) virtualhosts;

	/* NULL if this server is not a vhost */
        char *vhost_pattern;

	int timeout;

	size_t default_max_headers_size;
	ev_uint64_t default_max_body_size;

	void (*gencb)(struct evhttp_request *req, void *);
	void *gencbarg;

	struct event_base *base;
};

/* resets the connection; can be reused for more requests */
void evhttp_connection_reset(struct evhttp_connection *);

/* connects if necessary */
int evhttp_connection_connect(struct evhttp_connection *);

/* notifies the current request that it failed; resets connection */
void evhttp_connection_fail(struct evhttp_connection *,
    enum evhttp_connection_error error);

void evhttp_get_request(struct evhttp *, evutil_socket_t, struct sockaddr *, ev_socklen_t);

enum message_read_status;

enum message_read_status evhttp_parse_firstline(struct evhttp_request *, struct evbuffer*);
enum message_read_status evhttp_parse_headers(struct evhttp_request *, struct evbuffer*);

void evhttp_start_read(struct evhttp_connection *);
void evhttp_make_header(struct evhttp_connection *, struct evhttp_request *);

void evhttp_write_buffer(struct evhttp_connection *,
    void (*)(struct evhttp_connection *, void *), void *);

/* response sending HTML the data in the buffer */
void evhttp_response_code(struct evhttp_request *, int, const char *);
void evhttp_send_page(struct evhttp_request *, struct evbuffer *);

#endif /* _HTTP_H */
