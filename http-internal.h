/*
 * Copyright 2001 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This header file contains definitions for dealing with HTTP requests
 * that are internal to libevent.  As user of the library, you should not
 * need to know about these.
 */

#ifndef _HTTP_H_
#define _HTTP_H_

#define HTTP_CONNECT_TIMEOUT	45
#define HTTP_WRITE_TIMEOUT	50
#define HTTP_READ_TIMEOUT	50

#define HTTP_PREFIX		"http://"
#define HTTP_DEFAULTPORT	80

struct evbuffer;
struct addrinfo;
struct evhttp_request;

/* A stupid connection object - maybe make this a bufferevent later */

enum evhttp_connection_state {
	EVCON_DISCONNECTED,	/* not currently connected not trying either */
	EVCON_CONNECTING,	/* tries to currently connect */
	EVCON_CONNECTED		/* connection is established */
};

struct evhttp_connection {
	int fd;
	struct event ev;
	struct evbuffer *input_buffer;
	struct evbuffer *output_buffer;
	
	char *address;
	u_short port;

	int flags;
#define EVHTTP_CON_INCOMING	0x0001	/* only one request on it ever */
#define EVHTTP_CON_OUTGOING	0x0002  /* multiple requests possible */
	
	enum evhttp_connection_state state;

	TAILQ_HEAD(evcon_requestq, evhttp_request) requests;
	
	void (*cb)(struct evhttp_connection *, void *);
	void *cb_arg;
};

enum evhttp_request_kind { EVHTTP_REQUEST, EVHTTP_RESPONSE };

struct evhttp_request {
	TAILQ_ENTRY(evhttp_request) next;

	/* the connection object that this request belongs to */
	struct evhttp_connection *evcon;
	int flags;
#define EVHTTP_REQ_OWN_CONNECTION	0x0001	
	
	struct evkeyvalq *input_headers;
	struct evkeyvalq *output_headers;

	/* xxx: do we still need these? */
	char *remote_host;
	u_short remote_port;

	enum evhttp_request_kind kind;
	enum evhttp_cmd_type type;

	char *uri;			/* uri after HTTP request was parsed */

	char major;			/* HTTP Major number */
	char minor;			/* HTTP Minor number */
	
	int got_firstline;
	int response_code;		/* HTTP Response code */
	char *response_code_line;	/* Readable response */

	struct evbuffer *input_buffer;	/* read data */
	int ntoread;

	struct evbuffer *output_buffer;	/* outgoing post or data */

	/* Callback */
	void (*cb)(struct evhttp_request *, void *);
	void *cb_arg;
};

struct evhttp_cb {
	TAILQ_ENTRY(evhttp_cb) next;

	char *what;

	void (*cb)(struct evhttp_request *req, void *);
	void *cbarg;
};

struct evhttp {
	struct event bind_ev;

	TAILQ_HEAD(httpcbq, evhttp_cb) callbacks;

	void (*gencb)(struct evhttp_request *req, void *);
	void *gencbarg;
};

/* resets the connection; can be reused for more requests */
void evhttp_connection_reset(struct evhttp_connection *);

/* connects if necessary */
int evhttp_connection_connect(struct evhttp_connection *);

/* notifies the current request that it failed; resets connection */
void evhttp_connection_fail(struct evhttp_connection *);

void evhttp_get_request(int, struct sockaddr *, socklen_t,
    void (*)(struct evhttp_request *, void *), void *);

int evhttp_hostportfile(char *, char **, u_short *, char **);

int evhttp_parse_lines(struct evhttp_request *, struct evbuffer*);

void evhttp_start_read(struct evhttp_connection *);
void evhttp_read_header(int, short, void *);
void evhttp_make_header(struct evhttp_connection *, struct evhttp_request *);

void evhttp_write_buffer(struct evhttp_connection *,
    void (*)(struct evhttp_connection *, void *), void *);

/* response sending HTML the data in the buffer */
void evhttp_response_code(struct evhttp_request *, int, const char *);
void evhttp_send_page(struct evhttp_request *, struct evbuffer *);

#endif /* _HTTP_H */
