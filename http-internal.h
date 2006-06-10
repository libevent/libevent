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

/* A stupid connection object - maybe make this a bufferevent later */

struct evhttp_connection {
	int fd;
	struct event ev;

	char *address;
	u_short port;
	
	void (*cb)(struct evhttp_connection *, void *);
	void *cb_arg;
};

enum evhttp_request_kind { EVHTTP_REQUEST, EVHTTP_RESPONSE };

struct evhttp_request {
	struct evkeyvalq *input_headers;
	struct evkeyvalq *output_headers;

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

	int fd;

	struct event ev;

	struct evbuffer *buffer;
	int ntoread;

	/* Callback */
	void (*cb)(struct evhttp_request *, void *);
	void *cb_arg;

	void (*save_cb)(struct evhttp_request *, void *);
	void *save_cbarg;
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

void evhttp_get_request(int, struct sockaddr *, socklen_t,
    void (*)(struct evhttp_request *, void *), void *);

/*
 * Starts a connection to the specified address and invokes the callback
 * if everything is fine.
 */
struct evhttp_connection *evhttp_connect(
	const char *address, unsigned short port,
	void (*cb)(struct evhttp_connection *, void *), void *cb_arg);

/* Frees an http connection */
void evhttp_connection_free(struct evhttp_connection *evcon);

int evhttp_make_request(struct evhttp_connection *evcon,
    struct evhttp_request *req,
    enum evhttp_cmd_type type, const char *uri);

int evhttp_hostportfile(char *, char **, u_short *, char **);

int evhttp_parse_lines(struct evhttp_request *, struct evbuffer*);

void evhttp_start_read(struct evhttp_request *);
void evhttp_read_header(int, short, void *);
void evhttp_make_header(struct evbuffer *, struct evhttp_request *);

void evhttp_form_response(struct evbuffer *, struct evhttp_request *);
void evhttp_write_buffer(struct evhttp_request *, struct evbuffer *,
    void (*)(struct evhttp_request *, void *), void *);

/* response sending HTML the data in the buffer */
void evhttp_response_code(struct evhttp_request *, int, const char *);
void evhttp_send_page(struct evhttp_request *, struct evbuffer *);
void evhttp_fail(struct evhttp_request *);

#endif /* _HTTP_H */
