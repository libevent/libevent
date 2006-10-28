/*
 * Copyright (c) 2002-2006 Niels Provos <provos@citi.umich.edu>
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

#include <sys/param.h>
#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netdb.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>

#undef timeout_pending
#undef timeout_initialized

#include "event.h"
#include "evhttp.h"
#include "log.h"
#include "http-internal.h"

extern int debug;

static int make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t),
    struct addrinfo *);
static int make_socket(int (*)(int, const struct sockaddr *, socklen_t),
    const char *, short);
static void name_from_addr(struct sockaddr *, socklen_t, char **, char **);

void evhttp_write(int, short, void *);

static const char *
html_replace(char ch)
{
	static char buf[2];
	
	switch (ch) {
	case '<':
		return "&lt;";
	case '>':
		return "&gt;";
	case '"':
		return "&quot;";
	case '\'':
		return "&#039;";
	case '&':
		return "&amp;";
	default:
		break;
	}

	/* Echo the character back */
	buf[0] = ch;
	buf[1] = '\0';
	
	return buf;
}

/*
 * Replaces <, >, ", ' and & with &lt;, &gt;, &quot;,
 * &#039; and &amp; correspondingly.
 *
 * The returned string needs to be freed by the caller.
 */

char *
evhttp_htmlescape(const char *html)
{
	int i, new_size = 0;
	char *escaped_html, *p;
	
	for (i = 0; i < strlen(html); ++i)
		new_size += strlen(html_replace(html[i]));

	p = escaped_html = malloc(new_size + 1);
	if (escaped_html == NULL)
		event_err(1, "%s: malloc(%d)", __func__, new_size + 1);
	for (i = 0; i < strlen(html); ++i) {
		const char *replaced = html_replace(html[i]);
		/* this is length checked */
		strcpy(p, replaced);
		p += strlen(replaced);
	}

	*p = '\0';

	return (escaped_html);
}

const char *
evhttp_method(enum evhttp_cmd_type type)
{
	const char *method;

	switch (type) {
	case EVHTTP_REQ_GET:
		method = "GET";
		break;
	case EVHTTP_REQ_POST:
		method = "POST";
		break;
	case EVHTTP_REQ_HEAD:
		method = "HEAD";
		break;
	default:
		method = NULL;
		break;
	}

	return (method);
}

void
evhttp_write_buffer(struct evhttp_connection *evcon,
    void (*cb)(struct evhttp_connection *, void *), void *arg)
{
	struct timeval tv;

	event_debug(("%s: preparing to write buffer\n", __func__));

	/* Set call back */
	evcon->cb = cb;
	evcon->cb_arg = arg;

	/* xxx: maybe check if the event is still pending? */
	event_set(&evcon->ev, evcon->fd, EV_WRITE, evhttp_write, evcon);
	timerclear(&tv);
	tv.tv_sec = HTTP_WRITE_TIMEOUT;
	event_add(&evcon->ev, &tv);
}

/*
 * Create the headers need for an HTTP reply
 */
static void
evhttp_make_header_request(struct evhttp_connection *evcon,
    struct evhttp_request *req)
{
	static char line[1024];
	const char *method;
	
	evhttp_remove_header(req->output_headers, "Accept-Encoding");
	evhttp_remove_header(req->output_headers, "Proxy-Connection");
	evhttp_remove_header(req->output_headers, "Connection");
	evhttp_add_header(req->output_headers, "Connection", "close");
	req->minor = 0;

	/* Generate request line */
	method = evhttp_method(req->type);
	snprintf(line, sizeof(line), "%s %s HTTP/%d.%d\r\n",
	    method, req->uri, req->major, req->minor);
	evbuffer_add(evcon->output_buffer, line, strlen(line));

	/* Add the content length on a post request if missing */
	if (req->type == EVHTTP_REQ_POST &&
	    evhttp_find_header(req->output_headers, "Content-Length") == NULL){
		char size[12];
		snprintf(size, sizeof(size), "%ld",
		    EVBUFFER_LENGTH(req->output_buffer));
		evhttp_add_header(req->output_headers, "Content-Length", size);
	}
}

/*
 * Create the headers needed for an HTTP reply
 */
static void
evhttp_make_header_response(struct evhttp_connection *evcon,
    struct evhttp_request *req)
{
	static char line[1024];
	snprintf(line, sizeof(line), "HTTP/%d.%d %d %s\r\n",
	    req->major, req->minor, req->response_code,
	    req->response_code_line);
	evbuffer_add(evcon->output_buffer, line, strlen(line));

	/* Potentially add headers */
	if (evhttp_find_header(req->output_headers, "Content-Type") == NULL) {
		evhttp_add_header(req->output_headers,
		    "Content-Type", "text/html; charset=ISO-8859-1");
	}
}

void
evhttp_make_header(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	static char line[1024];
	struct evkeyval *header;

	/*
	 * Depending if this is a HTTP request or response, we might need to
	 * add some new headers or remove existing headers.
	 */
	if (req->kind == EVHTTP_REQUEST) {
		evhttp_make_header_request(evcon, req);
	} else {
		evhttp_make_header_response(evcon, req);
	}

	TAILQ_FOREACH(header, req->output_headers, next) {
		snprintf(line, sizeof(line), "%s: %s\r\n",
		    header->key, header->value);
		evbuffer_add(evcon->output_buffer, line, strlen(line));
	}
	evbuffer_add(evcon->output_buffer, "\r\n", 2);

	if (EVBUFFER_LENGTH(req->output_buffer) >= 0) {
		/*
		 * For a request, we add the POST data, for a reply, this
		 * is the regular data.
		 */
		evbuffer_add_buffer(evcon->output_buffer, req->output_buffer);
	}
}

/* Separated host, port and file from URI */

int
evhttp_hostportfile(char *url, char **phost, u_short *pport, char **pfile)
{
	static char host[1024];
	static char file[1024];
	char *p, *p2;
	int len;
	u_short port;

	len = strlen(HTTP_PREFIX);
	if (strncasecmp(url, HTTP_PREFIX, len))
		return (-1);

	url += len;

	/* We might overrun */
	if (strlcpy(host, url, sizeof (host)) >= sizeof(host))
		return (-1);

	p = strchr(host, '/');
	if (p != NULL) {
		*p = '\0';
		p2 = p + 1;
	} else
		p2 = NULL;

	if (pfile != NULL) {
		/* Generate request file */
		if (p2 == NULL)
			p2 = "";
		snprintf(file, sizeof(file), "/%s", p2);
	}

	p = strchr(host, ':');
	if (p != NULL) {
		*p = '\0';
		port = atoi(p + 1);

		if (port == 0)
			return (-1);
	} else
		port = HTTP_DEFAULTPORT;

	if (phost != NULL)
		*phost = host;
	if (pport != NULL)
		*pport = port;
	if (pfile != NULL)
		*pfile = file;

	return (0);
}

void
evhttp_connection_fail(struct evhttp_connection *evcon)
{
	struct evhttp_request* req = TAILQ_FIRST(&evcon->requests);
	assert(req != NULL);
	
	/* reset the connection */
	evhttp_connection_reset(evcon);

	if (req->cb != NULL) {
		/* xxx: maybe we need to pass the request here? */
		(*req->cb)(NULL, req->cb_arg);
	}

	TAILQ_REMOVE(&evcon->requests, req, next);
	evhttp_request_free(req);

	/* xxx: maybe we should fail all requests??? */
	
	/* We are trying the next request that was queued on us */
	if (TAILQ_FIRST(&evcon->requests) != NULL)
		evhttp_connection_connect(evcon);
}

void
evhttp_write(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct timeval tv;
	int n;

	if (what == EV_TIMEOUT) {
		evhttp_connection_fail(evcon);
		return;
	}

	n = evbuffer_write(evcon->output_buffer, fd);
	if (n == -1) {
		event_warn("%s: evbuffer_write", __func__);
		evhttp_connection_fail(evcon);
		return;
	}

	if (n == 0) {
		event_warnx("%s: write nothing\n", __func__);
		evhttp_connection_fail(evcon);
		return;
	}

	if (EVBUFFER_LENGTH(evcon->output_buffer) != 0) {
		timerclear(&tv);
		tv.tv_sec = HTTP_WRITE_TIMEOUT;
		event_add(&evcon->ev, &tv);
		return;
	}

	/* Activate our call back */
	(*evcon->cb)(evcon, evcon->cb_arg);
}

void
evhttp_connection_done(struct evhttp_connection *evcon)
{
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);

	/*
	 * if this is an incoming connection, we need to leave the request
	 * on the connection, so that we can reply to it.
	 */
	if (evcon->flags & EVHTTP_CON_OUTGOING) {
		TAILQ_REMOVE(&evcon->requests, req, next);
		req->evcon = NULL;

		if (TAILQ_FIRST(&evcon->requests) != NULL) {
			/*
			 * We have more requests; reset the connection
			 * and deal with the next request.  xxx: no
			 * persistent connection right now
			 */
			evhttp_connection_connect(evcon);
		}
	}

	/* hand what ever we read over to the request */
	evbuffer_add_buffer(req->input_buffer, evcon->input_buffer);
	
	/* notify the user of the request */
	(*req->cb)(req, req->cb_arg);

	/* if this was an outgoing request, we own and it's done. so free it */
	if (evcon->flags & EVHTTP_CON_OUTGOING) {
		evhttp_request_free(req);
	}
}

/*
 * Reads data into a buffer structure until no more data
 * can be read on the file descriptor or we have read all
 * the data that we wanted to read.
 * Execute callback when done.
 */

void
evhttp_read(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	struct timeval tv;
	int n;

	if (what == EV_TIMEOUT) {
		evhttp_connection_fail(evcon);
		return;
	}

	n = evbuffer_read(req->input_buffer, fd, req->ntoread);
	event_debug(("%s: got %d on %d\n", __func__, n, req->fd));

	if (n == -1) {
		event_warn("%s: evbuffer_read", __func__);
		evhttp_connection_fail(evcon);
		return;
	}

	/* Adjust the amount of data that we have left to read */
	if (req->ntoread > 0)
		req->ntoread -= n;

	if (n == 0 || req->ntoread == 0) {
		evhttp_connection_done(evcon);
		return;
	}
	
	timerclear(&tv);
	tv.tv_sec = HTTP_READ_TIMEOUT;
	event_add(&evcon->ev, &tv);
}

void
evhttp_write_connectioncb(struct evhttp_connection *evcon, void *arg)
{
	/* This is after writing the request to the server */
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	assert(req != NULL);

	/* We are done writing our header and are now expecting the response */
	req->kind = EVHTTP_RESPONSE;

	evhttp_start_read(evcon);
}

/*
 * Clean up a connection object
 */

void
evhttp_connection_free(struct evhttp_connection *evcon)
{
	if (event_initialized(&evcon->ev))
		event_del(&evcon->ev);
	
	if (evcon->fd != -1)
		close(evcon->fd);

	if (evcon->address != NULL)
		free(evcon->address);

	if (evcon->input_buffer != NULL)
		evbuffer_free(evcon->input_buffer);

	if (evcon->output_buffer != NULL)
		evbuffer_free(evcon->output_buffer);

	free(evcon);
}

void
evhttp_request_dispatch(struct evhttp_connection* evcon)
{
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	
	/* this should not usually happy but it's possible */
	if (req == NULL)
		return;

	/* we assume that the connection is connected already */
	assert(evcon->state = EVCON_CONNECTED);

	/* Create the header from the store arguments */
	evhttp_make_header(evcon, req);

	evhttp_write_buffer(evcon, evhttp_write_connectioncb, NULL);
}

/* Reset our connection state */
void
evhttp_connection_reset(struct evhttp_connection *evcon)
{
	if (event_initialized(&evcon->ev))
		event_del(&evcon->ev);

	if (evcon->fd != -1) {
		close(evcon->fd);
		evcon->fd = -1;
	}
	evcon->state = EVCON_DISCONNECTED;
}

/*
 * Call back for asynchronous connection attempt.
 */

void
evhttp_connectioncb(int fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	int error;
	socklen_t errsz = sizeof(error);
		
	if (what == EV_TIMEOUT) {
		event_warnx("%s: connection timeout for \"%s:%d\" on %d\n",
		    __func__, evcon->address, evcon->port, evcon->fd);
		goto cleanup;
	}

	/* Check if the connection completed */
	if (getsockopt(evcon->fd, SOL_SOCKET, SO_ERROR, &error,
		       &errsz) == -1) {
		event_warn("%s: getsockopt for \"%s:%d\" on %d",
		    __func__, evcon->address, evcon->port, evcon->fd);
		goto cleanup;
	}

	if (error) {
		event_warnx("%s: connect failed for \"%s:%d\" on %d: %s\n",
		    __func__, evcon->address, evcon->port, evcon->fd,
		    strerror(error));
		goto cleanup;
	}

	/* We are connected to the server now */
	event_debug(("%s: connected to \"%s:%d\" on %d\n",
			__func__, evcon->address, evcon->port, evcon->fd));

	evcon->state = EVCON_CONNECTED;

	/* try to start requests that have queued up on this connection */
	evhttp_request_dispatch(evcon);
	return;

 cleanup:
	evhttp_connection_reset(evcon);

	/* for now, we just signal all requests by executing their callbacks */
	while (TAILQ_FIRST(&evcon->requests) != NULL) {
		struct evhttp_request *request = TAILQ_FIRST(&evcon->requests);
		TAILQ_REMOVE(&evcon->requests, request, next);
		request->evcon = NULL;

		/* we might want to set an error here */
		request->cb(request, request->cb_arg);
	}
}

/*
 * Check if we got a valid response code.
 */

int
evhttp_valid_response_code(int code)
{
	if (code == 0)
		return (0);

	return (1);
}

/* Parses the status line of a web server */

int
evhttp_parse_response_line(struct evhttp_request *req, char *line)
{
	char *protocol;
	char *number;
	char *readable;

	protocol = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	number = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	readable = line;

	if (strcmp(protocol, "HTTP/1.0") == 0) {
		req->major = 1;
		req->minor = 0;
	} else if (strcmp(protocol, "HTTP/1.1") == 0) {
		req->major = 1;
		req->minor = 1;
	} else {
		event_warnx("%s: bad protocol \"%s\"\n",
		    __func__, protocol);
		return (-1);
	}

	req->response_code = atoi(number);
	if (!evhttp_valid_response_code(req->response_code)) {
		event_warnx("%s: bad response code \"%s\"\n",
		    __func__, number);
		return (-1);
	}

	if ((req->response_code_line = strdup(readable)) == NULL)
		event_err(1, "%s: strdup", __func__);

	return (0);
}

/* Parse the first line of a HTTP request */

int
evhttp_parse_request_line(struct evhttp_request *req, char *line)
{
	char *method;
	char *uri;
	char *version;

	/* Parse the request line */
	method = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	uri = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	version = strsep(&line, " ");
	if (line != NULL)
		return (-1);

	/* First line */
	if (strcmp(method, "GET") == 0) {
		req->type = EVHTTP_REQ_GET;
	} else if (strcmp(method, "POST") == 0) {
		req->type = EVHTTP_REQ_POST;
	} else if (strcmp(method, "HEAD") == 0) {
		req->type = EVHTTP_REQ_HEAD;
	} else {
		event_warnx("%s: bad method %s on request %p\n",
		    __func__, method, req);
		return (-1);
	}

	if (strcmp(version, "HTTP/1.0") == 0) {
		req->major = 1;
		req->minor = 0;
	} else if (strcmp(version, "HTTP/1.1") == 0) {
		req->major = 1;
		req->minor = 1;
	} else {
		event_warnx("%s: bad version %s on request %p\n",
		    __func__, version, req);
		return (-1);
	}

	if ((req->uri = strdup(uri)) == NULL) {
		event_warn("%s: strdup", __func__);
		return (-1);
	}

	return (0);
}

const char *
evhttp_find_header(struct evkeyvalq *headers, const char *key)
{
	struct evkeyval *header;

	TAILQ_FOREACH(header, headers, next) {
		if (strcasecmp(header->key, key) == 0)
			return (header->value);
	}

	return (NULL);
}

void
evhttp_clear_headers(struct evkeyvalq *headers)
{
	struct evkeyval *header;

	for (header = TAILQ_FIRST(headers);
	    header != NULL;
	    header = TAILQ_FIRST(headers)) {
		TAILQ_REMOVE(headers, header, next);
		free(header->key);
		free(header->value);
		free(header);
	}
}

/*
 * Returns 0,  if the header was successfully removed.
 * Returns -1, if the header could not be found.
 */

int
evhttp_remove_header(struct evkeyvalq *headers, const char *key)
{
	struct evkeyval *header;

	TAILQ_FOREACH(header, headers, next) {
		if (strcasecmp(header->key, key) == 0)
			break;
	}

	if (header == NULL)
		return (-1);

	/* Free and remove the header that we found */
	TAILQ_REMOVE(headers, header, next);
	free(header->key);
	free(header->value);
	free(header);

	return (0);
}

int
evhttp_add_header(struct evkeyvalq *headers, const char *key, const char *value)
{
	struct evkeyval *header;

	header = calloc(1, sizeof(struct evkeyval));
	if (header == NULL) {
		event_warn("%s: calloc", __func__);
		return (-1);
	}
	if ((header->key = strdup(key)) == NULL) {
		free(header);
		event_warn("%s: strdup", __func__);
		return (-1);
	}
	if ((header->value = strdup(value)) == NULL) {
		free(header->key);
		free(header);
		event_warn("%s: strdup", __func__);
		return (-1);
	}

	TAILQ_INSERT_TAIL(headers, header, next);

	return (0);
}

/*
 * Parses header lines from a request or a response into the specified
 * request object given an event buffer.
 *
 * Returns
 *   -1  on error
 *    0  when we need to read more headers
 *    1  when all headers have been read.
 */

int
evhttp_parse_lines(struct evhttp_request *req, struct evbuffer* buffer)
{
	u_char *endp;
	int done = 0;

	struct evkeyvalq* headers = req->input_headers;
	while ((endp = evbuffer_find(buffer, "\r\n", 2)) != NULL) {
		char *skey, *svalue;

		if (strncmp(EVBUFFER_DATA(buffer), "\r\n", 2) == 0) {
			evbuffer_drain(buffer, 2);
			/* Last header - Done */
			done = 1;
			break;
		}

		*endp = '\0';
		endp += 2;

		event_debug(("%s: Got: %s\n", __func__, EVBUFFER_DATA(buffer)));

		/* Processing of header lines */
		if (req->got_firstline == 0) {
			switch (req->kind) {
			case EVHTTP_REQUEST:
				if (evhttp_parse_request_line(req, EVBUFFER_DATA(buffer)) == -1)
					return (-1);
				break;
			case EVHTTP_RESPONSE:
				if (evhttp_parse_response_line(req, EVBUFFER_DATA(buffer)) == -1)
					return (-1);
				break;
			default:
				return (-1);
			}
			req->got_firstline = 1;
		} else {
			/* Regular header */
			svalue = EVBUFFER_DATA(buffer);
			skey = strsep(&svalue, ":");
			if (svalue == NULL)
				return (-1);

			svalue += strspn(svalue, " ");

			if (evhttp_add_header(headers, skey, svalue) == -1)
				return (-1);
		}

		/* Move the uncompleted headers forward */
		evbuffer_drain(buffer, endp - EVBUFFER_DATA(buffer));
	}

	return (done);
}

void
evhttp_get_body(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	struct timeval tv;
	const char *content_length;
	const char *connection;
	struct evkeyvalq *headers = req->input_headers;
	
	/* If this is a request without a body, then we are done */
	if (req->kind == EVHTTP_REQUEST && req->type != EVHTTP_REQ_POST) {
		evhttp_connection_done(evcon);
		return;
	}

	content_length = evhttp_find_header(headers, "Content-Length");
	connection = evhttp_find_header(headers, "Connection");

	if (content_length == NULL && connection == NULL)
		req->ntoread = -1;
	else if (content_length == NULL &&
	    strcasecmp(connection, "Close") != 0) {
		/* Bad combination, we don't know when it will end */
		event_warnx("%s: we got no content length, but the server"
		    " wants to keep the connection open: %s.\n",
		    __func__, connection);
		evhttp_connection_fail(evcon);
		return;
	} else if (content_length == NULL)
		req->ntoread = -1;
	else
		req->ntoread = atoi(content_length);

	event_debug(("%s: bytes to read: %d (in buffer %d)\n",
			__func__, req->ntoread, EVBUFFER_LENGTH(evcon->buffer)));
	
	if (req->ntoread > 0)
		req->ntoread -= EVBUFFER_LENGTH(evcon->input_buffer);

	if (req->ntoread == 0) {
		evhttp_connection_done(evcon);
		return;
	}

	event_set(&evcon->ev, evcon->fd, EV_READ, evhttp_read, evcon);
	timerclear(&tv);
	tv.tv_sec = HTTP_READ_TIMEOUT;
	event_add(&evcon->ev, &tv);
	return;
}

void
evhttp_read_header(int fd, short what, void *arg)
{
	struct timeval tv;
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	int n, res;

	if (what == EV_TIMEOUT) {
		event_warnx("%s: timeout on %d\n", __func__, fd);
		evhttp_connection_fail(evcon);
		return;
	}

	n = evbuffer_read(evcon->input_buffer, fd, -1);
	if (n == 0) {
		event_warnx("%s: no more data on %d\n", __func__, fd);
		evhttp_connection_fail(evcon);
		return;
	}
	if (n == -1) {
		event_warnx("%s: bad read on %d\n", __func__, fd);
		evhttp_connection_fail(evcon);
		return;
	}

	res = evhttp_parse_lines(req, evcon->input_buffer);
	if (res == -1) {
		/* Error while reading, terminate */
		event_warnx("%s: bad header lines on %d\n", __func__, fd);
		evhttp_connection_fail(evcon);
		return;
	} else if (res == 0) {
		/* Need more header lines */
		timerclear(&tv);
		tv.tv_sec = HTTP_READ_TIMEOUT;
		event_add(&evcon->ev, &tv);
		return;
	}

	/* Done reading headers, do the real work */
	switch (req->kind) {
	case EVHTTP_REQUEST:
		event_debug(("%s: checking for post data on %d\n",
				__func__, fd));
		evhttp_get_body(evcon, req);
		break;

	case EVHTTP_RESPONSE:
		event_debug(("%s: starting to read body for \"%s\" on %d\n",
				__func__, req->remote_host, fd));
		evhttp_get_body(evcon, req);
		break;

	default:
		event_warnx("%s: bad header on %d\n", __func__, fd);
		evhttp_connection_fail(evcon);
		break;
	}
}

/*
 * Creates a TCP connection to the specified port and executes a callback
 * when finished.  Failure or sucess is indicate by the passed connection
 * object.
 *
 * Although this interface accepts a hostname, it is intended to take
 * only numeric hostnames so that non-blocking DNS resolution can
 * happen elsewhere.
 */

struct evhttp_connection *
evhttp_connection_new(const char *address, unsigned short port)
{
	struct evhttp_connection *evcon = NULL;
	
	event_debug(("Attempting connection to %s:%d\n", address, port));

	if ((evcon = calloc(1, sizeof(struct evhttp_connection))) == NULL) {
		event_warn("%s: calloc failed", __func__);
		goto error;
	}

	evcon->fd = -1;
	evcon->port = port;

	if ((evcon->address = strdup(address)) == NULL) {
		event_warn("%s: strdup failed", __func__);
		goto error;
	}

	if ((evcon->input_buffer = evbuffer_new()) == NULL) {
		event_warn("%s: evbuffer_new failed", __func__);
		goto error;
	}

	if ((evcon->output_buffer = evbuffer_new()) == NULL) {
		event_warn("%s: evbuffer_new failed", __func__);
		goto error;
	}
	
	evcon->state = EVCON_DISCONNECTED;
	TAILQ_INIT(&evcon->requests);

	return (evcon);
	
 error:
	if (evcon != NULL)
		evhttp_connection_free(evcon);
	return (NULL);
}

int
evhttp_connection_connect(struct evhttp_connection *evcon)
{
	struct timeval tv;
	
	if (evcon->state == EVCON_CONNECTING)
		return (0);
	
	evhttp_connection_reset(evcon);

	assert(!(evcon->flags & EVHTTP_CON_INCOMING));
	evcon->flags |= EVHTTP_CON_OUTGOING;
	
	/* Do async connection to HTTP server */
	if ((evcon->fd = make_socket(
		     connect, evcon->address, evcon->port)) == -1) {
		event_warn("%s: failed to connect to \"%s:%d\"",
		    __func__, evcon->address, evcon->port);
		return (-1);
	}

	/* Set up a callback for successful connection setup */
	event_set(&evcon->ev, evcon->fd, EV_WRITE, evhttp_connectioncb, evcon);
	timerclear(&tv);
	tv.tv_sec = HTTP_CONNECT_TIMEOUT;
	event_add(&evcon->ev, &tv);

	evcon->state = EVCON_CONNECTING;
	
	return (0);
}

/*
 * Starts an HTTP request on the provided evhttp_connection object.
 * If the connection object is not connected to the web server already,
 * this will start the connection.
 */

int
evhttp_make_request(struct evhttp_connection *evcon,
    struct evhttp_request *req,
    enum evhttp_cmd_type type, const char *uri)
{
	/* We are making a request */
	req->kind = EVHTTP_REQUEST;
	req->type = type;
	if (req->uri != NULL)
		free(req->uri);
	if ((req->uri = strdup(uri)) == NULL)
		event_err(1, "%s: strdup", __func__);

	/* Set the protocol version if it is not supplied */
	if (!req->major && !req->minor) {
		req->major = 1;
		req->minor = 1;
	}
	
	assert(req->evcon == NULL);
	req->evcon = evcon;
	assert(!(req->flags && EVHTTP_REQ_OWN_CONNECTION));
	
	TAILQ_INSERT_TAIL(&evcon->requests, req, next);

	/* If the connection object is not connected; make it so */
	if (evcon->state != EVCON_CONNECTED)
		return (evhttp_connection_connect(evcon));

	/*
	 * If it's connected already and we are the first in the queue,
	 * then we can dispatch this request immediately.  Otherwise, it
	 * will be dispatched once the pending requests are completed.
	 */
	if (TAILQ_FIRST(&evcon->requests) == req)
		evhttp_request_dispatch(evcon);

	return (0);
}

/*
 * Reads data from file descriptor into request structure
 * Request structure needs to be set up correctly.
 */

void
evhttp_start_read(struct evhttp_connection *evcon)
{
	struct timeval tv;

	/* Set up an event to read the headers */
	if (event_initialized(&evcon->ev))
		event_del(&evcon->ev);
	event_set(&evcon->ev, evcon->fd, EV_READ, evhttp_read_header, evcon);

	timerclear(&tv);
	tv.tv_sec = HTTP_READ_TIMEOUT;
	event_add(&evcon->ev, &tv);
}

void
evhttp_send_done(struct evhttp_connection *evcon, void *arg)
{
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	TAILQ_REMOVE(&evcon->requests, req, next);

	if (req->flags & EVHTTP_REQ_OWN_CONNECTION)
		evhttp_connection_free(evcon);
	
	evhttp_request_free(req);
}

/*
 * Returns an error page.
 */

void
evhttp_send_error(struct evhttp_request *req, int error, const char *reason)
{
	char *fmt = "<HTML><HEAD>\n"
	    "<TITLE>%d %s</TITLE>\n"
	    "</HEAD><BODY>\n"
	    "<H1>Method Not Implemented</H1>\n"
	    "Invalid method in request<P>\n"
	    "</BODY></HTML>\n";

	struct evbuffer *buf = evbuffer_new();

	evhttp_response_code(req, error, reason);

	evbuffer_add_printf(buf, fmt, error, reason);

	evhttp_send_page(req, buf);

	evbuffer_free(buf);
}

/* Requires that headers and response code are already set up */

static __inline void
evhttp_send(struct evhttp_request *req, struct evbuffer *databuf)
{
	struct evhttp_connection *evcon = req->evcon;

	assert(TAILQ_FIRST(&evcon->requests) == req);

	/* xxx: not sure if we really should expost the data buffer this way */
	evbuffer_add_buffer(req->output_buffer, databuf);

	/* Adds headers to the response */
	evhttp_make_header(evcon, req);

	evhttp_write_buffer(evcon, evhttp_send_done, NULL);
}

void
evhttp_send_reply(struct evhttp_request *req, int code, const char *reason,
    struct evbuffer *databuf)
{
	evhttp_response_code(req, code, reason);
	
	evhttp_send(req, databuf);
}

void
evhttp_response_code(struct evhttp_request *req, int code, const char *reason)
{
	req->kind = EVHTTP_RESPONSE;
	req->response_code = code;
	if (req->response_code_line != NULL)
		free(req->response_code_line);
	req->response_code_line = strdup(reason);
}

void
evhttp_send_page(struct evhttp_request *req, struct evbuffer *databuf)
{
	if (req->kind != EVHTTP_RESPONSE)
		evhttp_response_code(req, 200, "OK");

	evhttp_clear_headers(req->output_headers);
	evhttp_add_header(req->output_headers, "Content-Type", "text/html");
	evhttp_add_header(req->output_headers, "Connection", "close");

	evhttp_send(req, databuf);
}

/* 
 * Helper function to parse out arguments in a query.
 * The arguments are separated by key and value.
 */

void
evhttp_parse_query(const char *uri, struct evkeyvalq *headers)
{
	char *line;
	char *argument;
	char *p;

	TAILQ_INIT(headers);

	/* No arguments - we are done */
	if (strchr(uri, '?') == NULL)
		return;

	if ((line = strdup(uri)) == NULL)
		event_err(1, "%s: strdup", __func__);


	argument = line;

	/* We already know that there has to be a ? */
	strsep(&argument, "?");

	p = argument;
	while (p != NULL && *p != '\0') {
		char *key, *value;
		argument = strsep(&p, "&");

		value = argument;
		key = strsep(&value, "=");
		if (value == NULL)
			goto error;

		event_warnx("Got: %s -> %s\n", key, value);
		evhttp_add_header(headers, key, value);
	}

 error:
	free(line);
}

void
evhttp_handle_request(struct evhttp_request *req, void *arg)
{
	struct evhttp *http = arg;
	struct evhttp_cb *cb;

	/* Test for different URLs */
	TAILQ_FOREACH(cb, &http->callbacks, next) {
		int res;
		char *p = strchr(req->uri, '?');
		if (p == NULL)
			res = strcmp(cb->what, req->uri) == 0;
		else
			res = strncmp(cb->what, req->uri,
			    (size_t)(p - req->uri)) == 0;
		if (res) {
			(*cb->cb)(req, cb->cbarg);
			return;
		}
	}

	/* Generic call back */
	if (http->gencb) {
		(*http->gencb)(req, http->gencbarg);
		return;
	} else {
		/* We need to send a 404 here */
		char *fmt = "<html><head>"
		    "<title>404 Not Found</title>"
		    "</head><body>"
		    "<h1>Not Found</h1>"
		    "<p>The requested URL %s was not found on this server.</p>"
		    "</body></html>\n";

		char *escaped_html = evhttp_htmlescape(req->uri);
		struct evbuffer *buf = evbuffer_new();

		evhttp_response_code(req, HTTP_NOTFOUND, "Not Found");

		evbuffer_add_printf(buf, fmt, escaped_html);

		free(escaped_html);
		
		evhttp_send_page(req, buf);

		evbuffer_free(buf);
	}
}

static void
accept_socket(int fd, short what, void *arg)
{
	struct evhttp *http = arg;
	struct sockaddr_storage ss;
	socklen_t addrlen = sizeof(ss);
	int nfd;

	if ((nfd = accept(fd, (struct sockaddr *)&ss, &addrlen)) == -1) {
		event_warn("%s: bad accept", __func__);
		return;
	}

	evhttp_get_request(nfd, (struct sockaddr *)&ss, addrlen,
	    evhttp_handle_request, http);
}

static int
bind_socket(struct evhttp *http, const char *address, u_short port)
{
	struct event *ev = &http->bind_ev;
	int fd;

	if ((fd = make_socket(bind, address, port)) == -1)
		return (-1);

	if (listen(fd, 10) == -1) {
		event_warn("%s: listen", __func__);
		return (-1);
	}

	/* Schedule the socket for accepting */
	event_set(ev, fd, EV_READ | EV_PERSIST, accept_socket, http);
	event_add(ev, NULL);

	event_debug(("Bound to port %d - Awaiting connections ... ", port));

	return (0);
}

/*
 * Start a web server on the specified address and port.
 */

struct evhttp *
evhttp_start(const char *address, u_short port)
{
	struct evhttp *http;

	if ((http = calloc(1, sizeof(struct evhttp))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (NULL);
	}

	TAILQ_INIT(&http->callbacks);

	if (bind_socket(http, address, port) == -1) {
		free(http);
		return (NULL);
	}

	return (http);
}

void
evhttp_free(struct evhttp* http)
{
	struct evhttp_cb *http_cb;
	int fd = http->bind_ev.ev_fd;

	/* Remove the accepting part */
	event_del(&http->bind_ev);
	close(fd);

	while ((http_cb = TAILQ_FIRST(&http->callbacks)) != NULL) {
		TAILQ_REMOVE(&http->callbacks, http_cb, next);
		free(http_cb->what);
		free(http_cb);
	}
	
	free(http);
}

void
evhttp_set_cb(struct evhttp *http, const char *uri,
    void (*cb)(struct evhttp_request *, void *), void *cbarg)
{
	struct evhttp_cb *http_cb;

	if ((http_cb = calloc(1, sizeof(struct evhttp_cb))) == NULL)
		event_err(1, "%s: calloc", __func__);

	http_cb->what = strdup(uri);
	http_cb->cb = cb;
	http_cb->cbarg = cbarg;

	TAILQ_INSERT_TAIL(&http->callbacks, http_cb, next);
}

void
evhttp_set_gencb(struct evhttp *http,
    void (*cb)(struct evhttp_request *, void *), void *cbarg)
{
	http->gencb = cb;
	http->gencbarg = cbarg;
}

/*
 * Request related functions
 */

struct evhttp_request *
evhttp_request_new(void (*cb)(struct evhttp_request *, void *), void *arg)
{
	struct evhttp_request *req = NULL;

	/* Allocate request structure */
	if ((req = calloc(1, sizeof(struct evhttp_request))) == NULL) {
		event_warn("%s: calloc", __func__);
		goto error;
	}

	req->kind = EVHTTP_RESPONSE;
	req->input_headers = calloc(1, sizeof(struct evkeyvalq));
	if (req->input_headers == NULL) {
		event_warn("%s: calloc", __func__);
		goto error;
	}
	TAILQ_INIT(req->input_headers);

	req->output_headers = calloc(1, sizeof(struct evkeyvalq));
	if (req->output_headers == NULL) {
		event_warn("%s: calloc", __func__);
		goto error;
	}
	TAILQ_INIT(req->output_headers);

	if ((req->input_buffer = evbuffer_new()) == NULL) {
		event_warn("%s: evbuffer_new", __func__);
		goto error;
	}

	if ((req->output_buffer = evbuffer_new()) == NULL) {
		event_warn("%s: evbuffer_new", __func__);
		goto error;
	}

	req->cb = cb;
	req->cb_arg = arg;

	return (req);

 error:
	if (req != NULL)
		evhttp_request_free(req);
	return (NULL);
}

void
evhttp_request_free(struct evhttp_request *req)
{
	if (req->remote_host != NULL)
		free(req->remote_host);
	if (req->uri != NULL)
		free(req->uri);
	if (req->response_code_line != NULL)
		free(req->response_code_line);

	evhttp_clear_headers(req->input_headers);
	free(req->input_headers);

	evhttp_clear_headers(req->output_headers);
	free(req->output_headers);

	if (req->input_buffer != NULL)
		evbuffer_free(req->input_buffer);

	if (req->output_buffer != NULL)
		evbuffer_free(req->output_buffer);

	free(req);
}

/*
 * Allows for inspection of the request URI
 */

const char *
evhttp_request_uri(struct evhttp_request *req) {
	if (req->uri == NULL)
		event_debug(("%s: request %p has no uri\n", req));
	return (req->uri);
}

/*
 * Takes a file descriptor to read a request from.
 * The callback is executed once the whole request has been read.
 */

void
evhttp_get_request(int fd, struct sockaddr *sa, socklen_t salen,
    void (*cb)(struct evhttp_request *, void *), void *arg)
{
	struct evhttp_connection *evcon;
	struct evhttp_request *req;
	char *hostname, *portname;

	name_from_addr(sa, salen, &hostname, &portname);
	event_debug(("%s: new request from %s:%s on %d\n",
			__func__, hostname, portname, fd));

	/* we need a connection object to put the http request on */
	if ((evcon = evhttp_connection_new(hostname, atoi(portname))) == NULL)
		return;
	evcon->flags |= EVHTTP_CON_INCOMING;
	evcon->state = EVCON_CONNECTED;
	
	if ((req = evhttp_request_new(cb, arg)) == NULL) {
		evhttp_connection_free(evcon);
		return;
	}

	evcon->fd = fd;

	req->evcon = evcon;	/* the request ends up owning the connection */
	req->flags |= EVHTTP_REQ_OWN_CONNECTION;
	
	TAILQ_INSERT_TAIL(&evcon->requests, req, next);
	
	req->kind = EVHTTP_REQUEST;
	
	if ((req->remote_host = strdup(hostname)) == NULL)
		event_err(1, "%s: strdup", __func__);
	req->remote_port = atoi(portname);

	evhttp_start_read(evcon);
}


/*
 * Network helper functions that we do not want to export to the rest of
 * the world.
 */

static struct addrinfo *
addr_from_name(char *address)
{
        struct addrinfo ai, *aitop;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = SOCK_RAW;
        ai.ai_flags = 0;
        if (getaddrinfo(address, NULL, &ai, &aitop) != 0) {
                event_warn("getaddrinfo");
                return (NULL);
        }

	return (aitop);
}

static void
name_from_addr(struct sockaddr *sa, socklen_t salen,
    char **phost, char **pport)
{
	static char ntop[NI_MAXHOST];
	static char strport[NI_MAXSERV];

	if (getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV) != 0)
		event_err(1, "getnameinfo failed");

	*phost = ntop;
	*pport = strport;
}

/* Either connect or bind */

static int
make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t),
    struct addrinfo *ai)
{
        struct linger linger;
        int fd, on = 1;
	int serrno;

        /* Create listen socket */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                event_warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
                event_warn("fcntl(O_NONBLOCK)");
                goto out;
        }

        if (fcntl(fd, F_SETFD, 1) == -1) {
                event_warn("fcntl(F_SETFD)");
                goto out;
        }

        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
        linger.l_onoff = 1;
        linger.l_linger = 5;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));

        if ((f)(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		if (errno != EINPROGRESS) {
			goto out;
		}
        }

	return (fd);

 out:
	serrno = errno;
	close(fd);
	errno = serrno;
	return (-1);
}

static int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    const char *address, short port)
{
        struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];
	int fd;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = SOCK_STREAM;
        ai.ai_flags = f != connect ? AI_PASSIVE : 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                event_warn("getaddrinfo");
                return (-1);
        }
        
	fd = make_socket_ai(f, aitop);

	freeaddrinfo(aitop);

	return (fd);
}
