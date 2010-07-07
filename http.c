/*
 * Copyright (c) 2002-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2010 Niels Provos and Nick Mathewson
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

#include "event2/event-config.h"

#ifdef _EVENT_HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCCOM_H
#include <sys/ioccom.h>
#endif

#ifndef WIN32
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <sys/queue.h>

#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _EVENT_HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef WIN32
#include <winsock2.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <syslog.h>
#endif
#include <signal.h>
#include <time.h>
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _EVENT_HAVE_FCNTL_H
#include <fcntl.h>
#endif

#undef timeout_pending
#undef timeout_initialized

#include "strlcpy-internal.h"
#include "event2/http.h"
#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_compat.h"
#include "event2/http_struct.h"
#include "event2/http_compat.h"
#include "event2/util.h"
#include "event2/listener.h"
#include "log-internal.h"
#include "util-internal.h"
#include "http-internal.h"
#include "mm-internal.h"

#ifndef _EVENT_HAVE_GETNAMEINFO
#define NI_MAXSERV 32
#define NI_MAXHOST 1025

#ifndef NI_NUMERICHOST
#define NI_NUMERICHOST 1
#endif

#ifndef NI_NUMERICSERV
#define NI_NUMERICSERV 2
#endif

static int
fake_getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
	size_t hostlen, char *serv, size_t servlen, int flags)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	if (serv != NULL) {
		char tmpserv[16];
		evutil_snprintf(tmpserv, sizeof(tmpserv),
		    "%d", ntohs(sin->sin_port));
		if (strlcpy(serv, tmpserv, servlen) >= servlen)
			return (-1);
	}

	if (host != NULL) {
		if (flags & NI_NUMERICHOST) {
			if (strlcpy(host, inet_ntoa(sin->sin_addr),
			    hostlen) >= hostlen)
				return (-1);
			else
				return (0);
		} else {
			struct hostent *hp;
			hp = gethostbyaddr((char *)&sin->sin_addr,
			    sizeof(struct in_addr), AF_INET);
			if (hp == NULL)
				return (-2);

			if (strlcpy(host, hp->h_name, hostlen) >= hostlen)
				return (-1);
			else
				return (0);
		}
	}
	return (0);
}

#endif

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

extern int debug;

static evutil_socket_t bind_socket_ai(struct evutil_addrinfo *, int reuse);
static evutil_socket_t bind_socket(const char *, ev_uint16_t, int reuse);
static void name_from_addr(struct sockaddr *, ev_socklen_t, char **, char **);
static int evhttp_associate_new_request_with_connection(
	struct evhttp_connection *evcon);
static void evhttp_connection_start_detectclose(
	struct evhttp_connection *evcon);
static void evhttp_connection_stop_detectclose(
	struct evhttp_connection *evcon);
static void evhttp_request_dispatch(struct evhttp_connection* evcon);
static void evhttp_read_firstline(struct evhttp_connection *evcon,
				  struct evhttp_request *req);
static void evhttp_read_header(struct evhttp_connection *evcon,
    struct evhttp_request *req);
static int evhttp_add_header_internal(struct evkeyvalq *headers,
    const char *key, const char *value);
static const char *evhttp_response_phrase_internal(int code);

/* callbacks for bufferevent */
static void evhttp_read_cb(struct bufferevent *, void *);
static void evhttp_write_cb(struct bufferevent *, void *);
static void evhttp_error_cb(struct bufferevent *bufev, short what, void *arg);
static int evhttp_decode_uri_internal(const char *uri, size_t length,
    char *ret, int always_decode_plus);

#ifndef _EVENT_HAVE_STRSEP
/* strsep replacement for platforms that lack it.  Only works if
 * del is one character long. */
static char *
strsep(char **s, const char *del)
{
	char *d, *tok;
	EVUTIL_ASSERT(strlen(del) == 1);
	if (!s || !*s)
		return NULL;
	tok = *s;
	d = strstr(tok, del);
	if (d) {
		*d = '\0';
		*s = d + 1;
	} else
		*s = NULL;
	return tok;
}
#endif

static const char *
html_replace(char ch, char *buf)
{
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
	int i, new_size = 0, old_size = strlen(html);
	char *escaped_html, *p;
	char scratch_space[2];

	for (i = 0; i < old_size; ++i)
		new_size += strlen(html_replace(html[i], scratch_space));

	p = escaped_html = mm_malloc(new_size + 1);
	if (escaped_html == NULL) {
		event_warn("%s: malloc(%d)", __func__, new_size + 1);
		return (NULL);
	}
	for (i = 0; i < old_size; ++i) {
		const char *replaced = html_replace(html[i], scratch_space);
		size_t len = strlen(replaced);
		memcpy(p, replaced, len);
		p += len;
	}

	*p = '\0';

	return (escaped_html);
}

static const char *
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
	case EVHTTP_REQ_PUT:
		method = "PUT";
		break;
	case EVHTTP_REQ_DELETE:
		method = "DELETE";
		break;
	default:
		method = NULL;
		break;
	}

	return (method);
}

/**
 * Determines if a response should have a body.
 * Follows the rules in RFC 2616 section 4.3.
 * @return 1 if the response MUST have a body; 0 if the response MUST NOT have
 *     a body.
 */
static int
evhttp_response_needs_body(struct evhttp_request *req)
{
	return (req->response_code != HTTP_NOCONTENT &&
		req->response_code != HTTP_NOTMODIFIED &&
		(req->response_code < 100 || req->response_code >= 200) &&
		req->type != EVHTTP_REQ_HEAD);
}

static int
evhttp_add_event(struct event *ev, int timeout, int default_timeout)
{
	if (timeout != 0) {
		struct timeval tv;

		evutil_timerclear(&tv);
		tv.tv_sec = timeout != -1 ? timeout : default_timeout;
		return event_add(ev, &tv);
	} else {
		return event_add(ev, NULL);
	}
}

void
evhttp_write_buffer(struct evhttp_connection *evcon,
    void (*cb)(struct evhttp_connection *, void *), void *arg)
{
	event_debug(("%s: preparing to write buffer\n", __func__));

	/* Set call back */
	evcon->cb = cb;
	evcon->cb_arg = arg;

	bufferevent_disable(evcon->bufev, EV_READ);
	bufferevent_enable(evcon->bufev, EV_WRITE);
}

static int
evhttp_connected(struct evhttp_connection *evcon)
{
	switch (evcon->state) {
	case EVCON_DISCONNECTED:
	case EVCON_CONNECTING:
		return (0);
	case EVCON_IDLE:
	case EVCON_READING_FIRSTLINE:
	case EVCON_READING_HEADERS:
	case EVCON_READING_BODY:
	case EVCON_READING_TRAILER:
	case EVCON_WRITING:
	default:
		return (1);
	}
}

/*
 * Create the headers needed for an HTTP request
 */
static void
evhttp_make_header_request(struct evhttp_connection *evcon,
    struct evhttp_request *req)
{
	const char *method;

	evhttp_remove_header(req->output_headers, "Proxy-Connection");

	/* Generate request line */
	method = evhttp_method(req->type);
	evbuffer_add_printf(bufferevent_get_output(evcon->bufev),
	    "%s %s HTTP/%d.%d\r\n",
	    method, req->uri, req->major, req->minor);

	/* Add the content length on a post or put request if missing */
	if ((req->type == EVHTTP_REQ_POST || req->type == EVHTTP_REQ_PUT) &&
	    evhttp_find_header(req->output_headers, "Content-Length") == NULL){
		char size[12];
		evutil_snprintf(size, sizeof(size), "%ld",
		    (long)evbuffer_get_length(req->output_buffer));
		evhttp_add_header(req->output_headers, "Content-Length", size);
	}
}

static int
evhttp_is_connection_close(int flags, struct evkeyvalq* headers)
{
	if (flags & EVHTTP_PROXY_REQUEST) {
		/* proxy connection */
		const char *connection = evhttp_find_header(headers, "Proxy-Connection");
		return (connection == NULL || evutil_ascii_strcasecmp(connection, "keep-alive") != 0);
	} else {
		const char *connection = evhttp_find_header(headers, "Connection");
		return (connection != NULL && evutil_ascii_strcasecmp(connection, "close") == 0);
	}
}

static int
evhttp_is_connection_keepalive(struct evkeyvalq* headers)
{
	const char *connection = evhttp_find_header(headers, "Connection");
	return (connection != NULL
	    && evutil_ascii_strncasecmp(connection, "keep-alive", 10) == 0);
}

static void
evhttp_maybe_add_date_header(struct evkeyvalq *headers)
{
	if (evhttp_find_header(headers, "Date") == NULL) {
		char date[50];
#ifndef WIN32
		struct tm cur;
#endif
		struct tm *cur_p;
		time_t t = time(NULL);
#ifdef WIN32
		cur_p = gmtime(&t);
#else
		gmtime_r(&t, &cur);
		cur_p = &cur;
#endif
		if (strftime(date, sizeof(date),
			"%a, %d %b %Y %H:%M:%S GMT", cur_p) != 0) {
			evhttp_add_header(headers, "Date", date);
		}
	}
}

static void
evhttp_maybe_add_content_length_header(struct evkeyvalq *headers,
    long content_length)
{
	if (evhttp_find_header(headers, "Transfer-Encoding") == NULL &&
	    evhttp_find_header(headers,	"Content-Length") == NULL) {
		char len[12];
		evutil_snprintf(len, sizeof(len), "%ld", content_length);
		evhttp_add_header(headers, "Content-Length", len);
	}
}

/*
 * Create the headers needed for an HTTP reply
 */

static void
evhttp_make_header_response(struct evhttp_connection *evcon,
    struct evhttp_request *req)
{
	int is_keepalive = evhttp_is_connection_keepalive(req->input_headers);
	evbuffer_add_printf(bufferevent_get_output(evcon->bufev),
	    "HTTP/%d.%d %d %s\r\n",
	    req->major, req->minor, req->response_code,
	    req->response_code_line);

	if (req->major == 1) {
		if (req->minor == 1)
			evhttp_maybe_add_date_header(req->output_headers);

		/*
		 * if the protocol is 1.0; and the connection was keep-alive
		 * we need to add a keep-alive header, too.
		 */
		if (req->minor == 0 && is_keepalive)
			evhttp_add_header(req->output_headers,
			    "Connection", "keep-alive");

		if ((req->minor == 1 || is_keepalive) &&
		    evhttp_response_needs_body(req)) {
			/*
			 * we need to add the content length if the
			 * user did not give it, this is required for
			 * persistent connections to work.
			 */
			evhttp_maybe_add_content_length_header(
				req->output_headers,
				(long)evbuffer_get_length(req->output_buffer));
		}
	}

	/* Potentially add headers for unidentified content. */
	if (evhttp_response_needs_body(req)) {
		if (evhttp_find_header(req->output_headers,
			"Content-Type") == NULL) {
			evhttp_add_header(req->output_headers,
			    "Content-Type", "text/html; charset=ISO-8859-1");
		}
	}

	/* if the request asked for a close, we send a close, too */
	if (evhttp_is_connection_close(req->flags, req->input_headers)) {
		evhttp_remove_header(req->output_headers, "Connection");
		if (!(req->flags & EVHTTP_PROXY_REQUEST))
		    evhttp_add_header(req->output_headers, "Connection", "close");
		evhttp_remove_header(req->output_headers, "Proxy-Connection");
	}
}

void
evhttp_make_header(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	struct evkeyval *header;
	struct evbuffer *output = bufferevent_get_output(evcon->bufev);

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
		evbuffer_add_printf(output, "%s: %s\r\n",
		    header->key, header->value);
	}
	evbuffer_add(output, "\r\n", 2);

	if (evbuffer_get_length(req->output_buffer) > 0) {
		/*
		 * For a request, we add the POST data, for a reply, this
		 * is the regular data.
		 */
		evbuffer_add_buffer(output, req->output_buffer);
	}
}

void
evhttp_connection_set_max_headers_size(struct evhttp_connection *evcon,
    ev_ssize_t new_max_headers_size)
{
	if (new_max_headers_size<0)
		evcon->max_headers_size = EV_SIZE_MAX;
	else
		evcon->max_headers_size = new_max_headers_size;
}
void
evhttp_connection_set_max_body_size(struct evhttp_connection* evcon,
    ev_ssize_t new_max_body_size)
{
	if (new_max_body_size<0)
		evcon->max_body_size = EV_UINT64_MAX;
	else
		evcon->max_body_size = new_max_body_size;
}

static int
evhttp_connection_incoming_fail(struct evhttp_request *req,
    enum evhttp_connection_error error)
{
	switch (error) {
	case EVCON_HTTP_TIMEOUT:
	case EVCON_HTTP_EOF:
		/*
		 * these are cases in which we probably should just
		 * close the connection and not send a reply.  this
		 * case may happen when a browser keeps a persistent
		 * connection open and we timeout on the read.  when
		 * the request is still being used for sending, we
		 * need to disassociated it from the connection here.
		 */
		if (!req->userdone) {
			/* remove it so that it will not be freed */
			TAILQ_REMOVE(&req->evcon->requests, req, next);
			/* indicate that this request no longer has a
			 * connection object
			 */
			req->evcon = NULL;
		}
		return (-1);
	case EVCON_HTTP_INVALID_HEADER:
	case EVCON_HTTP_BUFFER_ERROR:
	case EVCON_HTTP_REQUEST_CANCEL:
	default:	/* xxx: probably should just error on default */
		/* the callback looks at the uri to determine errors */
		if (req->uri) {
			mm_free(req->uri);
			req->uri = NULL;
		}

		/*
		 * the callback needs to send a reply, once the reply has
		 * been send, the connection should get freed.
		 */
		(*req->cb)(req, req->cb_arg);
	}

	return (0);
}

void
evhttp_connection_fail(struct evhttp_connection *evcon,
    enum evhttp_connection_error error)
{
	struct evhttp_request* req = TAILQ_FIRST(&evcon->requests);
	void (*cb)(struct evhttp_request *, void *);
	void *cb_arg;
	EVUTIL_ASSERT(req != NULL);

	bufferevent_disable(evcon->bufev, EV_READ|EV_WRITE);

	if (evcon->flags & EVHTTP_CON_INCOMING) {
		/*
		 * for incoming requests, there are two different
		 * failure cases.  it's either a network level error
		 * or an http layer error. for problems on the network
		 * layer like timeouts we just drop the connections.
		 * For HTTP problems, we might have to send back a
		 * reply before the connection can be freed.
		 */
		if (evhttp_connection_incoming_fail(req, error) == -1)
			evhttp_connection_free(evcon);
		return;
	}

	/* when the request was canceled, the callback is not executed */
	if (error != EVCON_HTTP_REQUEST_CANCEL) {
		/* save the callback for later; the cb might free our object */
		cb = req->cb;
		cb_arg = req->cb_arg;
	} else {
		cb = NULL;
		cb_arg = NULL;
	}

	/* do not fail all requests; the next request is going to get
	 * send over a new connection.   when a user cancels a request,
	 * all other pending requests should be processed as normal
	 */
	TAILQ_REMOVE(&evcon->requests, req, next);
	evhttp_request_free(req);

	/* reset the connection */
	evhttp_connection_reset(evcon);

	/* We are trying the next request that was queued on us */
	if (TAILQ_FIRST(&evcon->requests) != NULL)
		evhttp_connection_connect(evcon);

	/* inform the user */
	if (cb != NULL)
		(*cb)(NULL, cb_arg);
}

static void
evhttp_write_cb(struct bufferevent *bufev, void *arg)
{
	struct evhttp_connection *evcon = arg;

	/* Activate our call back */
	if (evcon->cb != NULL)
		(*evcon->cb)(evcon, evcon->cb_arg);
}

/**
 * Advance the connection state.
 * - If this is an outgoing connection, we've just processed the response;
 *   idle or close the connection.
 * - If this is an incoming connection, we've just processed the request;
 *   respond.
 */
static void
evhttp_connection_done(struct evhttp_connection *evcon)
{
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	int con_outgoing = evcon->flags & EVHTTP_CON_OUTGOING;

	if (con_outgoing) {
		/* idle or close the connection */
		int need_close;
		TAILQ_REMOVE(&evcon->requests, req, next);
		req->evcon = NULL;

		evcon->state = EVCON_IDLE;

		need_close =
		    evhttp_is_connection_close(req->flags, req->input_headers)||
		    evhttp_is_connection_close(req->flags, req->output_headers);

		/* check if we got asked to close the connection */
		if (need_close)
			evhttp_connection_reset(evcon);

		if (TAILQ_FIRST(&evcon->requests) != NULL) {
			/*
			 * We have more requests; reset the connection
			 * and deal with the next request.
			 */
			if (!evhttp_connected(evcon))
				evhttp_connection_connect(evcon);
			else
				evhttp_request_dispatch(evcon);
		} else if (!need_close) {
			/*
			 * The connection is going to be persistent, but we
			 * need to detect if the other side closes it.
			 */
			evhttp_connection_start_detectclose(evcon);
		}
	} else {
		/*
		 * incoming connection - we need to leave the request on the
		 * connection so that we can reply to it.
		 */
		evcon->state = EVCON_WRITING;
	}

	/* notify the user of the request */
	(*req->cb)(req, req->cb_arg);

	/* if this was an outgoing request, we own and it's done. so free it.
	 * unless the callback specifically requested to own the request.
	 */
	if (con_outgoing && ((req->flags & EVHTTP_USER_OWNED) == 0)) {
		evhttp_request_free(req);
	}
}

/*
 * Handles reading from a chunked request.
 *   return ALL_DATA_READ:
 *     all data has been read
 *   return MORE_DATA_EXPECTED:
 *     more data is expected
 *   return DATA_CORRUPTED:
 *     data is corrupted
 *   return REQUEST_CANCELED:
 *     request was canceled by the user calling evhttp_cancel_request
 *   return DATA_TOO_LONG:
 *     ran over the maximum limit
 */

static enum message_read_status
evhttp_handle_chunked_read(struct evhttp_request *req, struct evbuffer *buf)
{
	int len;

	while ((len = evbuffer_get_length(buf)) > 0) {
		if (req->ntoread < 0) {
			/* Read chunk size */
			ev_int64_t ntoread;
			char *p = evbuffer_readln(buf, NULL, EVBUFFER_EOL_CRLF);
			char *endp;
			int error;
			if (p == NULL)
				break;
			/* the last chunk is on a new line? */
			if (strlen(p) == 0) {
				mm_free(p);
				continue;
			}
			ntoread = evutil_strtoll(p, &endp, 16);
			error = (*p == '\0' ||
			    (*endp != '\0' && *endp != ' ') ||
			    ntoread < 0);
			mm_free(p);
			if (error) {
				/* could not get chunk size */
				return (DATA_CORRUPTED);
			}
			if (req->body_size + (size_t)ntoread > req->evcon->max_body_size) {
				/* failed body length test */
				event_debug(("Request body is too long"));
				return (DATA_TOO_LONG);
			}
			req->body_size += (size_t)ntoread;
			req->ntoread = ntoread;
			if (req->ntoread == 0) {
				/* Last chunk */
				return (ALL_DATA_READ);
			}
			continue;
		}

		/* don't have enough to complete a chunk; wait for more */
		if (len < req->ntoread)
			return (MORE_DATA_EXPECTED);

		/* Completed chunk */
		/* XXXX fixme: what if req->ntoread is > SIZE_T_MAX? */
		evbuffer_remove_buffer(buf, req->input_buffer, (size_t)req->ntoread);
		req->ntoread = -1;
		if (req->chunk_cb != NULL) {
			req->flags |= EVHTTP_REQ_DEFER_FREE;
			(*req->chunk_cb)(req, req->cb_arg);
			evbuffer_drain(req->input_buffer,
			    evbuffer_get_length(req->input_buffer));
			req->flags &= ~EVHTTP_REQ_DEFER_FREE;
			if ((req->flags & EVHTTP_REQ_NEEDS_FREE) != 0) {
				return (REQUEST_CANCELED);
			}
		}
	}

	return (MORE_DATA_EXPECTED);
}

static void
evhttp_read_trailer(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	struct evbuffer *buf = bufferevent_get_input(evcon->bufev);

	switch (evhttp_parse_headers(req, buf)) {
	case DATA_CORRUPTED:
	case DATA_TOO_LONG:
		evhttp_connection_fail(evcon, EVCON_HTTP_INVALID_HEADER);
		break;
	case ALL_DATA_READ:
		bufferevent_disable(evcon->bufev, EV_READ);
		evhttp_connection_done(evcon);
		break;
	case MORE_DATA_EXPECTED:
	case REQUEST_CANCELED: /* ??? */
	default:
		bufferevent_enable(evcon->bufev, EV_READ);
		break;
	}
}

static void
evhttp_read_body(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	struct evbuffer *buf = bufferevent_get_input(evcon->bufev);

	if (req->chunked) {
		switch (evhttp_handle_chunked_read(req, buf)) {
		case ALL_DATA_READ:
			/* finished last chunk */
			evcon->state = EVCON_READING_TRAILER;
			evhttp_read_trailer(evcon, req);
			return;
		case DATA_CORRUPTED:
		case DATA_TOO_LONG:/*separate error for this? XXX */
			/* corrupted data */
			evhttp_connection_fail(evcon,
			    EVCON_HTTP_INVALID_HEADER);
			return;
		case REQUEST_CANCELED:
			/* request canceled */
			evhttp_request_free(req);
			return;
		case MORE_DATA_EXPECTED:
		default:
			break;
		}
	} else if (req->ntoread < 0) {
		/* Read until connection close. */
		evbuffer_add_buffer(req->input_buffer, buf);
		req->body_size += evbuffer_get_length(buf);
	} else if (req->chunk_cb != NULL ||
	    evbuffer_get_length(buf) >= req->ntoread) {
		/* We've postponed moving the data until now, but we're
		 * about to use it. */
		req->ntoread -= evbuffer_get_length(buf);
		req->body_size += evbuffer_get_length(buf);
		evbuffer_add_buffer(req->input_buffer, buf);
	}

	if (req->body_size > req->evcon->max_body_size) {
		/* failed body length test */
		event_debug(("Request body is too long"));
		evhttp_connection_fail(evcon,
				       EVCON_HTTP_INVALID_HEADER);
		return;
	}

	if (evbuffer_get_length(req->input_buffer) > 0 && req->chunk_cb != NULL) {
		req->flags |= EVHTTP_REQ_DEFER_FREE;
		(*req->chunk_cb)(req, req->cb_arg);
		req->flags &= ~EVHTTP_REQ_DEFER_FREE;
		evbuffer_drain(req->input_buffer,
		    evbuffer_get_length(req->input_buffer));
		if ((req->flags & EVHTTP_REQ_NEEDS_FREE) != 0) {
			evhttp_request_free(req);
			return;
		}
	}

	if (req->ntoread == 0) {
		bufferevent_disable(evcon->bufev, EV_READ);
		/* Completed content length */
		evhttp_connection_done(evcon);
		return;
	}

	/* Read more! */
	bufferevent_enable(evcon->bufev, EV_READ);
}

/*
 * Gets called when more data becomes available
 */

static void
evhttp_read_cb(struct bufferevent *bufev, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);

	switch (evcon->state) {
	case EVCON_READING_FIRSTLINE:
		evhttp_read_firstline(evcon, req);
		/* note the request may have been freed in
		 * evhttp_read_body */
		break;
	case EVCON_READING_HEADERS:
		evhttp_read_header(evcon, req);
		/* note the request may have been freed in
		 * evhttp_read_body */
		break;
	case EVCON_READING_BODY:
		evhttp_read_body(evcon, req);
		/* note the request may have been freed in
		 * evhttp_read_body */
		break;
	case EVCON_READING_TRAILER:
		evhttp_read_trailer(evcon, req);
		break;
	case EVCON_DISCONNECTED:
	case EVCON_CONNECTING:
	case EVCON_IDLE:
	case EVCON_WRITING:
	default:
		event_errx(1, "%s: illegal connection state %d",
			   __func__, evcon->state);
	}
}

static void
evhttp_write_connectioncb(struct evhttp_connection *evcon, void *arg)
{
	/* This is after writing the request to the server */
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	EVUTIL_ASSERT(req != NULL);

	EVUTIL_ASSERT(evcon->state == EVCON_WRITING);

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
	struct evhttp_request *req;

	/* notify interested parties that this connection is going down */
	if (evcon->fd != -1) {
		if (evhttp_connected(evcon) && evcon->closecb != NULL)
			(*evcon->closecb)(evcon, evcon->closecb_arg);
	}

	/* remove all requests that might be queued on this
	 * connection.  for server connections, this should be empty.
	 * because it gets dequeued either in evhttp_connection_done or
	 * evhttp_connection_fail.
	 */
	while ((req = TAILQ_FIRST(&evcon->requests)) != NULL) {
		TAILQ_REMOVE(&evcon->requests, req, next);
		evhttp_request_free(req);
	}

	if (evcon->http_server != NULL) {
		struct evhttp *http = evcon->http_server;
		TAILQ_REMOVE(&http->connections, evcon, next);
	}

	if (event_initialized(&evcon->retry_ev)) {
		event_del(&evcon->retry_ev);
		event_debug_unassign(&evcon->retry_ev);
	}

	if (evcon->bufev != NULL)
		bufferevent_free(evcon->bufev);

	if (evcon->fd != -1)
		evutil_closesocket(evcon->fd);

	if (evcon->bind_address != NULL)
		mm_free(evcon->bind_address);

	if (evcon->address != NULL)
		mm_free(evcon->address);

	mm_free(evcon);
}

void
evhttp_connection_set_local_address(struct evhttp_connection *evcon,
    const char *address)
{
	EVUTIL_ASSERT(evcon->state == EVCON_DISCONNECTED);
	if (evcon->bind_address)
		mm_free(evcon->bind_address);
	if ((evcon->bind_address = mm_strdup(address)) == NULL)
		event_err(1, "%s: strdup", __func__);
}

void
evhttp_connection_set_local_port(struct evhttp_connection *evcon,
    ev_uint16_t port)
{
	EVUTIL_ASSERT(evcon->state == EVCON_DISCONNECTED);
	evcon->bind_port = port;
}

static void
evhttp_request_dispatch(struct evhttp_connection* evcon)
{
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);

	/* this should not usually happy but it's possible */
	if (req == NULL)
		return;

	/* delete possible close detection events */
	evhttp_connection_stop_detectclose(evcon);

	/* we assume that the connection is connected already */
	EVUTIL_ASSERT(evcon->state == EVCON_IDLE);

	evcon->state = EVCON_WRITING;

	/* Create the header from the store arguments */
	evhttp_make_header(evcon, req);

	evhttp_write_buffer(evcon, evhttp_write_connectioncb, NULL);
}

/* Reset our connection state */
void
evhttp_connection_reset(struct evhttp_connection *evcon)
{
	struct evbuffer *tmp;

	bufferevent_disable(evcon->bufev, EV_READ|EV_WRITE);

	if (evcon->fd != -1) {
		/* inform interested parties about connection close */
		if (evhttp_connected(evcon) && evcon->closecb != NULL)
			(*evcon->closecb)(evcon, evcon->closecb_arg);

		evutil_closesocket(evcon->fd);
		evcon->fd = -1;
	}

	/* we need to clean up any buffered data */
	tmp = bufferevent_get_output(evcon->bufev);
	evbuffer_drain(tmp, evbuffer_get_length(tmp));
	tmp = bufferevent_get_input(evcon->bufev);
	evbuffer_drain(tmp, evbuffer_get_length(tmp));

	evcon->state = EVCON_DISCONNECTED;
}

static void
evhttp_connection_start_detectclose(struct evhttp_connection *evcon)
{
	evcon->flags |= EVHTTP_CON_CLOSEDETECT;

	bufferevent_enable(evcon->bufev, EV_READ);
}

static void
evhttp_connection_stop_detectclose(struct evhttp_connection *evcon)
{
	bufferevent_disable(evcon->bufev, EV_READ);
}

static void
evhttp_connection_retry(evutil_socket_t fd, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;

	evcon->state = EVCON_DISCONNECTED;
	evhttp_connection_connect(evcon);
}

static void
evhttp_connection_cb_cleanup(struct evhttp_connection *evcon)
{
	if (evcon->retry_max < 0 || evcon->retry_cnt < evcon->retry_max) {
		evtimer_assign(&evcon->retry_ev, evcon->base, evhttp_connection_retry, evcon);
		/* XXXX handle failure from evhttp_add_event */
		evhttp_add_event(&evcon->retry_ev,
		    MIN(3600, 2 << evcon->retry_cnt),
		    HTTP_CONNECT_TIMEOUT);
		evcon->retry_cnt++;
		return;
	}
	evhttp_connection_reset(evcon);

	/* for now, we just signal all requests by executing their callbacks */
	while (TAILQ_FIRST(&evcon->requests) != NULL) {
		struct evhttp_request *request = TAILQ_FIRST(&evcon->requests);
		TAILQ_REMOVE(&evcon->requests, request, next);
		request->evcon = NULL;

		/* we might want to set an error here */
		request->cb(request, request->cb_arg);
		evhttp_request_free(request);
	}
}

static void
evhttp_error_cb(struct bufferevent *bufev, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);

	switch (evcon->state) {
	case EVCON_CONNECTING:
		if (what == BEV_EVENT_TIMEOUT) {
			event_debug(("%s: connection timeout for \"%s:%d\" on %d",
				__func__, evcon->address, evcon->port,
				evcon->fd));
			evhttp_connection_cb_cleanup(evcon);
			return;
		}
		break;

	case EVCON_READING_BODY:
		if (!req->chunked && req->ntoread < 0
		    && what == (BEV_EVENT_READING|BEV_EVENT_EOF)) {
			/* EOF on read can be benign */
			evhttp_connection_done(evcon);
			return;
		}
		break;

	case EVCON_DISCONNECTED:
	case EVCON_IDLE:
	case EVCON_READING_FIRSTLINE:
	case EVCON_READING_HEADERS:
	case EVCON_READING_TRAILER:
	case EVCON_WRITING:
	default:
		break;
	}

	/* when we are in close detect mode, a read error means that
	 * the other side closed their connection.
	 */
	if (evcon->flags & EVHTTP_CON_CLOSEDETECT) {
		evcon->flags &= ~EVHTTP_CON_CLOSEDETECT;
		EVUTIL_ASSERT(evcon->http_server == NULL);
		/* For connections from the client, we just
		 * reset the connection so that it becomes
		 * disconnected.
		 */
		EVUTIL_ASSERT(evcon->state == EVCON_IDLE);
		evhttp_connection_reset(evcon);
		return;
	}

	if (what & BEV_EVENT_TIMEOUT) {
		evhttp_connection_fail(evcon, EVCON_HTTP_TIMEOUT);
	} else if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		evhttp_connection_fail(evcon, EVCON_HTTP_EOF);
	} else {
		evhttp_connection_fail(evcon, EVCON_HTTP_BUFFER_ERROR);
	}
}

/*
 * Event callback for asynchronous connection attempt.
 */
static void
evhttp_connection_cb(struct bufferevent *bufev, short what, void *arg)
{
	struct evhttp_connection *evcon = arg;
	int error;
	ev_socklen_t errsz = sizeof(error);

	if (!(what & BEV_EVENT_CONNECTED)) {
		/* some operating systems return ECONNREFUSED immediately
		 * when connecting to a local address.  the cleanup is going
		 * to reschedule this function call.
		 */
#ifndef WIN32
		if (errno == ECONNREFUSED)
			goto cleanup;
#endif
		evhttp_error_cb(bufev, what, arg);
		return;
	}

	/* Check if the connection completed */
	if (getsockopt(evcon->fd, SOL_SOCKET, SO_ERROR, (void*)&error,
		       &errsz) == -1) {
		event_debug(("%s: getsockopt for \"%s:%d\" on %d",
			__func__, evcon->address, evcon->port, evcon->fd));
		goto cleanup;
	}

	if (error) {
		event_debug(("%s: connect failed for \"%s:%d\" on %d: %s",
		    __func__, evcon->address, evcon->port, evcon->fd,
			evutil_socket_error_to_string(error)));
		goto cleanup;
	}

	/* We are connected to the server now */
	event_debug(("%s: connected to \"%s:%d\" on %d\n",
			__func__, evcon->address, evcon->port, evcon->fd));

	/* Reset the retry count as we were successful in connecting */
	evcon->retry_cnt = 0;
	evcon->state = EVCON_IDLE;

	/* reset the bufferevent cbs */
	bufferevent_setcb(evcon->bufev,
	    evhttp_read_cb,
	    evhttp_write_cb,
	    evhttp_error_cb,
	    evcon);

	if (evcon->timeout == -1)
		bufferevent_settimeout(evcon->bufev,
		    HTTP_READ_TIMEOUT, HTTP_WRITE_TIMEOUT);
	else {
		struct timeval tv;
		tv.tv_sec = evcon->timeout;
		tv.tv_usec = 0;
		bufferevent_set_timeouts(evcon->bufev, &tv, &tv);
	}

	/* try to start requests that have queued up on this connection */
	evhttp_request_dispatch(evcon);
	return;

 cleanup:
	evhttp_connection_cb_cleanup(evcon);
}

/*
 * Check if we got a valid response code.
 */

static int
evhttp_valid_response_code(int code)
{
	if (code == 0)
		return (0);

	return (1);
}

/* Parses the status line of a web server */

static int
evhttp_parse_response_line(struct evhttp_request *req, char *line)
{
	char *protocol;
	char *number;
	const char *readable = "";

	protocol = strsep(&line, " ");
	if (line == NULL)
		return (-1);
	number = strsep(&line, " ");
	if (line != NULL)
		readable = line;

	if (strcmp(protocol, "HTTP/1.0") == 0) {
		req->major = 1;
		req->minor = 0;
	} else if (strcmp(protocol, "HTTP/1.1") == 0) {
		req->major = 1;
		req->minor = 1;
	} else {
		event_debug(("%s: bad protocol \"%s\"",
			__func__, protocol));
		return (-1);
	}

	req->response_code = atoi(number);
	if (!evhttp_valid_response_code(req->response_code)) {
		event_debug(("%s: bad response code \"%s\"",
			__func__, number));
		return (-1);
	}

	if ((req->response_code_line = mm_strdup(readable)) == NULL) {
		event_warn("%s: strdup", __func__);
		return (-1);
	}

	return (0);
}

/* Parse the first line of a HTTP request */

static int
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
	} else if (strcmp(method, "PUT") == 0) {
		req->type = EVHTTP_REQ_PUT;
	} else if (strcmp(method, "DELETE") == 0) {
		req->type = EVHTTP_REQ_DELETE;
	} else {
		event_debug(("%s: bad method %s on request %p from %s",
			__func__, method, req, req->remote_host));
		return (-1);
	}

	if (strcmp(version, "HTTP/1.0") == 0) {
		req->major = 1;
		req->minor = 0;
	} else if (strcmp(version, "HTTP/1.1") == 0) {
		req->major = 1;
		req->minor = 1;
	} else {
		event_debug(("%s: bad version %s on request %p from %s",
			__func__, version, req, req->remote_host));
		return (-1);
	}

	if ((req->uri = mm_strdup(uri)) == NULL) {
		event_debug(("%s: mm_strdup", __func__));
		return (-1);
	}

	/* determine if it's a proxy request */
	if (strlen(req->uri) > 0 && req->uri[0] != '/')
		req->flags |= EVHTTP_PROXY_REQUEST;

	return (0);
}

const char *
evhttp_find_header(const struct evkeyvalq *headers, const char *key)
{
	struct evkeyval *header;

	TAILQ_FOREACH(header, headers, next) {
		if (evutil_ascii_strcasecmp(header->key, key) == 0)
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
		mm_free(header->key);
		mm_free(header->value);
		mm_free(header);
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
		if (evutil_ascii_strcasecmp(header->key, key) == 0)
			break;
	}

	if (header == NULL)
		return (-1);

	/* Free and remove the header that we found */
	TAILQ_REMOVE(headers, header, next);
	mm_free(header->key);
	mm_free(header->value);
	mm_free(header);

	return (0);
}

static int
evhttp_header_is_valid_value(const char *value)
{
	const char *p = value;

	while ((p = strpbrk(p, "\r\n")) != NULL) {
		/* we really expect only one new line */
		p += strspn(p, "\r\n");
		/* we expect a space or tab for continuation */
		if (*p != ' ' && *p != '\t')
			return (0);
	}
	return (1);
}

int
evhttp_add_header(struct evkeyvalq *headers,
    const char *key, const char *value)
{
	event_debug(("%s: key: %s val: %s\n", __func__, key, value));

	if (strchr(key, '\r') != NULL || strchr(key, '\n') != NULL) {
		/* drop illegal headers */
		event_debug(("%s: dropping illegal header key\n", __func__));
		return (-1);
	}

	if (!evhttp_header_is_valid_value(value)) {
		event_debug(("%s: dropping illegal header value\n", __func__));
		return (-1);
	}

	return (evhttp_add_header_internal(headers, key, value));
}

static int
evhttp_add_header_internal(struct evkeyvalq *headers,
    const char *key, const char *value)
{
	struct evkeyval *header = mm_calloc(1, sizeof(struct evkeyval));
	if (header == NULL) {
		event_warn("%s: calloc", __func__);
		return (-1);
	}
	if ((header->key = mm_strdup(key)) == NULL) {
		mm_free(header);
		event_warn("%s: strdup", __func__);
		return (-1);
	}
	if ((header->value = mm_strdup(value)) == NULL) {
		mm_free(header->key);
		mm_free(header);
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
 *   DATA_CORRUPTED      on error
 *   MORE_DATA_EXPECTED  when we need to read more headers
 *   ALL_DATA_READ       when all headers have been read.
 */

enum message_read_status
evhttp_parse_firstline(struct evhttp_request *req, struct evbuffer *buffer)
{
	char *line;
	enum message_read_status status = ALL_DATA_READ;

	size_t line_length;
	/* XXX try */
	line = evbuffer_readln(buffer, &line_length, EVBUFFER_EOL_CRLF);
	if (line == NULL) {
		if (req->evcon != NULL &&
		    evbuffer_get_length(buffer) > req->evcon->max_headers_size)
			return (DATA_TOO_LONG);
		else
			return (MORE_DATA_EXPECTED);
	}

	if (req->evcon != NULL &&
	    line_length > req->evcon->max_headers_size) {
		mm_free(line);
		return (DATA_TOO_LONG);
	}

	req->headers_size = line_length;

	switch (req->kind) {
	case EVHTTP_REQUEST:
		if (evhttp_parse_request_line(req, line) == -1)
			status = DATA_CORRUPTED;
		break;
	case EVHTTP_RESPONSE:
		if (evhttp_parse_response_line(req, line) == -1)
			status = DATA_CORRUPTED;
		break;
	default:
		status = DATA_CORRUPTED;
	}

	mm_free(line);
	return (status);
}

static int
evhttp_append_to_last_header(struct evkeyvalq *headers, const char *line)
{
	struct evkeyval *header = TAILQ_LAST(headers, evkeyvalq);
	char *newval;
	size_t old_len, line_len;

	if (header == NULL)
		return (-1);

	old_len = strlen(header->value);
	line_len = strlen(line);

	newval = mm_realloc(header->value, old_len + line_len + 1);
	if (newval == NULL)
		return (-1);

	memcpy(newval + old_len, line, line_len + 1);
	header->value = newval;

	return (0);
}

enum message_read_status
evhttp_parse_headers(struct evhttp_request *req, struct evbuffer* buffer)
{
	enum message_read_status errcode = DATA_CORRUPTED;
	char *line;
	enum message_read_status status = MORE_DATA_EXPECTED;

	struct evkeyvalq* headers = req->input_headers;
	size_t line_length;
	while ((line = evbuffer_readln(buffer, &line_length, EVBUFFER_EOL_CRLF))
	       != NULL) {
		char *skey, *svalue;

		req->headers_size += line_length;

		if (req->evcon != NULL &&
		    req->headers_size > req->evcon->max_headers_size) {
			errcode = DATA_TOO_LONG;
			goto error;
		}

		if (*line == '\0') { /* Last header - Done */
			status = ALL_DATA_READ;
			mm_free(line);
			break;
		}

		/* Check if this is a continuation line */
		if (*line == ' ' || *line == '\t') {
			if (evhttp_append_to_last_header(headers, line) == -1)
				goto error;
			mm_free(line);
			continue;
		}

		/* Processing of header lines */
		svalue = line;
		skey = strsep(&svalue, ":");
		if (svalue == NULL)
			goto error;

		svalue += strspn(svalue, " ");

		if (evhttp_add_header(headers, skey, svalue) == -1)
			goto error;

		mm_free(line);
	}

	if (status == MORE_DATA_EXPECTED) {
		if (req->headers_size + evbuffer_get_length(buffer) > req->evcon->max_headers_size)
			return (DATA_TOO_LONG);
	}

	return (status);

 error:
	mm_free(line);
	return (errcode);
}

static int
evhttp_get_body_length(struct evhttp_request *req)
{
	struct evkeyvalq *headers = req->input_headers;
	const char *content_length;
	const char *connection;

	content_length = evhttp_find_header(headers, "Content-Length");
	connection = evhttp_find_header(headers, "Connection");

	if (content_length == NULL && connection == NULL)
		req->ntoread = -1;
	else if (content_length == NULL &&
	    evutil_ascii_strcasecmp(connection, "Close") != 0) {
		/* Bad combination, we don't know when it will end */
		event_warnx("%s: we got no content length, but the "
		    "server wants to keep the connection open: %s.",
		    __func__, connection);
		return (-1);
	} else if (content_length == NULL) {
		req->ntoread = -1;
	} else {
		char *endp;
		ev_int64_t ntoread = evutil_strtoll(content_length, &endp, 10);
		if (*content_length == '\0' || *endp != '\0' || ntoread < 0) {
			event_debug(("%s: illegal content length: %s",
				__func__, content_length));
			return (-1);
		}
		req->ntoread = ntoread;
	}

	event_debug(("%s: bytes to read: %ld (in buffer %ld)\n",
		__func__, (long)req->ntoread,
		evbuffer_get_length(bufferevent_get_input(req->evcon->bufev))));

	return (0);
}

static void
evhttp_get_body(struct evhttp_connection *evcon, struct evhttp_request *req)
{
	const char *xfer_enc;

	/* If this is a request without a body, then we are done */
	if (req->kind == EVHTTP_REQUEST &&
	    (req->type != EVHTTP_REQ_POST && req->type != EVHTTP_REQ_PUT)) {
		evhttp_connection_done(evcon);
		return;
	}
	evcon->state = EVCON_READING_BODY;
	xfer_enc = evhttp_find_header(req->input_headers, "Transfer-Encoding");
	if (xfer_enc != NULL && evutil_ascii_strcasecmp(xfer_enc, "chunked") == 0) {
		req->chunked = 1;
		req->ntoread = -1;
	} else {
		if (evhttp_get_body_length(req) == -1) {
			evhttp_connection_fail(evcon,
			    EVCON_HTTP_INVALID_HEADER);
			return;
		}
	}
	evhttp_read_body(evcon, req);
	/* note the request may have been freed in evhttp_read_body */
}

static void
evhttp_read_firstline(struct evhttp_connection *evcon,
		      struct evhttp_request *req)
{
	enum message_read_status res;

	res = evhttp_parse_firstline(req, bufferevent_get_input(evcon->bufev));
	if (res == DATA_CORRUPTED || res == DATA_TOO_LONG) {
		/* Error while reading, terminate */
		event_debug(("%s: bad header lines on %d\n",
			__func__, evcon->fd));
		evhttp_connection_fail(evcon, EVCON_HTTP_INVALID_HEADER);
		return;
	} else if (res == MORE_DATA_EXPECTED) {
		/* Need more header lines */
		return;
	}

	evcon->state = EVCON_READING_HEADERS;
	evhttp_read_header(evcon, req);
}

static void
evhttp_read_header(struct evhttp_connection *evcon,
		   struct evhttp_request *req)
{
	enum message_read_status res;
	evutil_socket_t fd = evcon->fd;

	res = evhttp_parse_headers(req, bufferevent_get_input(evcon->bufev));
	if (res == DATA_CORRUPTED || res == DATA_TOO_LONG) {
		/* Error while reading, terminate */
		event_debug(("%s: bad header lines on %d\n", __func__, fd));
		evhttp_connection_fail(evcon, EVCON_HTTP_INVALID_HEADER);
		return;
	} else if (res == MORE_DATA_EXPECTED) {
		/* Need more header lines */
		return;
	}

	/* Disable reading for now */
	bufferevent_disable(evcon->bufev, EV_READ);

	/* Done reading headers, do the real work */
	switch (req->kind) {
	case EVHTTP_REQUEST:
		event_debug(("%s: checking for post data on %d\n",
				__func__, fd));
		evhttp_get_body(evcon, req);
		/* note the request may have been freed in evhttp_get_body */
		break;

	case EVHTTP_RESPONSE:
		if (!evhttp_response_needs_body(req)) {
			event_debug(("%s: skipping body for code %d\n",
					__func__, req->response_code));
			evhttp_connection_done(evcon);
		} else {
			event_debug(("%s: start of read body for %s on %d\n",
				__func__, req->remote_host, fd));
			evhttp_get_body(evcon, req);
			/* note the request may have been freed in
			 * evhttp_get_body */
		}
		break;

	default:
		event_warnx("%s: bad header on %d", __func__, fd);
		evhttp_connection_fail(evcon, EVCON_HTTP_INVALID_HEADER);
		break;
	}
	/* request may have been freed above */
}

/*
 * Creates a TCP connection to the specified port and executes a callback
 * when finished.  Failure or success is indicate by the passed connection
 * object.
 *
 * Although this interface accepts a hostname, it is intended to take
 * only numeric hostnames so that non-blocking DNS resolution can
 * happen elsewhere.
 */

struct evhttp_connection *
evhttp_connection_new(const char *address, unsigned short port)
{
	return (evhttp_connection_base_new(NULL, NULL, address, port));
}

struct evhttp_connection *
evhttp_connection_base_new(struct event_base *base, struct evdns_base *dnsbase,
    const char *address, unsigned short port)
{
	struct evhttp_connection *evcon = NULL;

	event_debug(("Attempting connection to %s:%d\n", address, port));

	if ((evcon = mm_calloc(1, sizeof(struct evhttp_connection))) == NULL) {
		event_warn("%s: calloc failed", __func__);
		goto error;
	}

	evcon->fd = -1;
	evcon->port = port;

	evcon->max_headers_size = EV_SIZE_MAX;
	evcon->max_body_size = EV_SIZE_MAX;

	evcon->timeout = -1;
	evcon->retry_cnt = evcon->retry_max = 0;

	if ((evcon->address = mm_strdup(address)) == NULL) {
		event_warn("%s: strdup failed", __func__);
		goto error;
	}

	if ((evcon->bufev = bufferevent_new(-1,
		    evhttp_read_cb,
		    evhttp_write_cb,
		    evhttp_error_cb, evcon)) == NULL) {
		event_warn("%s: bufferevent_new failed", __func__);
		goto error;
	}

	evcon->state = EVCON_DISCONNECTED;
	TAILQ_INIT(&evcon->requests);

	if (base != NULL) {
		evcon->base = base;
		bufferevent_base_set(base, evcon->bufev);
	}

	evcon->dns_base = dnsbase;

	return (evcon);

 error:
	if (evcon != NULL)
		evhttp_connection_free(evcon);
	return (NULL);
}

void
evhttp_connection_set_base(struct evhttp_connection *evcon,
    struct event_base *base)
{
	EVUTIL_ASSERT(evcon->base == NULL);
	EVUTIL_ASSERT(evcon->state == EVCON_DISCONNECTED);
	evcon->base = base;
	bufferevent_base_set(base, evcon->bufev);
}

void
evhttp_connection_set_timeout(struct evhttp_connection *evcon,
    int timeout_in_secs)
{
	evcon->timeout = timeout_in_secs;

	if (evcon->timeout == -1)
		bufferevent_settimeout(evcon->bufev,
		    HTTP_READ_TIMEOUT, HTTP_WRITE_TIMEOUT);
	else
		bufferevent_settimeout(evcon->bufev,
		    evcon->timeout, evcon->timeout);
}

void
evhttp_connection_set_retries(struct evhttp_connection *evcon,
    int retry_max)
{
	evcon->retry_max = retry_max;
}

void
evhttp_connection_set_closecb(struct evhttp_connection *evcon,
    void (*cb)(struct evhttp_connection *, void *), void *cbarg)
{
	evcon->closecb = cb;
	evcon->closecb_arg = cbarg;
}

void
evhttp_connection_get_peer(struct evhttp_connection *evcon,
    char **address, ev_uint16_t *port)
{
	*address = evcon->address;
	*port = evcon->port;
}

int
evhttp_connection_connect(struct evhttp_connection *evcon)
{
	if (evcon->state == EVCON_CONNECTING)
		return (0);

	evhttp_connection_reset(evcon);

	EVUTIL_ASSERT(!(evcon->flags & EVHTTP_CON_INCOMING));
	evcon->flags |= EVHTTP_CON_OUTGOING;

	evcon->fd = bind_socket(
		evcon->bind_address, evcon->bind_port, 0 /*reuse*/);
	if (evcon->fd == -1) {
		event_debug(("%s: failed to bind to \"%s\"",
			__func__, evcon->bind_address));
		return (-1);
	}

	/* Set up a callback for successful connection setup */
	bufferevent_setfd(evcon->bufev, evcon->fd);
	bufferevent_setcb(evcon->bufev,
	    NULL /* evhttp_read_cb */,
	    NULL /* evhttp_write_cb */,
	    evhttp_connection_cb,
	    evcon);
	bufferevent_settimeout(evcon->bufev, 0,
	    evcon->timeout != -1 ? evcon->timeout : HTTP_CONNECT_TIMEOUT);
	/* make sure that we get a write callback */
	bufferevent_enable(evcon->bufev, EV_WRITE);

	if (bufferevent_socket_connect_hostname(evcon->bufev, evcon->dns_base,
		AF_UNSPEC, evcon->address, evcon->port) < 0) {
		event_sock_warn(evcon->fd, "%s: connection to \"%s\" failed",
		    __func__, evcon->address);
		/* some operating systems return ECONNREFUSED immediately
		 * when connecting to a local address.  the cleanup is going
		 * to reschedule this function call.
		 */
		evhttp_connection_cb_cleanup(evcon);
		return (0);
	}

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
		mm_free(req->uri);
	if ((req->uri = mm_strdup(uri)) == NULL) {
		event_warn("%s: strdup", __func__);
		evhttp_request_free(req);
		return (-1);
	}

	/* Set the protocol version if it is not supplied */
	if (!req->major && !req->minor) {
		req->major = 1;
		req->minor = 1;
	}

	EVUTIL_ASSERT(req->evcon == NULL);
	req->evcon = evcon;
	EVUTIL_ASSERT(!(req->flags & EVHTTP_REQ_OWN_CONNECTION));

	TAILQ_INSERT_TAIL(&evcon->requests, req, next);

	/* If the connection object is not connected; make it so */
	if (!evhttp_connected(evcon))
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

void
evhttp_cancel_request(struct evhttp_request *req)
{
	struct evhttp_connection *evcon = req->evcon;
	if (evcon != NULL) {
		/* We need to remove it from the connection */
		if (TAILQ_FIRST(&evcon->requests) == req) {
			/* it's currently being worked on, so reset
			 * the connection.
			 */
			evhttp_connection_fail(evcon,
			    EVCON_HTTP_REQUEST_CANCEL);

			/* connection fail freed the request */
			return;
		} else {
			/* otherwise, we can just remove it from the
			 * queue
			 */
			TAILQ_REMOVE(&evcon->requests, req, next);
		}
	}

	evhttp_request_free(req);
}

/*
 * Reads data from file descriptor into request structure
 * Request structure needs to be set up correctly.
 */

void
evhttp_start_read(struct evhttp_connection *evcon)
{
	/* Set up an event to read the headers */
	bufferevent_disable(evcon->bufev, EV_WRITE);
	bufferevent_enable(evcon->bufev, EV_READ);
	evcon->state = EVCON_READING_FIRSTLINE;
}

static void
evhttp_send_done(struct evhttp_connection *evcon, void *arg)
{
	int need_close;
	struct evhttp_request *req = TAILQ_FIRST(&evcon->requests);
	TAILQ_REMOVE(&evcon->requests, req, next);

	need_close =
	    (req->minor == 0 &&
		!evhttp_is_connection_keepalive(req->input_headers))||
	    evhttp_is_connection_close(req->flags, req->input_headers) ||
	    evhttp_is_connection_close(req->flags, req->output_headers);

	EVUTIL_ASSERT(req->flags & EVHTTP_REQ_OWN_CONNECTION);
	evhttp_request_free(req);

	if (need_close) {
		evhttp_connection_free(evcon);
		return;
	}

	/* we have a persistent connection; try to accept another request. */
	if (evhttp_associate_new_request_with_connection(evcon) == -1) {
		evhttp_connection_free(evcon);
	}
}

/*
 * Returns an error page.
 */

void
evhttp_send_error(struct evhttp_request *req, int error, const char *reason)
{

#define ERR_FORMAT "<HTML><HEAD>\n" \
	    "<TITLE>%d %s</TITLE>\n" \
	    "</HEAD><BODY>\n" \
	    "<H1>%s</H1>\n" \
	    "</BODY></HTML>\n"

	struct evbuffer *buf = evbuffer_new();
	if (buf == NULL) {
		/* if we cannot allocate memory; we just drop the connection */
		evhttp_connection_free(req->evcon);
		return;
	}
	if (reason == NULL) {
		reason = evhttp_response_phrase_internal(error);
	}

	evhttp_response_code(req, error, reason);

	evbuffer_add_printf(buf, ERR_FORMAT, error, reason, reason);

	evhttp_send_page(req, buf);

	evbuffer_free(buf);
#undef ERR_FORMAT
}

/* Requires that headers and response code are already set up */

static inline void
evhttp_send(struct evhttp_request *req, struct evbuffer *databuf)
{
	struct evhttp_connection *evcon = req->evcon;

	if (evcon == NULL) {
		evhttp_request_free(req);
		return;
	}

	EVUTIL_ASSERT(TAILQ_FIRST(&evcon->requests) == req);

	/* we expect no more calls form the user on this request */
	req->userdone = 1;

	/* xxx: not sure if we really should expose the data buffer this way */
	if (databuf != NULL)
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
evhttp_send_reply_start(struct evhttp_request *req, int code,
    const char *reason)
{
	evhttp_response_code(req, code, reason);
	if (evhttp_find_header(req->output_headers, "Content-Length") == NULL &&
	    req->major == 1 && req->minor == 1 &&
	    evhttp_response_needs_body(req)) {
		/*
		 * prefer HTTP/1.1 chunked encoding to closing the connection;
		 * note RFC 2616 section 4.4 forbids it with Content-Length:
		 * and it's not necessary then anyway.
		 */
		evhttp_add_header(req->output_headers, "Transfer-Encoding",
		    "chunked");
		req->chunked = 1;
	}
	evhttp_make_header(req->evcon, req);
	evhttp_write_buffer(req->evcon, NULL, NULL);
}

void
evhttp_send_reply_chunk(struct evhttp_request *req, struct evbuffer *databuf)
{
	struct evhttp_connection *evcon = req->evcon;
	struct evbuffer *output;

	if (evcon == NULL)
		return;

	output = bufferevent_get_output(evcon->bufev);

	if (evbuffer_get_length(databuf) == 0)
		return;
	if (!evhttp_response_needs_body(req))
		return;
	if (req->chunked) {
		evbuffer_add_printf(output, "%x\r\n",
				    (unsigned)evbuffer_get_length(databuf));
	}
	evbuffer_add_buffer(output, databuf);
	if (req->chunked) {
		evbuffer_add(output, "\r\n", 2);
	}
	evhttp_write_buffer(evcon, NULL, NULL);
}

void
evhttp_send_reply_end(struct evhttp_request *req)
{
	struct evhttp_connection *evcon = req->evcon;
	struct evbuffer *output;

	if (evcon == NULL) {
		evhttp_request_free(req);
		return;
	}

	output = bufferevent_get_output(evcon->bufev);

	/* we expect no more calls form the user on this request */
	req->userdone = 1;

	if (req->chunked) {
		evbuffer_add(output, "0\r\n\r\n", 5);
		evhttp_write_buffer(req->evcon, evhttp_send_done, NULL);
		req->chunked = 0;
	} else if (evbuffer_get_length(output) == 0) {
		/* let the connection know that we are done with the request */
		evhttp_send_done(evcon, NULL);
	} else {
		/* make the callback execute after all data has been written */
		evcon->cb = evhttp_send_done;
		evcon->cb_arg = NULL;
	}
}

static const char *informational_phrases[] = {
	/* 100 */ "Continue",
	/* 101 */ "Switching Protocols"
};

static const char *success_phrases[] = {
	/* 200 */ "OK",
	/* 201 */ "Created",
	/* 202 */ "Accepted",
	/* 203 */ "Non-Authoritative Information",
	/* 204 */ "No Content",
	/* 205 */ "Reset Content",
	/* 206 */ "Partial Content"
};

static const char *redirection_phrases[] = {
	/* 300 */ "Multiple Choices",
	/* 301 */ "Moved Permanently",
	/* 302 */ "Found",
	/* 303 */ "See Other",
	/* 304 */ "Not Modified",
	/* 305 */ "Use Proxy",
	/* 307 */ "Temporary Redirect"
};

static const char *client_error_phrases[] = {
	/* 400 */ "Bad Request",
	/* 401 */ "Unauthorized",
	/* 402 */ "Payment Required",
	/* 403 */ "Forbidden",
	/* 404 */ "Not Found",
	/* 405 */ "Method Not Allowed",
	/* 406 */ "Not Acceptable",
	/* 407 */ "Proxy Authentication Required",
	/* 408 */ "Request Time-out",
	/* 409 */ "Conflict",
	/* 410 */ "Gone",
	/* 411 */ "Length Required",
	/* 412 */ "Precondition Failed",
	/* 413 */ "Request Entity Too Large",
	/* 414 */ "Request-URI Too Large",
	/* 415 */ "Unsupported Media Type",
	/* 416 */ "Requested range not satisfiable",
	/* 417 */ "Expectation Failed"
};

static const char *server_error_phrases[] = {
	/* 500 */ "Internal Server Error",
	/* 501 */ "Not Implemented",
	/* 502 */ "Bad Gateway",
	/* 503 */ "Service Unavailable",
	/* 504 */ "Gateway Time-out",
	/* 505 */ "HTTP Version not supported"
};

struct response_class {
	const char *name;
	size_t num_responses;
	const char **responses;
};

#ifndef MEMBERSOF
#define MEMBERSOF(x) (sizeof(x)/sizeof(x[0]))
#endif

static const struct response_class response_classes[] = {
	/* 1xx */ { "Informational", MEMBERSOF(informational_phrases), informational_phrases },
	/* 2xx */ { "Success", MEMBERSOF(success_phrases), success_phrases },
	/* 3xx */ { "Redirection", MEMBERSOF(redirection_phrases), redirection_phrases },
	/* 4xx */ { "Client Error", MEMBERSOF(client_error_phrases), client_error_phrases },
	/* 5xx */ { "Server Error", MEMBERSOF(server_error_phrases), server_error_phrases }
};

static const char *
evhttp_response_phrase_internal(int code)
{
	int klass = code / 100 - 1;
	int subcode = code % 100;

	/* Unknown class - can't do any better here */
	if (klass < 0 || klass >= MEMBERSOF(response_classes))
		return "Unknown Status Class";

	/* Unknown sub-code, return class name at least */
	if (subcode >= response_classes[klass].num_responses)
		return response_classes[klass].name;

	return response_classes[klass].responses[subcode];
}

void
evhttp_response_code(struct evhttp_request *req, int code, const char *reason)
{
	req->kind = EVHTTP_RESPONSE;
	req->response_code = code;
	if (req->response_code_line != NULL)
		mm_free(req->response_code_line);
	if (reason == NULL)
		reason = evhttp_response_phrase_internal(code);
	req->response_code_line = mm_strdup(reason);
}

void
evhttp_send_page(struct evhttp_request *req, struct evbuffer *databuf)
{
	if (!req->major || !req->minor) {
		req->major = 1;
		req->minor = 1;
	}

	if (req->kind != EVHTTP_RESPONSE)
		evhttp_response_code(req, 200, "OK");

	evhttp_clear_headers(req->output_headers);
	evhttp_add_header(req->output_headers, "Content-Type", "text/html");
	evhttp_add_header(req->output_headers, "Connection", "close");

	evhttp_send(req, databuf);
}

static const char uri_chars[256] = {
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 0, 0, 1, 0, 0, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 1, 0, 0,
	/* 64 */
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 0, 1,
	0, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,   1, 1, 1, 0, 0, 0, 1, 0,
	/* 128 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	/* 192 */
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,   0, 0, 0, 0, 0, 0, 0, 0,
};

/*
 * Helper functions to encode/decode a URI.
 * The returned string must be freed by the caller.
 */
char *
evhttp_encode_uri(const char *uri)
{
	struct evbuffer *buf = evbuffer_new();
	char *p;

	if (buf == NULL)
		return (NULL);

	for (p = (char *)uri; *p != '\0'; p++) {
		if (uri_chars[(unsigned char)(*p)]) {
			evbuffer_add(buf, p, 1);
		} else {
			evbuffer_add_printf(buf, "%%%02X", (unsigned char)(*p));
		}
	}
	evbuffer_add(buf, "", 1);
	p = mm_strdup((char*)evbuffer_pullup(buf, -1));
	evbuffer_free(buf);

	return (p);
}

/*
 * @param always_decode_plus: when true we transform plus to space even
 *     if we have not seen a ?.
 */
static int
evhttp_decode_uri_internal(
	const char *uri, size_t length, char *ret, int always_decode_plus)
{
	char c;
	int j, in_query = always_decode_plus;
	unsigned i;

	for (i = j = 0; i < length; i++) {
		c = uri[i];
		if (c == '?') {
			in_query = 1;
		} else if (c == '+' && in_query) {
			c = ' ';
		} else if (c == '%' && EVUTIL_ISXDIGIT(uri[i+1]) &&
		    EVUTIL_ISXDIGIT(uri[i+2])) {
			char tmp[3];
			tmp[0] = uri[i+1];
			tmp[1] = uri[i+2];
			tmp[2] = '\0';
			c = (char)strtol(tmp, NULL, 16);
			i += 2;
		}
		ret[j++] = c;
	}
	ret[j] = '\0';

	return (j);
}

char *
evhttp_decode_uri(const char *uri)
{
	char *ret;

	if ((ret = mm_malloc(strlen(uri) + 1)) == NULL) {
		event_warn("%s: malloc(%lu)", __func__,
			  (unsigned long)(strlen(uri) + 1));
		return (NULL);
	}

	evhttp_decode_uri_internal(uri, strlen(uri),
	    ret, 0 /*always_decode_plus*/);

	return (ret);
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

	if ((line = mm_strdup(uri)) == NULL) {
		/* TODO(niels): does this function need to return -1 */
		event_warn("%s: strdup", __func__);
		return;
	}


	argument = line;

	/* We already know that there has to be a ? */
	strsep(&argument, "?");

	p = argument;
	while (p != NULL && *p != '\0') {
		char *key, *value, *decoded_value;
		argument = strsep(&p, "&");

		value = argument;
		key = strsep(&value, "=");
		if (value == NULL || *key == '\0')
			goto error;

		if ((decoded_value = mm_malloc(strlen(value) + 1)) == NULL) {
			/* TODO(niels): do we need to return -1 here? */
			event_warn("%s: mm_malloc", __func__);
			break;
		}
		evhttp_decode_uri_internal(value, strlen(value),
		    decoded_value, 1 /*always_decode_plus*/);
		event_debug(("Query Param: %s -> %s\n", key, decoded_value));
		evhttp_add_header_internal(headers, key, decoded_value);
		mm_free(decoded_value);
	}

 error:
	mm_free(line);
}

static struct evhttp_cb *
evhttp_dispatch_callback(struct httpcbq *callbacks, struct evhttp_request *req)
{
	struct evhttp_cb *cb;
	size_t offset = 0;
	char *translated;

	/* Test for different URLs */
	char *p = req->uri;
	while (*p != '\0' && *p != '?')
		++p;
	offset = (size_t)(p - req->uri);

	if ((translated = mm_malloc(offset + 1)) == NULL)
		return (NULL);
	offset = evhttp_decode_uri_internal(req->uri, offset,
	    translated, 0 /* always_decode_plus */);

	TAILQ_FOREACH(cb, callbacks, next) {
		int res = 0;
		res = ((strncmp(cb->what, translated, offset) == 0) &&
		    (cb->what[offset] == '\0'));

		if (res) {
			mm_free(translated);
			return (cb);
		}
	}

	mm_free(translated);
	return (NULL);
}


static int
prefix_suffix_match(const char *pattern, const char *name, int ignorecase)
{
	char c;

	while (1) {
		switch (c = *pattern++) {
		case '\0':
			return *name == '\0';

		case '*':
			while (*name != '\0') {
				if (prefix_suffix_match(pattern, name,
					ignorecase))
					return (1);
				++name;
			}
			return (0);
		default:
			if (c != *name) {
				if (!ignorecase ||
				    EVUTIL_TOLOWER(c) != EVUTIL_TOLOWER(*name))
					return (0);
			}
			++name;
		}
	}
	/* NOTREACHED */
}

static void
evhttp_handle_request(struct evhttp_request *req, void *arg)
{
	struct evhttp *http = arg;
	struct evhttp_cb *cb = NULL;
	const char *hostname;

	/* we have a new request on which the user needs to take action */
	req->userdone = 0;

	if (req->uri == NULL) {
		evhttp_send_error(req, HTTP_BADREQUEST, NULL);
		return;
	}

	/* handle potential virtual hosts */
	hostname = evhttp_find_header(req->input_headers, "Host");
	if (hostname != NULL) {
		struct evhttp *vhost;
		TAILQ_FOREACH(vhost, &http->virtualhosts, next) {
			if (prefix_suffix_match(vhost->vhost_pattern, hostname,
				1 /* ignorecase */)) {
				evhttp_handle_request(req, vhost);
				return;
			}
		}
	}

	if ((cb = evhttp_dispatch_callback(&http->callbacks, req)) != NULL) {
		(*cb->cb)(req, cb->cbarg);
		return;
	}

	/* Generic call back */
	if (http->gencb) {
		(*http->gencb)(req, http->gencbarg);
		return;
	} else {
		/* We need to send a 404 here */
#define ERR_FORMAT "<html><head>" \
		    "<title>404 Not Found</title>" \
		    "</head><body>" \
		    "<h1>Not Found</h1>" \
		    "<p>The requested URL %s was not found on this server.</p>"\
		    "</body></html>\n"

		char *escaped_html;
		struct evbuffer *buf;

		if ((escaped_html = evhttp_htmlescape(req->uri)) == NULL) {
			evhttp_connection_free(req->evcon);
			return;
		}

		if ((buf = evbuffer_new()) == NULL) {
			mm_free(escaped_html);
			evhttp_connection_free(req->evcon);
			return;
		}

		evhttp_response_code(req, HTTP_NOTFOUND, "Not Found");

		evbuffer_add_printf(buf, ERR_FORMAT, escaped_html);

		mm_free(escaped_html);

		evhttp_send_page(req, buf);

		evbuffer_free(buf);
#undef ERR_FORMAT
	}
}

static void
accept_socket_cb(struct evconnlistener *listener, evutil_socket_t nfd, struct sockaddr *peer_sa, int peer_socklen, void *arg)
{
	struct evhttp *http = arg;

	evhttp_get_request(http, nfd, peer_sa, peer_socklen);
}

int
evhttp_bind_socket(struct evhttp *http, const char *address, ev_uint16_t port)
{
	struct evhttp_bound_socket *bound =
		evhttp_bind_socket_with_handle(http, address, port);
	if (bound == NULL)
		return (-1);
	return (0);
}

struct evhttp_bound_socket *
evhttp_bind_socket_with_handle(struct evhttp *http, const char *address, ev_uint16_t port)
{
	evutil_socket_t fd;
	struct evhttp_bound_socket *bound;

	if ((fd = bind_socket(address, port, 1 /*reuse*/)) == -1)
		return (NULL);

	if (listen(fd, 128) == -1) {
		event_sock_warn(fd, "%s: listen", __func__);
		evutil_closesocket(fd);
		return (NULL);
	}

	bound = evhttp_accept_socket_with_handle(http, fd);

	if (bound != NULL) {
		event_debug(("Bound to port %d - Awaiting connections ... ",
			port));
		return (bound);
	}

	return (NULL);
}

int
evhttp_accept_socket(struct evhttp *http, evutil_socket_t fd)
{
	struct evhttp_bound_socket *bound =
		evhttp_accept_socket_with_handle(http, fd);
	if (bound == NULL)
		return (-1);
	return (0);
}


struct evhttp_bound_socket *
evhttp_accept_socket_with_handle(struct evhttp *http, evutil_socket_t fd)
{
	struct evhttp_bound_socket *bound;
	struct evconnlistener *listener;
	const int flags =
	    LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_CLOSE_ON_FREE;

	bound = mm_malloc(sizeof(struct evhttp_bound_socket));
	if (bound == NULL)
		return (NULL);

	listener = evconnlistener_new(http->base, accept_socket_cb, http,
	    flags,
	    0, /* Backlog is '0' because we already said 'listen' */
	    fd);
	if (!listener) {
		mm_free(bound);
		return (NULL);
	}
	bound->listener = listener;

	TAILQ_INSERT_TAIL(&http->sockets, bound, next);

	return (bound);
}

evutil_socket_t evhttp_bound_socket_get_fd(struct evhttp_bound_socket *bound)
{
	return evconnlistener_get_fd(bound->listener);
}

void
evhttp_del_accept_socket(struct evhttp *http, struct evhttp_bound_socket *bound)
{
	TAILQ_REMOVE(&http->sockets, bound, next);
	evconnlistener_free(bound->listener);
	mm_free(bound);
}

static struct evhttp*
evhttp_new_object(void)
{
	struct evhttp *http = NULL;

	if ((http = mm_calloc(1, sizeof(struct evhttp))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (NULL);
	}

	http->timeout = -1;
	evhttp_set_max_headers_size(http, EV_SIZE_MAX);
	evhttp_set_max_body_size(http, EV_SIZE_MAX);

	TAILQ_INIT(&http->sockets);
	TAILQ_INIT(&http->callbacks);
	TAILQ_INIT(&http->connections);
	TAILQ_INIT(&http->virtualhosts);

	return (http);
}

struct evhttp *
evhttp_new(struct event_base *base)
{
	struct evhttp *http = evhttp_new_object();

	http->base = base;

	return (http);
}

/*
 * Start a web server on the specified address and port.
 */

struct evhttp *
evhttp_start(const char *address, unsigned short port)
{
	struct evhttp *http = evhttp_new_object();

	if (evhttp_bind_socket(http, address, port) == -1) {
		mm_free(http);
		return (NULL);
	}

	return (http);
}

void
evhttp_free(struct evhttp* http)
{
	struct evhttp_cb *http_cb;
	struct evhttp_connection *evcon;
	struct evhttp_bound_socket *bound;
	struct evhttp* vhost;

	/* Remove the accepting part */
	while ((bound = TAILQ_FIRST(&http->sockets)) != NULL) {
		TAILQ_REMOVE(&http->sockets, bound, next);

		evconnlistener_free(bound->listener);

		mm_free(bound);
	}

	while ((evcon = TAILQ_FIRST(&http->connections)) != NULL) {
		/* evhttp_connection_free removes the connection */
		evhttp_connection_free(evcon);
	}

	while ((http_cb = TAILQ_FIRST(&http->callbacks)) != NULL) {
		TAILQ_REMOVE(&http->callbacks, http_cb, next);
		mm_free(http_cb->what);
		mm_free(http_cb);
	}

	while ((vhost = TAILQ_FIRST(&http->virtualhosts)) != NULL) {
		TAILQ_REMOVE(&http->virtualhosts, vhost, next);

		evhttp_free(vhost);
	}

	if (http->vhost_pattern != NULL)
		mm_free(http->vhost_pattern);

	mm_free(http);
}

int
evhttp_add_virtual_host(struct evhttp* http, const char *pattern,
    struct evhttp* vhost)
{
	/* a vhost can only be a vhost once and should not have bound sockets */
	if (vhost->vhost_pattern != NULL ||
	    TAILQ_FIRST(&vhost->sockets) != NULL)
		return (-1);

	vhost->vhost_pattern = mm_strdup(pattern);
	if (vhost->vhost_pattern == NULL)
		return (-1);

	TAILQ_INSERT_TAIL(&http->virtualhosts, vhost, next);

	return (0);
}

int
evhttp_remove_virtual_host(struct evhttp* http, struct evhttp* vhost)
{
	if (vhost->vhost_pattern == NULL)
		return (-1);

	TAILQ_REMOVE(&http->virtualhosts, vhost, next);

	mm_free(vhost->vhost_pattern);
	vhost->vhost_pattern = NULL;

	return (0);
}

void
evhttp_set_timeout(struct evhttp* http, int timeout_in_secs)
{
	http->timeout = timeout_in_secs;
}

void
evhttp_set_max_headers_size(struct evhttp* http, ev_ssize_t max_headers_size)
{
	if (max_headers_size < 0)
		http->default_max_headers_size = EV_SIZE_MAX;
	else
		http->default_max_headers_size = max_headers_size;
}

void
evhttp_set_max_body_size(struct evhttp* http, ev_ssize_t max_body_size)
{
	if (max_body_size < 0)
		http->default_max_body_size = EV_UINT64_MAX;
	else
		http->default_max_body_size = max_body_size;
}

int
evhttp_set_cb(struct evhttp *http, const char *uri,
    void (*cb)(struct evhttp_request *, void *), void *cbarg)
{
	struct evhttp_cb *http_cb;

	TAILQ_FOREACH(http_cb, &http->callbacks, next) {
		if (strcmp(http_cb->what, uri) == 0)
			return (-1);
	}

	if ((http_cb = mm_calloc(1, sizeof(struct evhttp_cb))) == NULL) {
		event_warn("%s: calloc", __func__);
		return (-2);
	}

	http_cb->what = mm_strdup(uri);
	http_cb->cb = cb;
	http_cb->cbarg = cbarg;

	TAILQ_INSERT_TAIL(&http->callbacks, http_cb, next);

	return (0);
}

int
evhttp_del_cb(struct evhttp *http, const char *uri)
{
	struct evhttp_cb *http_cb;

	TAILQ_FOREACH(http_cb, &http->callbacks, next) {
		if (strcmp(http_cb->what, uri) == 0)
			break;
	}
	if (http_cb == NULL)
		return (-1);

	TAILQ_REMOVE(&http->callbacks, http_cb, next);
	mm_free(http_cb->what);
	mm_free(http_cb);

	return (0);
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
	if ((req = mm_calloc(1, sizeof(struct evhttp_request))) == NULL) {
		event_warn("%s: calloc", __func__);
		goto error;
	}

	req->headers_size = 0;
	req->body_size = 0;

	req->kind = EVHTTP_RESPONSE;
	req->input_headers = mm_calloc(1, sizeof(struct evkeyvalq));
	if (req->input_headers == NULL) {
		event_warn("%s: calloc", __func__);
		goto error;
	}
	TAILQ_INIT(req->input_headers);

	req->output_headers = mm_calloc(1, sizeof(struct evkeyvalq));
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
	if ((req->flags & EVHTTP_REQ_DEFER_FREE) != 0) {
		req->flags |= EVHTTP_REQ_NEEDS_FREE;
		return;
	}

	if (req->remote_host != NULL)
		mm_free(req->remote_host);
	if (req->uri != NULL)
		mm_free(req->uri);
	if (req->response_code_line != NULL)
		mm_free(req->response_code_line);

	evhttp_clear_headers(req->input_headers);
	mm_free(req->input_headers);

	evhttp_clear_headers(req->output_headers);
	mm_free(req->output_headers);

	if (req->input_buffer != NULL)
		evbuffer_free(req->input_buffer);

	if (req->output_buffer != NULL)
		evbuffer_free(req->output_buffer);

	mm_free(req);
}

void
evhttp_request_own(struct evhttp_request *req)
{
	req->flags |= EVHTTP_USER_OWNED;
}

int
evhttp_request_is_owned(struct evhttp_request *req)
{
	return (req->flags & EVHTTP_USER_OWNED) != 0;
}

struct evhttp_connection *
evhttp_request_get_connection(struct evhttp_request *req)
{
	return req->evcon;
}


void
evhttp_request_set_chunked_cb(struct evhttp_request *req,
    void (*cb)(struct evhttp_request *, void *))
{
	req->chunk_cb = cb;
}

/*
 * Allows for inspection of the request URI
 */

const char *
evhttp_request_get_uri(struct evhttp_request *req) {
	if (req->uri == NULL)
		event_debug(("%s: request %p has no uri\n", __func__, req));
	return (req->uri);
}

/** Returns the input headers */
struct evkeyvalq *evhttp_request_get_input_headers(struct evhttp_request *req)
{
	return (req->input_headers);
}

/** Returns the output headers */
struct evkeyvalq *evhttp_request_get_output_headers(struct evhttp_request *req)
{
	return (req->output_headers);
}

/** Returns the input buffer */
struct evbuffer *evhttp_request_get_input_buffer(struct evhttp_request *req)
{
	return (req->input_buffer);
}

/** Returns the output buffer */
struct evbuffer *evhttp_request_get_output_buffer(struct evhttp_request *req)
{
	return (req->output_buffer);
}


/*
 * Takes a file descriptor to read a request from.
 * The callback is executed once the whole request has been read.
 */

static struct evhttp_connection*
evhttp_get_request_connection(
	struct evhttp* http,
	evutil_socket_t fd, struct sockaddr *sa, ev_socklen_t salen)
{
	struct evhttp_connection *evcon;
	char *hostname = NULL, *portname = NULL;

	name_from_addr(sa, salen, &hostname, &portname);
	if (hostname == NULL || portname == NULL) {
		if (hostname) mm_free(hostname);
		if (portname) mm_free(portname);
		return (NULL);
	}

	event_debug(("%s: new request from %s:%s on %d\n",
			__func__, hostname, portname, fd));

	/* we need a connection object to put the http request on */
	evcon = evhttp_connection_base_new(
		http->base, NULL, hostname, atoi(portname));
	mm_free(hostname);
	mm_free(portname);
	if (evcon == NULL)
		return (NULL);

	evcon->max_headers_size = http->default_max_headers_size;
	evcon->max_body_size = http->default_max_body_size;

	evcon->flags |= EVHTTP_CON_INCOMING;
	evcon->state = EVCON_READING_FIRSTLINE;

	evcon->fd = fd;

	bufferevent_setfd(evcon->bufev, fd);

	return (evcon);
}

static int
evhttp_associate_new_request_with_connection(struct evhttp_connection *evcon)
{
	struct evhttp *http = evcon->http_server;
	struct evhttp_request *req;
	if ((req = evhttp_request_new(evhttp_handle_request, http)) == NULL)
		return (-1);

	if ((req->remote_host = mm_strdup(evcon->address)) == NULL) {
		event_warn("%s: strdup", __func__);
		evhttp_request_free(req);
		return (-1);
	}
	req->remote_port = evcon->port;

	req->evcon = evcon;	/* the request ends up owning the connection */
	req->flags |= EVHTTP_REQ_OWN_CONNECTION;

	/* We did not present the request to the user user yet, so treat it as
	 * if the user was done with the request.  This allows us to free the 
	 * request on a persistent connection if the client drops it without
	 * sending a request.
	 */
	req->userdone = 1;

	TAILQ_INSERT_TAIL(&evcon->requests, req, next);

	req->kind = EVHTTP_REQUEST;


	evhttp_start_read(evcon);

	return (0);
}

void
evhttp_get_request(struct evhttp *http, evutil_socket_t fd,
    struct sockaddr *sa, ev_socklen_t salen)
{
	struct evhttp_connection *evcon;

	evcon = evhttp_get_request_connection(http, fd, sa, salen);
	if (evcon == NULL) {
		event_sock_warn(fd, "%s: cannot get connection on %d", __func__, fd);
		evutil_closesocket(fd);
		return;
	}

	/* the timeout can be used by the server to close idle connections */
	if (http->timeout != -1)
		evhttp_connection_set_timeout(evcon, http->timeout);

	/*
	 * if we want to accept more than one request on a connection,
	 * we need to know which http server it belongs to.
	 */
	evcon->http_server = http;
	TAILQ_INSERT_TAIL(&http->connections, evcon, next);

	if (evhttp_associate_new_request_with_connection(evcon) == -1)
		evhttp_connection_free(evcon);
}


/*
 * Network helper functions that we do not want to export to the rest of
 * the world.
 */

static void
name_from_addr(struct sockaddr *sa, ev_socklen_t salen,
    char **phost, char **pport)
{
	char ntop[NI_MAXHOST];
	char strport[NI_MAXSERV];
	int ni_result;

#ifdef _EVENT_HAVE_GETNAMEINFO
	ni_result = getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV);

	if (ni_result != 0) {
#ifdef EAI_SYSTEM
		/* Windows doesn't have an EAI_SYSTEM. */
		if (ni_result == EAI_SYSTEM)
			event_err(1, "getnameinfo failed");
		else
#endif
			event_errx(1, "getnameinfo failed: %s", gai_strerror(ni_result));
		return;
	}
#else
	ni_result = fake_getnameinfo(sa, salen,
		ntop, sizeof(ntop), strport, sizeof(strport),
		NI_NUMERICHOST|NI_NUMERICSERV);
	if (ni_result != 0)
			return;
#endif

	*phost = mm_strdup(ntop);
	*pport = mm_strdup(strport);
}

/* Create a non-blocking socket and bind it */
/* todo: rename this function */
static evutil_socket_t
bind_socket_ai(struct evutil_addrinfo *ai, int reuse)
{
	evutil_socket_t fd;

	int on = 1, r;
	int serrno;

	/* Create listen socket */
	fd = socket(ai ? ai->ai_family : AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
			event_sock_warn(-1, "socket");
			return (-1);
	}

	if (evutil_make_socket_nonblocking(fd) < 0)
		goto out;
	if (evutil_make_socket_closeonexec(fd) < 0)
		goto out;

	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
	if (reuse)
		evutil_make_listen_socket_reuseable(fd);

	if (ai != NULL) {
		r = bind(fd, ai->ai_addr, ai->ai_addrlen);
		if (r == -1)
			goto out;
	}

	return (fd);

 out:
	serrno = EVUTIL_SOCKET_ERROR();
	evutil_closesocket(fd);
	EVUTIL_SET_SOCKET_ERROR(serrno);
	return (-1);
}

static struct evutil_addrinfo *
make_addrinfo(const char *address, ev_uint16_t port)
{
	struct evutil_addrinfo *ai = NULL;

	struct evutil_addrinfo hints;
	char strport[NI_MAXSERV];
	int ai_result;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	/* turn NULL hostname into INADDR_ANY, and skip looking up any address
	 * types we don't have an interface to connect to. */
	hints.ai_flags = EVUTIL_AI_PASSIVE|EVUTIL_AI_ADDRCONFIG;
	evutil_snprintf(strport, sizeof(strport), "%d", port);
	if ((ai_result = evutil_getaddrinfo(address, strport, &hints, &ai))
	    != 0) {
		if (ai_result == EVUTIL_EAI_SYSTEM)
			event_warn("getaddrinfo");
		else
			event_warnx("getaddrinfo: %s",
			    evutil_gai_strerror(ai_result));
		return (NULL);
	}

	return (ai);
}

static evutil_socket_t
bind_socket(const char *address, ev_uint16_t port, int reuse)
{
	evutil_socket_t fd;
	struct evutil_addrinfo *aitop = NULL;

	/* just create an unbound socket */
	if (address == NULL && port == 0)
		return bind_socket_ai(NULL, 0);

	aitop = make_addrinfo(address, port);

	if (aitop == NULL)
		return (-1);

	fd = bind_socket_ai(aitop, reuse);

	evutil_freeaddrinfo(aitop);

	return (fd);
}

