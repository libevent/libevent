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
#ifndef _EVENT2_HTTP_H_
#define _EVENT2_HTTP_H_

/* For int types. */
#include <event2/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

/* In case we haven't included the right headers yet. */
struct evbuffer;
struct event_base;

/** @file evhttp.h
 *
 * Basic support for HTTP serving.
 *
 * As libevent is a library for dealing with event notification and most
 * interesting applications are networked today, I have often found the
 * need to write HTTP code.  The following prototypes and definitions provide
 * an application with a minimal interface for making HTTP requests and for
 * creating a very simple HTTP server.
 */

/* Response codes */
#define HTTP_OK			200	/**< request completed ok */
#define HTTP_NOCONTENT		204	/**< request does not have content */
#define HTTP_MOVEPERM		301	/**< the uri moved permanently */
#define HTTP_MOVETEMP		302	/**< the uri moved temporarily */
#define HTTP_NOTMODIFIED	304	/**< page was not modified from last */
#define HTTP_BADREQUEST		400	/**< invalid http request was made */
#define HTTP_NOTFOUND		404	/**< could not find content for uri */
#define HTTP_SERVUNAVAIL	503	/**< the server is not available */

struct evhttp;
struct evhttp_request;
struct evkeyvalq;

/** Create a new HTTP server
 *
 * @param base (optional) the event base to receive the HTTP events
 * @return a pointer to a newly initialized evhttp server structure
 */
struct evhttp *evhttp_new(struct event_base *base);

/**
 * Binds an HTTP server on the specified address and port.
 *
 * Can be called multiple times to bind the same http server
 * to multiple different ports.
 *
 * @param http a pointer to an evhttp object
 * @param address a string containing the IP address to listen(2) on
 * @param port the port number to listen on
 * @return 0 on success, -1 on failure.
 * @see evhttp_free(), evhttp_accept_socket()
 */
int evhttp_bind_socket(struct evhttp *http, const char *address, ev_uint16_t port);

/**
 * Makes an HTTP server accept connections on the specified socket
 *
 * This may be useful to create a socket and then fork multiple instances
 * of an http server, or when a socket has been communicated via file
 * descriptor passing in situations where an http servers does not have
 * permissions to bind to a low-numbered port.
 *
 * Can be called multiple times to have the http server listen to
 * multiple different sockets.
 *
 * @param http a pointer to an evhttp object
 * @param fd a socket fd that is ready for accepting connections
 * @return 0 on success, -1 on failure.
 * @see evhttp_free(), evhttp_bind_socket()
 */
int evhttp_accept_socket(struct evhttp *http, evutil_socket_t fd);

/**
 * Free the previously created HTTP server.
 *
 * Works only if no requests are currently being served.
 *
 * @param http the evhttp server object to be freed
 * @see evhttp_start()
 */
void evhttp_free(struct evhttp* http);

/** Set a callback for a specified URI */
void evhttp_set_cb(struct evhttp *, const char *,
    void (*)(struct evhttp_request *, void *), void *);

/** Removes the callback for a specified URI */
int evhttp_del_cb(struct evhttp *, const char *);

/** 
    Set a callback for all requests that are not caught by specific callbacks

    Invokes the specified callback for all requests that do not match any of
    the previously specified request paths.  This is catchall for requests not
    specifically configured with evhttp_set_cb().

    @param http the evhttp server object for which to set the callback
    @param cb the callback to invoke for any unmatched requests
    @param arg an context argument for the callback
*/
void evhttp_set_gencb(struct evhttp *http,
    void (*cb)(struct evhttp_request *, void *), void *arg);

/**
   Adds a virtual host to the http server.

   A virtual host is a newly initialized evhttp object that has request
   callbacks set on it via evhttp_set_cb() or evhttp_set_gencb().  It
   most not have any listing sockets associated with it.

   If the virtual host has not been removed by the time that evhttp_free()
   is called on the main http server, it will be automatically freed, too.

   It is possible to have hierarchical vhosts.  For example: A vhost
   with the pattern *.example.com may have other vhosts with patterns
   foo.example.com and bar.example.com associated with it.

   @param http the evhttp object to which to add a virtual host
   @param pattern the glob pattern against which the hostname is matched.
     The match is case insensitive and follows otherwise regular shell
     matching.
   @param vhost the virtual host to add the regular http server.
   @return 0 on success, -1 on failure
   @see evhttp_remove_virtual_host()
*/
int evhttp_add_virtual_host(struct evhttp* http, const char *pattern,
    struct evhttp* vhost);

/**
   Removes a virtual host from the http server.

   @param http the evhttp object from which to remove the virtual host
   @param vhost the virtual host to remove from the regular http server.
   @return 0 on success, -1 on failure
   @see evhttp_add_virtual_host()
*/
int evhttp_remove_virtual_host(struct evhttp* http, struct evhttp* vhost);

/**
 * Set the timeout for an HTTP request.
 *
 * @param http an evhttp object
 * @param timeout_in_secs the timeout, in seconds
 */
void evhttp_set_timeout(struct evhttp *http, int timeout_in_secs);

/* Request/Response functionality */

/**
 * Send an HTML error message to the client.
 *
 * @param req a request object
 * @param error the HTTP error code
 * @param reason a brief explanation of the error
 */
void evhttp_send_error(struct evhttp_request *req, int error,
    const char *reason);

/**
 * Send an HTML reply to the client.
 *
 * @param req a request object
 * @param code the HTTP response code to send
 * @param reason a brief message to send with the response code
 * @param databuf the body of the response
 */
void evhttp_send_reply(struct evhttp_request *req, int code,
    const char *reason, struct evbuffer *databuf);

/* Low-level response interface, for streaming/chunked replies */
void evhttp_send_reply_start(struct evhttp_request *, int, const char *);
void evhttp_send_reply_chunk(struct evhttp_request *, struct evbuffer *);
void evhttp_send_reply_end(struct evhttp_request *);

/*
 * Interfaces for making requests
 */
enum evhttp_cmd_type { EVHTTP_REQ_GET, EVHTTP_REQ_POST, EVHTTP_REQ_HEAD, EVHTTP_REQ_PUT, EVHTTP_REQ_DELETE };

enum evhttp_request_kind { EVHTTP_REQUEST, EVHTTP_RESPONSE };

/**
 * Creates a new request object that needs to be filled in with the request
 * parameters.  The callback is executed when the request completed or an
 * error occurred.
 */
struct evhttp_request *evhttp_request_new(
	void (*cb)(struct evhttp_request *, void *), void *arg);

/** enable delivery of chunks to requestor */
void evhttp_request_set_chunked_cb(struct evhttp_request *,
    void (*cb)(struct evhttp_request *, void *));

/** Frees the request object and removes associated events. */
void evhttp_request_free(struct evhttp_request *req);

/**
 * A connection object that can be used to for making HTTP requests.  The
 * connection object tries to establish the connection when it is given an
 * http request object.
 */
struct evhttp_connection *evhttp_connection_base_new(
	struct event_base *base, const char *address, unsigned short port);

/** Takes ownership of the request object
 *
 * Can be used in a request callback to keep onto the request until
 * evhttp_request_free() is explicitly called by the user.
 */
void evhttp_request_own(struct evhttp_request *req);

/** Returns 1 if the request is owned by the user */
int evhttp_request_is_owned(struct evhttp_request *req);

/** Frees an http connection */
void evhttp_connection_free(struct evhttp_connection *evcon);

/** sets the ip address from which http connections are made */
void evhttp_connection_set_local_address(struct evhttp_connection *evcon,
    const char *address);

/** Sets the timeout for events related to this connection */
void evhttp_connection_set_timeout(struct evhttp_connection *evcon,
    int timeout_in_secs);

/** Sets the retry limit for this connection - -1 repeats indefnitely */
void evhttp_connection_set_retries(struct evhttp_connection *evcon,
    int retry_max);

/** Set a callback for connection close. */
void evhttp_connection_set_closecb(struct evhttp_connection *evcon,
    void (*)(struct evhttp_connection *, void *), void *);

/** Get the remote address and port associated with this connection. */
void evhttp_connection_get_peer(struct evhttp_connection *evcon,
    char **address, ev_uint16_t *port);

/** The connection gets ownership of the request */
int evhttp_make_request(struct evhttp_connection *evcon,
    struct evhttp_request *req,
    enum evhttp_cmd_type type, const char *uri);

/** Returns the request URI */
const char *evhttp_request_get_uri(struct evhttp_request *req);
/** Returns the input headers */
struct evkeyvalq *evhttp_request_get_input_headers(struct evhttp_request *req);
/** Returns the output headers */
struct evkeyvalq *evhttp_request_get_output_headers(struct evhttp_request *req);
/** Returns the input buffer */
struct evbuffer *evhttp_request_get_input_buffer(struct evhttp_request *req);
/** Returns the output buffer */
struct evbuffer *evhttp_request_get_output_buffer(struct evhttp_request *req);

/* Interfaces for dealing with HTTP headers */

/**
   Finds the value belonging to a header.
    
   @param headers the evkeyvalq object in which to find the header
   @param key the name of the header to find
   @returns a pointer to the value for the header or NULL if the header
     count not be found.
   @see evhttp_add_header(), evhttp_remove_header()
*/
const char *evhttp_find_header(const struct evkeyvalq *headers,
    const char *key);

/**
   Removes a header from a list of exisiting headers.
    
   @param headers the evkeyvalq object from which to remove a header
   @param key the name of the header to remove
   @returns 0 if the header was removed, -1  otherwise.
   @see evhttp_find_header(), evhttp_add_header()
*/
int evhttp_remove_header(struct evkeyvalq *headers, const char *key);

/**
   Adds a header to a list of exisiting headers.
    
   @param headers the evkeyvalq object to which to add a header
   @param key the name of the header
   @param value the value belonging to the header
   @returns 0 on success, -1  otherwise.
   @see evhttp_find_header(), evhttp_clear_headers()
*/
int evhttp_add_header(struct evkeyvalq *headers, const char *key, const char *value);

/**
   Removes all headers from the header list.

   @param headers the evkeyvalq object from which to remove all headers
*/
void evhttp_clear_headers(struct evkeyvalq *headers);

/* Miscellaneous utility functions */


/**
  Helper function to encode a URI.

  The returned string must be freed by the caller.

  @param uri an unencoded URI
  @return a newly allocated URI-encoded string
 */
char *evhttp_encode_uri(const char *uri);


/**
  Helper function to decode a URI.

  The returned string must be freed by the caller.

  @param uri an encoded URI
  @return a newly allocated unencoded URI
 */
char *evhttp_decode_uri(const char *uri);


/**
 * Helper function to parse out arguments in a query.
 * The arguments are separated by key and value.
 * URI should already be decoded.
 */
void evhttp_parse_query(const char *uri, struct evkeyvalq *);


/**
 * Escape HTML character entities in a string.
 *
 * Replaces <, >, ", ' and & with &lt;, &gt;, &quot;,
 * &#039; and &amp; correspondingly.
 *
 * The returned string needs to be freed by the caller.
 *
 * @param html an unescaped HTML string
 * @return an escaped HTML string
 */
char *evhttp_htmlescape(const char *html);

#ifdef __cplusplus
}
#endif

#endif /* _EVENT2_HTTP_H_ */
