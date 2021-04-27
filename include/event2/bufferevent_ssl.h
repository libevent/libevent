/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
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
#ifndef EVENT2_BUFFEREVENT_SSL_H_INCLUDED_
#define EVENT2_BUFFEREVENT_SSL_H_INCLUDED_

/** @file event2/bufferevent_ssl.h

    @brief OpenSSL support for bufferevents.
 */
#include <event2/visibility.h>
#include <event2/event-config.h>
#include <event2/bufferevent.h>
#include <event2/util.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
   The state of an SSL object to be used when creating a new
   SSL bufferevent.
 */
enum bufferevent_ssl_state {
	BUFFEREVENT_SSL_OPEN = 0,
	BUFFEREVENT_SSL_CONNECTING = 1,
	BUFFEREVENT_SSL_ACCEPTING = 2
};

/** Control how to report dirty SSL shutdowns.

    If the peer (or the network, or an attacker) closes the TCP
    connection before closing the SSL channel, and the protocol is SSL >= v3,
    this is a "dirty" shutdown.  If BUFFEREVENT_SSL_DIRTY_SHUTDOWN is not set
    (default), this is reported as BEV_EVENT_ERROR.

    If instead BUFFEREVENT_SSL_DIRTY_SHUTDOWN is set, a dirty shutdown is
    reported as BEV_EVENT_EOF.

    (Note that if the protocol is < SSLv3, you will always receive
    BEV_EVENT_EOF, since SSL 2 and earlier cannot distinguish a secure
    connection close from a dirty one.  This is one reason (among many)
    not to use SSL 2.)
*/
#define BUFFEREVENT_SSL_DIRTY_SHUTDOWN 1
/** Control writes in the SSL bufferevents.

    By default SSL bufferevent will peek bytes from the buffer as the arrived.
    with respect to the segment boundaries in the buffer.
    However, by ignoring these segment boundaries number of packets to send
    can be decreased.

    This flags will ignore the segment boundaries.

    Useful in conjunction with http layer.
*/
#define BUFFEREVENT_SSL_BATCH_WRITE 2

#if defined(EVENT__HAVE_OPENSSL) || defined(EVENT__HAVE_MBEDTLS)
/**
 * Get flags of the SSL bufferevent.
 *
 * @see BUFFEREVENT_SSL_*
 * @return flags or SIZE_MAX in case of error (if bufferevent is not SSL).
 */
EVENT2_EXPORT_SYMBOL
ev_uint64_t bufferevent_ssl_get_flags(struct bufferevent *bev);
/** Change the flags that are set for an ssl bufferevent by adding more.
 *
 * @param bev the ssl bufferevent.
 * @param flags One or more BUFFEREVENT_SSL_* options
 * @return old flags success, EV_UINT64_MAX on failure.
 */
EVENT2_EXPORT_SYMBOL
ev_uint64_t bufferevent_ssl_set_flags(struct bufferevent *bev, ev_uint64_t flags);
/** Change the flags that are set for an ssl bufferevent by removing some.
 *
 * @param bev the bufferevent.
 * @param flags One or more BUFFEREVENT_SSL_* options
 * @return old flags success, EV_UINT64_MAX on failure.
 */
EVENT2_EXPORT_SYMBOL
ev_uint64_t bufferevent_ssl_clear_flags(struct bufferevent *bev, ev_uint64_t flags);

#endif /* defined(EVENT__HAVE_OPENSSL) || defined(EVENT__HAVE_MBEDTLS) */

#if defined(EVENT__HAVE_OPENSSL) || defined(EVENT_IN_DOXYGEN_)
/* This is what openssl's SSL objects are underneath. */
struct ssl_st;

/**
   Create a new SSL bufferevent to send its data over another bufferevent.

   @param base An event_base to use to detect reading and writing.  It
      must also be the base for the underlying bufferevent.
   @param underlying A socket to use for this SSL
   @param ssl A SSL* object from openssl.
   @param state The current state of the SSL connection
   @param options One or more bufferevent_options
   @return A new bufferevent on success, or NULL on failure
*/
EVENT2_EXPORT_SYMBOL
struct bufferevent *
bufferevent_openssl_filter_new(struct event_base *base,
    struct bufferevent *underlying,
    struct ssl_st *ssl,
    enum bufferevent_ssl_state state,
    int options);

/**
   Create a new SSL bufferevent to send its data over an SSL * on a socket.

   @param base An event_base to use to detect reading and writing
   @param fd A socket to use for this SSL
   @param ssl A SSL* object from openssl.
   @param state The current state of the SSL connection
   @param options One or more bufferevent_options
   @return A new bufferevent on success, or NULL on failure.
*/
EVENT2_EXPORT_SYMBOL
struct bufferevent *
bufferevent_openssl_socket_new(struct event_base *base,
    evutil_socket_t fd,
    struct ssl_st *ssl,
    enum bufferevent_ssl_state state,
    int options);

/**
 * Get value of the BUFFEREVENT_SSL_DIRTY_SHUTDOWN flag.
 *
 * @see BUFFEREVENT_SSL_DIRTY_SHUTDOWN
 * @deprecated This function is deprecated, use bufferevent_ssl_get_flags() instead.
 * @see bufferevent_ssl_get_flags()
 */
EVENT2_EXPORT_SYMBOL
int bufferevent_openssl_get_allow_dirty_shutdown(struct bufferevent *bev);
/**
 * Set value of the BUFFEREVENT_SSL_DIRTY_SHUTDOWN flag.
 *
 * @see BUFFEREVENT_SSL_DIRTY_SHUTDOWN
 * @deprecated This function is deprecated, use bufferevent_ssl_set_flags() instead.
 * @see bufferevent_ssl_set_flags()
 */
EVENT2_EXPORT_SYMBOL
void bufferevent_openssl_set_allow_dirty_shutdown(struct bufferevent *bev,
    int allow_dirty_shutdown);

/** Return the underlying openssl SSL * object for an SSL bufferevent. */
EVENT2_EXPORT_SYMBOL
struct ssl_st *
bufferevent_openssl_get_ssl(struct bufferevent *bufev);

/** Tells a bufferevent to begin SSL renegotiation. */
EVENT2_EXPORT_SYMBOL
int bufferevent_ssl_renegotiate(struct bufferevent *bev);

/** Return the most recent OpenSSL error reported on an SSL bufferevent. */
EVENT2_EXPORT_SYMBOL
unsigned long bufferevent_get_openssl_error(struct bufferevent *bev);

#endif
#if defined(EVENT__HAVE_MBEDTLS) || defined(EVENT_IN_DOXYGEN_)
struct mbedtls_ssl_context;
/**
   Create a new SSL bufferevent to send its data over another bufferevent.

   @param base An event_base to use to detect reading and writing.  It
      must also be the base for the underlying bufferevent.
   @param underlying A socket to use for this SSL
   @param ssl A SSL* object from openssl.
   @param state The current state of the SSL connection
   @param options One or more bufferevent_options
   @return A new bufferevent on success, or NULL on failure
*/
EVENT2_EXPORT_SYMBOL
struct bufferevent *
bufferevent_mbedtls_filter_new(struct event_base *base,
    struct bufferevent *underlying,
    struct mbedtls_ssl_context *ssl,
    enum bufferevent_ssl_state state,
    int options);

/**
   Create a new SSL bufferevent to send its data over an SSL * on a socket.

   @param base An event_base to use to detect reading and writing
   @param fd A socket to use for this SSL
   @param ssl A SSL* object from mbedtls.
   @param state The current state of the SSL connection
   @param options One or more bufferevent_options
   @return A new bufferevent on success, or NULL on failure.
*/
EVENT2_EXPORT_SYMBOL
struct bufferevent *
bufferevent_mbedtls_socket_new(struct event_base *base,
    evutil_socket_t fd,
    struct mbedtls_ssl_context *ssl,
    enum bufferevent_ssl_state state,
    int options);

/**
 * Get value of the BUFFEREVENT_SSL_DIRTY_SHUTDOWN flag.
 *
 * @see BUFFEREVENT_SSL_DIRTY_SHUTDOWN
 * @deprecated This function is deprecated, use bufferevent_ssl_get_flags() instead.
 * @see bufferevent_ssl_get_flags()
 */
EVENT2_EXPORT_SYMBOL
int bufferevent_mbedtls_get_allow_dirty_shutdown(struct bufferevent *bev);
/**
 * Set value of the BUFFEREVENT_SSL_DIRTY_SHUTDOWN flag.
 *
 * @see BUFFEREVENT_SSL_DIRTY_SHUTDOWN
 * @deprecated This function is deprecated, use bufferevent_ssl_set_flags() instead.
 * @see bufferevent_ssl_set_flags()
 */
EVENT2_EXPORT_SYMBOL
void bufferevent_mbedtls_set_allow_dirty_shutdown(struct bufferevent *bev,
    int allow_dirty_shutdown);

/** Return the underlying mbedtls SSL * object for an SSL bufferevent. */
EVENT2_EXPORT_SYMBOL
struct mbedtls_ssl_context *
bufferevent_mbedtls_get_ssl(struct bufferevent *bufev);

/** Tells a bufferevent to begin SSL renegotiation. */
EVENT2_EXPORT_SYMBOL
int bufferevent_mbedtls_renegotiate(struct bufferevent *bev);

/** Return the most recent OpenSSL error reported on an SSL bufferevent. */
EVENT2_EXPORT_SYMBOL
unsigned long bufferevent_get_mbedtls_error(struct bufferevent *bev);

#endif

#ifdef __cplusplus
}
#endif

#endif /* EVENT2_BUFFEREVENT_SSL_H_INCLUDED_ */
