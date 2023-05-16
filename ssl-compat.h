#ifndef SSL_COMPACT_H
#define SSL_COMPACT_H

#include "event.h"
#include "bufferevent-internal.h"
#include "event2/bufferevent_ssl.h"
struct bufferevent_ssl;

struct le_ssl_ops {
	void *(*init)(void *ssl);
	void (*free)(void *ssl, int flags);
	void (*free_raw)(void *ssl);
	int (*renegotiate)(void *ssl);
	int (*write)(void *ssl, const unsigned char *buf, size_t len);
	int (*read)(void *ssl, unsigned char *buf, size_t len);
	size_t (*pending)(void *ssl);
	int (*handshake)(void *ssl);
	int (*get_error)(void *ssl, int ret);
	void (*clear_error)(void);
	int (*clear)(void *ssl);
	void (*set_connect_state)(void *ssl);
	void (*set_accept_state)(void *ssl);
	int (*handshake_is_ok)(int err);
	int (*err_is_want_read)(int err);
	int (*err_is_want_write)(int err);
	evutil_socket_t (*get_fd)(void *ssl);
	int (*bio_set_fd)(struct bufferevent_ssl *ssl, evutil_socket_t fd);
	void (*init_bio_counts)(struct bufferevent_ssl *bev);
	void (*decrement_buckets)(struct bufferevent_ssl *bev);
	void (*conn_closed)(
		struct bufferevent_ssl *bev, int when, int errcode, int ret);
	void (*print_err)(int err);
};

struct bio_data_counts {
	unsigned long n_written;
	unsigned long n_read;
};

struct bufferevent_ssl {
	/* Shared fields with common bufferevent implementation code.
	   If we were set up with an underlying bufferevent, we use the
	   events here as timers only.  If we have an SSL, then we use
	   the events as socket events.
	 */
	struct bufferevent_private bev;
	/* An underlying bufferevent that we're directing our output to.
	   If it's NULL, then we're connected to an fd, not an evbuffer. */
	struct bufferevent *underlying;
	/* The SSL context doing our encryption. */
	void *ssl;
	/* The SSL operations doing on ssl. */
	struct le_ssl_ops *ssl_ops;

	/* A callback that's invoked when data arrives on our outbuf so we
	   know to write data to the SSL. */
	struct evbuffer_cb_entry *outbuf_cb;

	/* A count of how much data the bios have read/written total.  Used
	   for rate-limiting. */
	struct bio_data_counts counts;

	/* If this value is greater than 0, then the last SSL_write blocked,
	 * and we need to try it again with this many bytes. */
	ev_ssize_t last_write;

#define NUM_ERRORS 3
	ev_uint32_t errors[NUM_ERRORS];

	/* When we next get available space, we should say "read" instead of
	   "write". This can happen if there's a renegotiation during a read
	   operation. */
	unsigned read_blocked_on_write : 1;
	/* When we next get data, we should say "write" instead of "read". */
	unsigned write_blocked_on_read : 1;
	/* XXX */
	unsigned n_errors : 2;

	/* Are we currently connecting, accepting, or doing IO? */
	unsigned state : 2;
	/* If we reset fd, we sould reset state too */
	unsigned old_state : 2;

	ev_uint64_t flags;
};

struct bufferevent *bufferevent_ssl_new_impl(struct event_base *base,
	struct bufferevent *underlying, evutil_socket_t fd, void *ssl,
	enum bufferevent_ssl_state state, int options, struct le_ssl_ops *ssl_ops);
struct bufferevent_ssl *bufferevent_ssl_upcast(struct bufferevent *bev);
void bufferevent_ssl_put_error(
	struct bufferevent_ssl *bev_ssl, unsigned long err);
void bufferevent_ssl_stop_reading(struct bufferevent_ssl *bev_ssl);
void bufferevent_ssl_stop_writing(struct bufferevent_ssl *bev_ssl);
int bufferevent_ssl_renegotiate_impl(struct bufferevent *bev);
unsigned long bufferevent_get_ssl_error(struct bufferevent *bev);
int bufferevent_ssl_get_allow_dirty_shutdown(struct bufferevent *bev);
void bufferevent_ssl_set_allow_dirty_shutdown(
	struct bufferevent *bev, int allow_dirty_shutdown);

#endif /* SSL_COMPACT_H */
