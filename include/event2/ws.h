#ifndef EVENT2_WS_H_INCLUDED_
#define EVENT2_WS_H_INCLUDED_

struct evws_connection;

#define WS_CR_NONE 0
#define WS_CR_NORMAL 1000
#define WS_CR_PROTO_ERR 1002
#define WS_CR_DATA_TOO_BIG 1009

/** Opens new WebSocket session from HTTP request.
 *
 * @param req a request object
 * @param cb the callback function that gets invoked on receiving message
 * @param arg an additional context argument for the callback
 * @return a pointer to a newly initialized WebSocket connection or NULL
 *   on error
 * @see evws_close()
 * */
EVENT2_EXPORT_SYMBOL
struct evws_connection *evws_new_session(struct evhttp_request *req,
	void (*cb)(struct evws_connection *, char *, size_t, void *), void* arg);

/** Sends data over WebSocket connection */
EVENT2_EXPORT_SYMBOL
void evws_send(struct evws_connection *evws, char *packet_str, size_t str_len);

/** Closes a WebSocket connection with reason code */
EVENT2_EXPORT_SYMBOL
void evws_close(struct evws_connection *evws, uint16_t reason);

/** Sets a callback for connection close. */
EVENT2_EXPORT_SYMBOL
void evws_connection_set_closecb(struct evws_connection *evws,
    void (*)(struct evws_connection *, void *), void *);

/** Frees a WebSocket connection */
EVENT2_EXPORT_SYMBOL
void evws_connection_free(struct evws_connection *evws);

/**
 * Return the bufferevent that an evws_connection is using.
 */
EVENT2_EXPORT_SYMBOL
struct bufferevent* evws_connection_get_bufferevent(struct evws_connection *evws);

#endif