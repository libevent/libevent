#ifndef EVENT2_WS_H_INCLUDED_
#define EVENT2_WS_H_INCLUDED_

struct evws_connection;

#define WS_CR_NONE 0
#define WS_CR_NORMAL 1000
#define WS_CR_PROTO_ERR 1002
#define WS_CR_DATA_TOO_BIG 1009

#define WS_TEXT_FRAME 0x1
#define WS_BINARY_FRAME 0x2

typedef void (*ws_on_msg_cb)(
	struct evws_connection *, int type, const unsigned char *, size_t, void *);
typedef void (*ws_on_close_cb)(struct evws_connection *, void *);

/** Opens new WebSocket session from HTTP request.
  @param req a request object
  @param cb the callback function that gets invoked on receiving message
  with len bytes length. In case of receiving text messages user is responsible
  to make a string with terminating \0 (with copying-out data) or use text data
  other way in which \0 is not required
  @param arg an additional context argument for the callback
  @return a pointer to a newly initialized WebSocket connection or NULL
	on error
  @see evws_close()
 */
EVENT2_EXPORT_SYMBOL
struct evws_connection *evws_new_session(
	struct evhttp_request *req, ws_on_msg_cb, void *arg, int options);

/** Sends data over WebSocket connection */
EVENT2_EXPORT_SYMBOL
void evws_send(
	struct evws_connection *evws, const char *packet_str, size_t str_len);

/** Closes a WebSocket connection with reason code */
EVENT2_EXPORT_SYMBOL
void evws_close(struct evws_connection *evws, uint16_t reason);

/** Sets a callback for connection close. */
EVENT2_EXPORT_SYMBOL
void evws_connection_set_closecb(
	struct evws_connection *evws, ws_on_close_cb, void *);

/** Frees a WebSocket connection */
EVENT2_EXPORT_SYMBOL
void evws_connection_free(struct evws_connection *evws);

/**
 * Return the bufferevent that an evws_connection is using.
 */
EVENT2_EXPORT_SYMBOL
struct bufferevent *evws_connection_get_bufferevent(
	struct evws_connection *evws);

#endif
