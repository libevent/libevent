#ifndef REGRESS_HTTP_H
#define REGRESS_HTTP_H

struct evhttp *http_setup(
	ev_uint16_t *pport, struct event_base *base, int mask);
evutil_socket_t http_connect(const char *address, ev_uint16_t port);
struct bufferevent *create_bev(
	struct event_base *base, evutil_socket_t fd, int ssl_mask, int flags_);
void http_writecb(struct bufferevent *bev, void *arg);

#endif /* REGRESS_HTTP_H */
