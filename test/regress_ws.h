#ifndef REGRESS_WS_H
#define REGRESS_WS_H

void http_on_ws_cb(struct evhttp_request *req, void *arg);
void http_ws_test(void *arg);

#endif /* REGRESS_WS_H */
