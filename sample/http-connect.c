#include <event2/event.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/buffer.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>

struct connect_base
{
	struct evhttp_connection *evcon;
	struct evhttp_uri *location;
};

void get_cb(struct evhttp_request *req, void *arg)
{
	assert(req);
	evbuffer_write(req->input_buffer, STDOUT_FILENO);
}

void connect_cb(struct evhttp_request *proxy_req, void *arg)
{
	char buffer[PATH_MAX];

	struct connect_base *base = arg;
	struct evhttp_connection *evcon = base->evcon;
	struct evhttp_uri *location = base->location;

	assert(proxy_req);
	if (evcon) {
		struct evhttp_request *req = evhttp_request_new(get_cb, NULL);
		evhttp_add_header(req->output_headers, "Connection", "close");
		assert(!evhttp_make_request(evcon, req, EVHTTP_REQ_GET,
			evhttp_uri_join(location, buffer, PATH_MAX)));
	}
}

int main(int argc, const char **argv)
{
	char buffer[PATH_MAX];

	struct evhttp_uri *host_port;
	struct evhttp_uri *location;
	struct evhttp_uri *proxy;

	struct event_base *base;
	struct evhttp_connection *evcon;
	struct evhttp_request *req;

	if (argc != 3) {
		printf("Usage: %s proxy url\n", argv[0]);
		return 1;
	}

	{
		proxy = evhttp_uri_parse(argv[1]);
		assert(evhttp_uri_get_host(proxy));
		assert(evhttp_uri_get_port(proxy) > 0);
	}
	{
		host_port = evhttp_uri_parse(argv[2]);
		evhttp_uri_set_scheme(host_port, NULL);
		evhttp_uri_set_userinfo(host_port, NULL);
		evhttp_uri_set_path(host_port, NULL);
		evhttp_uri_set_query(host_port, NULL);
		evhttp_uri_set_fragment(host_port, NULL);
		assert(evhttp_uri_get_host(host_port));
		assert(evhttp_uri_get_port(host_port) > 0);
	}
	{
		location = evhttp_uri_parse(argv[2]);
		evhttp_uri_set_scheme(location, NULL);
		evhttp_uri_set_userinfo(location, 0);
		evhttp_uri_set_host(location, NULL);
		evhttp_uri_set_port(location, -1);
	}

	assert(base = event_base_new());
	assert(evcon = evhttp_connection_base_new(base, NULL,
		evhttp_uri_get_host(proxy), evhttp_uri_get_port(proxy)));
	struct connect_base connect_base = {
		.evcon = evcon,
		.location = location,
	};
	assert(req = evhttp_request_new(connect_cb, &connect_base));

	evhttp_add_header(req->output_headers, "Connection", "keep-alive");
	evhttp_add_header(req->output_headers, "Proxy-Connection", "keep-alive");
	evutil_snprintf(buffer, PATH_MAX, "%s:%d",
		evhttp_uri_get_host(host_port), evhttp_uri_get_port(host_port));
	evhttp_make_request(evcon, req, EVHTTP_REQ_CONNECT, buffer);

	event_base_dispatch(base);
	evhttp_connection_free(evcon);
	event_base_free(base);
	evhttp_uri_free(proxy);
	evhttp_uri_free(host_port);
	evhttp_uri_free(location);
	return 0;
}
