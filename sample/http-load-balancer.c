#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/in.h>

#include <event2/thread.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/http.h>
#include <event2/buffer.h>

#include "util-internal.h"

/*
 * Load balancer
 */

#define LOAD_BALANCER_ROUNDROBIN 0
#define LOAD_BALANCER_RANDOM 1

struct serve_connection {
	evutil_socket_t sockfd;
	struct sockaddr_storage saddr;
	socklen_t socklen;
};

/*
 * Worker thread
 */
struct worker {
	size_t id;

	pthread_t thread;

	struct event_base *base;
	struct evhttp *http;

	struct bufferevent *bev_delegate;
	struct bufferevent *bev_execute;
};

/*
 * Provide load balancing services for new connections
 */
struct load_balancer {
	// algorithm to use
	uint8_t balance_kind;
	// How many worker threads to create
	uint8_t nworkers;

	// worker thread
	struct event_base *_base;
	struct worker *_workers;
	uint8_t _i;
};

static void
worker_http_handler(struct evhttp_request *req, void *arg)
{
	struct worker *worker = arg;
	struct evbuffer *reply = evbuffer_new();
	evbuffer_add_printf(reply, "serve by worker %u\n", (unsigned)worker->id);
	evhttp_send_reply(req, 200, "Ok", reply);
	evbuffer_free(reply);
}

static void
worker_bev_execute_read_cb(struct bufferevent *bev, void *arg)
{
	struct worker *worker = (struct worker *)arg;
	struct serve_connection srvconn;
	struct evhttp_connection *in_evcon = NULL;
	int nbytes = -1;
	srvconn = (struct serve_connection){
		.sockfd=EVUTIL_INVALID_SOCKET,
		.saddr={0},
		.socklen=0,
	};
	nbytes = bufferevent_read(bev, &srvconn, sizeof(srvconn));
	if (nbytes == sizeof(srvconn)) {
		in_evcon = evhttp_serve(worker->http, srvconn.sockfd, (struct sockaddr *)&srvconn.saddr, srvconn.socklen, NULL);
		if (!in_evcon) {
			fprintf(stderr, "%s:%d can't serve a connection\n", __func__, __LINE__);
		}
	} else {
		fprintf(stderr, "%s:%d read %d bytes instead of %d\n", __func__, __LINE__, nbytes, (int)sizeof(srvconn));
	}
}

static void *
worker_on_thread(void *arg)
{
	struct worker *worker = (struct worker *)arg;
	event_base_dispatch(worker->base);
	return NULL;
}

static void
worker_cleanup(struct worker *worker)
{
	if (worker->bev_delegate) {
		bufferevent_free(worker->bev_delegate);
		worker->bev_delegate = NULL;
	}
	if (worker->bev_execute) {
		bufferevent_free(worker->bev_execute);
		worker->bev_execute = NULL;
	}
	if (worker->http) {
		evhttp_free(worker->http);
		worker->http = NULL;
	}
	if (worker->base) {
		event_base_free(worker->base);
		worker->base = NULL;
	}
}

static int
worker_init(struct load_balancer *balancer, struct worker *worker, int id)
{
	evutil_socket_t pipefds[2] = { EVUTIL_INVALID_SOCKET, EVUTIL_INVALID_SOCKET };
	memset(worker, 0x00, sizeof(*worker));
	worker->id = id;
	worker->base = event_base_new();
	if (!worker->base) {
		fprintf(stderr, "%s:%d event_base_new fail\n", __func__, __LINE__);
		return -1;
	}
	worker->http = evhttp_new(worker->base);
	if (!worker->http) {
		fprintf(stderr, "%s:%d evhttp_new fail\n", __func__, __LINE__);
		return -1;
	}
	evhttp_set_gencb(worker->http, worker_http_handler, worker);

	if (evutil_make_internal_pipe_(pipefds)) {
		perror("pipe2");
		return -1;
	}

	worker->bev_delegate = bufferevent_socket_new(balancer->_base, pipefds[1], BEV_OPT_CLOSE_ON_FREE);
	worker->bev_execute = bufferevent_socket_new(worker->base, pipefds[0], BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	bufferevent_setcb(worker->bev_delegate, NULL, NULL, NULL, worker);
	if (bufferevent_enable(worker->bev_delegate, EV_WRITE)) {
		fprintf(stderr, "%s:%d bufferevent_enable failed\n", __func__, __LINE__);
		return -1;
	}

	bufferevent_setcb(worker->bev_execute, worker_bev_execute_read_cb, NULL, NULL, worker);
	if (bufferevent_enable(worker->bev_execute, EV_READ)) {
		fprintf(stderr, "%s:%d bufferevent_enable failed\n", __func__, __LINE__);
		return -1;
	}

	if (pthread_create(&worker->thread, NULL, worker_on_thread, worker)) {
		perror("pthread_create");
		return -1;
	}
	pthread_detach(worker->thread);
	return 0;
}

static int
load_balancer_init(struct load_balancer *balancer)
{
	balancer->_base = event_base_new();
	if (!balancer->_base) {
		fprintf(stderr, "%s:%d event_base_new fail", __func__, __LINE__);
		return -1;
	}

	balancer->_workers = calloc(balancer->nworkers, sizeof(struct worker));
	if (!balancer->_workers) {
		perror("malloc");
		return -1;
	}

	// create work thread
	for (ssize_t i = 0; i < balancer->nworkers; ++i) {
		if (worker_init(balancer, &balancer->_workers[i], i) == -1) {
			for (;i>=0;--i) {
				worker_cleanup(&balancer->_workers[i]);
			}
			free(balancer->_workers);
			balancer->_workers = NULL;
			break;
		}
	}

	return 0;
}

static void
load_balancer_destroy(struct load_balancer *balancer)
{
	if (balancer->_base) {
		event_base_free(balancer->_base);
		balancer->_base = NULL;
	}
	if (!balancer->_workers) {
		return;
	}
	for (size_t i = 0; i < balancer->nworkers; i++) {
		worker_cleanup(balancer->_workers + i);
	}
	free(balancer->_workers);
	balancer->_workers = 0;
}

static void
load_balancer_serve(struct load_balancer *balancer, evutil_socket_t sockfd, const struct sockaddr *addr, socklen_t socklen)
{
	// Return worker according to algorithm
	struct worker *worker = NULL;
	struct serve_connection srvconn = {0};
	switch (balancer->balance_kind) {
		case LOAD_BALANCER_RANDOM:
			worker = &balancer->_workers[rand() % balancer->nworkers];
		break;
		case LOAD_BALANCER_ROUNDROBIN:
		default:
			worker = &balancer->_workers[balancer->_i];
			if (++balancer->_i == balancer->nworkers) {
				balancer->_i = 0;
			}
		break;
	}

	// Push task to back
	srvconn = (struct serve_connection){
		.sockfd=sockfd,
		.saddr={0},
		.socklen=socklen,
	};
	memcpy(&srvconn.saddr, addr, socklen);
	if (bufferevent_write(worker->bev_delegate, &srvconn, sizeof(srvconn))) {
		fprintf(stderr, "%s:%d bufferevent_write failed\n", __func__, __LINE__);
		return;
	}
	if (bufferevent_flush(worker->bev_delegate, EV_WRITE, BEV_FLUSH)) {
		fprintf(stderr, "%s:%d bufferevent_flush failed\n", __func__, __LINE__);
		return;
	}
}

static void
evconnlistener_tcp_cb(struct evconnlistener *listener, evutil_socket_t s, struct sockaddr *addr, int socklen, void *ptr)
{
	// Let the load balancer handle the connection
	load_balancer_serve((struct load_balancer *)ptr, s, addr, socklen);
}

struct options {
	int nworkers;
	int balancer_kind;
	int port;
	int verbose;
};

static void
print_usage(FILE *out, const char *prog, int exit_code)
{
	fprintf(out,
		"Syntax: %s [ OPTS ]\n"
		" -n      - number of workers, default 8\n"
		" -b      - which balancer (0: robin, 1: random), default 0\n"
		" -p      - port\n"
		" -v      - verbosity, enables libevent debug logging too\n", prog);
	exit(exit_code);
}

static struct options
parse_opts(int argc, char **argv)
{
	struct options o = {
		.nworkers=8,
		.balancer_kind=0,
		.port=9000,
		.verbose=0,
	};

	int opt;
	while ((opt = getopt(argc, argv, "hn:b:p:v")) != -1) {
		switch (opt) {
			case 'n': o.nworkers = atoi(optarg); break;
			case 'b': o.balancer_kind = atoi(optarg); break;
			case 'p': o.port = atoi(optarg); break;
			case 'v': ++o.verbose; break;
			case 'h': print_usage(stdout, argv[0], 0); break;
			default : fprintf(stderr, "Unknown option %c\n", opt); break;
		}
	}

	if (o.nworkers < 1) {
		o.nworkers = 8;
	}

	return o;
}

int
main(int argc, char **argv)
{
	struct sockaddr_in6 sin6;
	struct sockaddr *addr = (struct sockaddr *)&sin6;
	socklen_t sa_len = sizeof(sin6);
	struct load_balancer balancer = {0};
	struct evconnlistener *evlistener = NULL;
	struct options o = parse_opts(argc, argv);

	if (o.verbose || getenv("EVENT_DEBUG_LOGGING_ALL")) {
		event_enable_debug_logging(EVENT_DBG_ALL);
	}

	// parse address
	sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_port = htons((uint16_t)o.port),
		.sin6_addr = in6addr_any,
	};

	// enable multithreading
	if (evthread_use_pthreads()) {
		fprintf(stderr, "%s:%d evthread_use_pthreads fail\n", __func__, __LINE__);
		return EXIT_FAILURE;
	}

	// Create a load balancer to distribute requests to different threads for processing
	balancer = (struct load_balancer){
		.balance_kind=o.balancer_kind,
		.nworkers=o.nworkers,
	};
	if (load_balancer_init(&balancer)) {
		fprintf(stderr, "%s:%d load_balancer_init fail\n", __func__, __LINE__);
		return EXIT_FAILURE;
	}

	// create listener;
	evlistener = evconnlistener_new_bind(
			balancer._base,
			evconnlistener_tcp_cb, &balancer,
			LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_DISABLED,
			128,
			addr, sa_len);
	if (!evlistener) {
		perror("evconnlistener_new_bind");
		goto err;
	}

	printf("http async listener work on: %d\n", o.port);

	// enable accept
	evconnlistener_enable(evlistener);
	// dispatch libevent
	event_base_dispatch(balancer._base);

	return EXIT_SUCCESS;
err:
	load_balancer_destroy(&balancer);
	libevent_global_shutdown();
	return EXIT_FAILURE;
}
