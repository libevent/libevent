#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/ws.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <getopt.h>
#include <io.h>

#ifndef stat
#define stat _stat
#endif
#ifndef fstat
#define fstat _fstat
#endif
#ifndef open
#define open _open
#endif
#ifndef close
#define close _close
#endif
#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif

#else /* !_WIN32 */
#include <unistd.h>
#endif /* _WIN32 */

#define log_d(...) fprintf(stderr, __VA_ARGS__)

typedef struct client {
	struct evws_connection *evws;
	char name[INET6_ADDRSTRLEN];
	TAILQ_ENTRY(client) next;
} client_t;
typedef TAILQ_HEAD(clients_s, client) clients_t;
static clients_t clients;

static void
broadcast_msg(char *msg)
{
	struct client *client;

	TAILQ_FOREACH (client, &clients, next) {
		evws_send(client->evws, msg, strlen(msg));
	}
	log_d("%s\n", msg);
}

static void
on_msg_cb(struct evws_connection *evws, char *data, size_t len, void *arg)
{
	struct client *self = arg;
	char buf[4096];

	if (strcmp(data, "/quit") == 0) {
		evws_close(evws, WS_CR_NORMAL);
		snprintf(buf, sizeof(buf), "'%s' left the chat", self->name);
	} else if (strncmp(data, "/name ", 6) == 0) {
		char *new_name = data + 6;
		snprintf(buf, sizeof(buf), "'%s' renamed itself to '%s'", self->name,
			new_name);
		strncpy(self->name, new_name, sizeof(self->name) - 1);
	} else {
		snprintf(buf, sizeof(buf), "[%s] %s", self->name, data);
	}

	broadcast_msg(buf);
}

static void
on_close_cb(struct evws_connection *evws, void *arg)
{
	client_t *client = arg;
	log_d("'%s' disconnected\n", client->name);
	TAILQ_REMOVE(&clients, client, next);
	free(arg);
}

static const char *
nice_addr(const char *addr)
{
	if (strncmp(addr, "::ffff:", 7) == 0)
		addr += 7;

	return addr;
}

static void
addr2str(struct sockaddr *sa, char *addr, size_t len)
{
	const char *nice;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)sa;
		evutil_inet_ntop(AF_INET, &s->sin_addr, addr, len);
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)sa;
		evutil_inet_ntop(AF_INET6, &s->sin6_addr, addr, len);
		nice = nice_addr(addr);
		if (nice != addr) {
			size_t len = strlen(addr) - (nice - addr);
			memmove(addr, nice, len);
			addr[len] = 0;
		}
	}
}


static void
on_ws(struct evhttp_request *req, void *arg)
{
	struct client *client;
	evutil_socket_t fd;
	struct sockaddr_storage addr;
	socklen_t len;

	client = calloc(sizeof(*client), 1);
	client->evws = evws_new_session(req, on_msg_cb, client);
	fd = bufferevent_getfd(evws_connection_get_bufferevent(client->evws));

	len = sizeof(addr);
	getpeername(fd, (struct sockaddr *)&addr, &len);

	addr2str((struct sockaddr *)&addr, client->name, sizeof(client->name));
	log_d("New client joined from %s\n", client->name);

	evws_connection_set_closecb(client->evws, on_close_cb, client);
	TAILQ_INSERT_TAIL(&clients, client, next);
}

static void
on_html(struct evhttp_request *req, void *arg)
{
	int fd = -1;
	struct evbuffer *evb;
	struct stat st;

	evhttp_add_header(
		evhttp_request_get_output_headers(req), "Content-Type", "text/html");
	if ((fd = open("ws-chat.html", O_RDONLY)) < 0) {
		perror("open");
		goto err;
	}

	if (fstat(fd, &st)<0) {
		/* Make sure the length still matches, now that we
		 * opened the file :/ */
		perror("fstat");
		goto err;
	}


	evb = evbuffer_new();
	evbuffer_add_file(evb, fd, 0, st.st_size);
	close(fd);
	evhttp_send_reply(req, HTTP_OK, NULL, evb);
	evbuffer_free(evb);
	return;

err:
	evhttp_send_error(req, HTTP_NOTFOUND, NULL);
	if (fd>=0)
		close(fd);
}

#ifndef EVENT__HAVE_STRSIGNAL
static inline const char* strsignal(evutil_socket_t sig) { return "Signal"; }
#endif

static void
signal_cb(evutil_socket_t fd, short event, void *arg)
{
	printf("%s signal received\n", strsignal(fd));
	event_base_loopbreak(arg);
}

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct event *sig_int;
	struct evhttp *http_server;

	TAILQ_INIT(&clients);

	base = event_base_new();

	sig_int = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(sig_int, NULL);

	http_server = evhttp_new(base);
	evhttp_bind_socket_with_handle(http_server, "0.0.0.0", 8080);

	evhttp_set_cb(http_server, "/", on_html, NULL);
	evhttp_set_cb(http_server, "/ws", on_ws, NULL);

	log_d("Server runs\n");
	event_base_dispatch(base);

	log_d("Active connections: %d\n", evhttp_get_connection_count(http_server));
	evhttp_free(http_server);

	event_free(sig_int);
	event_base_free(base);
	libevent_global_shutdown();
}
