/*
  This is an simple example of https/(http) client access Internet over https or
  socks5 proxy
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define snprintf _snprintf
#define strcasecmp _stricmp
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#ifdef USE_MBEDTLS
#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#ifdef USE_MBEDTLS
#else
#include "openssl_hostname_validation.h"
#endif

int g_nSocks5OrHttps = 1;
char g_szProxyHost[] = "192.168.88.1";
unsigned short g_usPorxyPort = 1913;
const char g_szTargetHost[] = "www.bing.com"; // https://www.bing.com

struct CtxSocks5 {
	char domainName[256];
	int fd;
	struct sockaddr_in addr4;
	char ipv4[32];
	unsigned short port;
};

static void
SetSocketOption(int s, int nTimeoutSec)
{
	struct timeval timeo = {nTimeoutSec, 0};
	socklen_t len = sizeof(timeo);
	setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &timeo, len);
	setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeo, len);
}

static int
ReadSocks5Rep(unsigned char method)
{
	if (method == 0x00)
		return 0;
	else if (method == 0x01)
		return -1;
	else if (method == 0x02) {
		// not support auth with name-password
		return -1;
	} else if (method >= 0x03 && method <= 0x7F)
		return -1;
	else if (method >= 0x80 && method <= 0xFE)
		return -1;
	else
		return -1;
}

static int
RequestSocks5Target(struct CtxSocks5 *socks5)
{
	uint32_t lenght = 0;
	uint32_t itr = 0;
	unsigned char msg[512] = {0};
	int nDNLength = strlen(socks5->domainName);
	msg[0] = 0x05;
	msg[1] = 0x01;
	msg[2] = 0x00;
	if (strlen(socks5->ipv4)) {
		msg[3] = 0x01;
		memcpy((unsigned char *)msg + 4,
			(unsigned char *)&socks5->addr4.sin_addr,
			sizeof(socks5->addr4.sin_addr));
		*(unsigned short *)(msg + 8) = htons(socks5->port);
		lenght = 10;
	} else if (nDNLength) {
		msg[3] = 0x03;
		msg[4] = (unsigned char)nDNLength;
		for (itr = 0; itr != msg[4]; ++itr)
			msg[itr + 5] = socks5->domainName[itr];
		*(unsigned short *)(msg + 5 + nDNLength) = htons(socks5->port);
		lenght = 5 + nDNLength + 2;
	} else
		return -1;
	if (send(socks5->fd, msg, lenght, 0) <= 0)
		return -2;

	return 0;
}

static int
SetAddress(struct CtxSocks5 *socks5, const char *address, unsigned short port)
{
	socks5->port = port;
	if (!evutil_inet_pton(AF_INET, address, &socks5->addr4.sin_addr))
		strcpy(socks5->domainName, address);
	else
		strcpy(socks5->ipv4, address);
	return 0;
}

static int
ConnectSocks5(struct CtxSocks5 *socks5)
{
	unsigned char tmp[512];
	if (3 != send(socks5->fd, "\x05\x01\x00", 3, 0))
		return -1;
	if (recv(socks5->fd, tmp, 512, 0) != 2)
		return -2;
	if (ReadSocks5Rep(tmp[1]))
		return -3;
	return 0;
}

static int
ConnectTargetViaSocks5(struct CtxSocks5 *socks5)
{
	int ret;
	unsigned char tmp[512];
	if (RequestSocks5Target(socks5))
		return -1;
	ret = recv(socks5->fd, tmp, 512, 0);
	if (ret < 0 || tmp[1] != 0)
		return -2;
	return 0;
}

// just support no auth socks5 proxy. Such as 'ssh -D'.
static int
Socks5Handshake(int fd, const char *szTargetHost, unsigned short port)
{
	int bOK = 0;
	struct CtxSocks5 s5;
	memset(&s5, 0, sizeof(struct CtxSocks5));
	do {
		// init
		s5.fd = fd;
		// do
		if (SetAddress(&s5, szTargetHost, port)) {
			fprintf(stderr, "Socks5Handshake SetAddress failed");
			break;
		}
		if (ConnectSocks5(&s5)) {
			fprintf(stderr, "Socks5Handshake ConnectSocks5 failed");
			break;
		}
		if (ConnectTargetViaSocks5(&s5)) {
			fprintf(stderr, "Socks5Handshake ConnectTargetViaSocks5 failed");
			break;
		}

		bOK = 1;
	} while (0);
	return bOK;
}

// http or https proxy
static int
RequestHttpProxyConnect(int fd)
{
	char szBuf[512];
	int nRet = -1, nChildRet = 0;
	do {
		sprintf(szBuf,
			"CONNECT %s:%d HTTP/1.0\r\nHost: "
			"%s:%d\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\n\r\n",
			g_szTargetHost, 443, g_szProxyHost, g_usPorxyPort);
		if ((nChildRet = send(fd, szBuf, strlen(szBuf), 0)) <= 0)
			break;
		memset(szBuf, 0, sizeof(szBuf));
		if ((nChildRet = recv(fd, szBuf, sizeof(szBuf), 0)) < 32)
			break;
		if (!strstr(szBuf, "HTTP/1.1 200 ") && !strstr(szBuf, "HTTP/1.0 200 "))
			break;
		nRet = 0;
	} while (0);
	return nRet;
}

static int
EvhttpConnectSuccessCallback(struct evhttp_connection *evConn, void *arg)
{
	struct bufferevent *bev = evhttp_connection_get_bufferevent(evConn);
	int nRet = -1, fd = bufferevent_getfd(bev), nOrigFlags,
		flags = fcntl(fd, F_GETFL, 0);
	nOrigFlags = flags;
	do {
		// write timeout check
		fd_set w;
		struct timeval timeout = {};
		timeout.tv_sec = 3;
		FD_ZERO(&w);
		FD_SET(fd, &w);
		if (select(fd + 1, NULL, &w, NULL, &timeout) <= 0)
			break;
		FD_CLR(fd, &w);
		// must
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK); // set block
		SetSocketOption(fd, 8);
		// choice
		if (g_nSocks5OrHttps) {
			if (!Socks5Handshake(fd, g_szTargetHost, 443))
				break;
		} else {
			if (RequestHttpProxyConnect(fd))
				break;
		}
		nRet = 0;
	} while (0);
	SetSocketOption(fd, 30);
	fcntl(fd, F_SETFL, nOrigFlags); // restore
	return nRet;
}

static void
http_request_done(struct evhttp_request *req, void *arg)
{
	char buffer[4096];
	int nread = 0;
	if (!req) {
		fprintf(stderr, "Http reponse failed\n");
		return;
	}
	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
				buffer, sizeof(buffer))) > 0) {
		printf("%s", (char *)buffer);
		memset(buffer, 0, sizeof(buffer));
	}
	return;
}

int
main(int argc, char **argv)
{
	int r;
	struct event_base *base = NULL;
	struct evhttp_uri *http_uri = NULL;
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	struct evkeyvalq *headerOutput;
	int ret = 0;

	do {
		printf("http client proxy begin\n");
		ssl_ctx = SSL_CTX_new(SSLv23_method());
		if (!ssl_ctx)
			break;
		base = event_base_new();
		if (!base)
			break;
		ssl = SSL_new(ssl_ctx);
		if (ssl == NULL)
			break;
		bev = bufferevent_openssl_socket_new(
			base, -1, ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
		if (bev == NULL)
			break;
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
		evcon = evhttp_connection_base_bufferevent_new(
			base, NULL, bev, g_szProxyHost, g_usPorxyPort);
		if (evcon == NULL)
			break;
		req = evhttp_request_new(http_request_done, bev);
		if (req == NULL)
			break;
		headerOutput = evhttp_request_get_output_headers(req);
		evhttp_add_header(headerOutput, "Host", g_szTargetHost);
		evhttp_add_header(headerOutput, "Connection", "close");
		evhttp_connection_set_connectcb(
			evcon, EvhttpConnectSuccessCallback, NULL);
		r = evhttp_make_request(evcon, req, EVHTTP_REQ_GET, "/");
		if (r != 0) {
			fprintf(stderr, "evhttp_make_request() failed\n");
			break;
		}
		event_base_dispatch(base);
		ret = 1;
		break;
	} while (0);

	if (evcon)
		evhttp_connection_free(evcon);
	if (http_uri)
		evhttp_uri_free(http_uri);
	if (base)
		event_base_free(base);
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	return ret;
}