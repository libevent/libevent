/*
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
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
#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#include <sys/types.h>
#ifdef _EVENT_HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef _EVENT_HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef _EVENT_HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef _EVENT_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef _EVENT_HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef _EVENT_HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef _EVENT_HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif

#ifndef _EVENT_HAVE_GETTIMEOFDAY
#include <sys/timeb.h>
#include <time.h>
#endif

#include "event2/util.h"
#include "util-internal.h"
#include "log-internal.h"

#include "strlcpy-internal.h"
#include "ipv6-internal.h"

int
evutil_socketpair(int family, int type, int protocol, evutil_socket_t fd[2])
{
#ifndef WIN32
	return socketpair(family, type, protocol, fd);
#else
	/* This code is originally from Tor.  Used with permission. */

	/* This socketpair does not work when localhost is down. So
	 * it's really not the same thing at all. But it's close enough
	 * for now, and really, when localhost is down sometimes, we
	 * have other problems too.
	 */
	evutil_socket_t listener = -1;
	evutil_socket_t connector = -1;
	evutil_socket_t acceptor = -1;
	struct sockaddr_in listen_addr;
	struct sockaddr_in connect_addr;
	int size;
	int saved_errno = -1;

	if (protocol
		|| (family != AF_INET
#ifdef AF_UNIX
		    && family != AF_UNIX
#endif
		)) {
		EVUTIL_SET_SOCKET_ERROR(WSAEAFNOSUPPORT);
		return -1;
	}
	if (!fd) {
		EVUTIL_SET_SOCKET_ERROR(WSAEINVAL);
		return -1;
	}

	listener = socket(AF_INET, type, 0);
	if (listener < 0)
		return -1;
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	listen_addr.sin_port = 0;	/* kernel chooses port.	 */
	if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
		== -1)
		goto tidy_up_and_fail;
	if (listen(listener, 1) == -1)
		goto tidy_up_and_fail;

	connector = socket(AF_INET, type, 0);
	if (connector < 0)
		goto tidy_up_and_fail;
	/* We want to find out the port number to connect to.  */
	size = sizeof(connect_addr);
	if (getsockname(listener, (struct sockaddr *) &connect_addr, &size) == -1)
		goto tidy_up_and_fail;
	if (size != sizeof (connect_addr))
		goto abort_tidy_up_and_fail;
	if (connect(connector, (struct sockaddr *) &connect_addr,
				sizeof(connect_addr)) == -1)
		goto tidy_up_and_fail;

	size = sizeof(listen_addr);
	acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
	if (acceptor < 0)
		goto tidy_up_and_fail;
	if (size != sizeof(listen_addr))
		goto abort_tidy_up_and_fail;
	EVUTIL_CLOSESOCKET(listener);
	/* Now check we are talking to ourself by matching port and host on the
	   two sockets.	 */
	if (getsockname(connector, (struct sockaddr *) &connect_addr, &size) == -1)
		goto tidy_up_and_fail;
	if (size != sizeof (connect_addr)
		|| listen_addr.sin_family != connect_addr.sin_family
		|| listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
		|| listen_addr.sin_port != connect_addr.sin_port)
		goto abort_tidy_up_and_fail;
	fd[0] = connector;
	fd[1] = acceptor;

	return 0;

 abort_tidy_up_and_fail:
	saved_errno = WSAECONNABORTED;
 tidy_up_and_fail:
	if (saved_errno < 0)
		saved_errno = WSAGetLastError();
	if (listener != -1)
		EVUTIL_CLOSESOCKET(listener);
	if (connector != -1)
		EVUTIL_CLOSESOCKET(connector);
	if (acceptor != -1)
		EVUTIL_CLOSESOCKET(acceptor);

	EVUTIL_SET_SOCKET_ERROR(saved_errno);
	return -1;
#endif
}

int
evutil_make_socket_nonblocking(evutil_socket_t fd)
{
#ifdef WIN32
	{
		unsigned long nonblocking = 1;
		ioctlsocket(fd, FIONBIO, (unsigned long*) &nonblocking);
	}
#else
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		event_warn("fcntl(O_NONBLOCK)");
		return -1;
	}
#endif
	return 0;
}

int
evutil_make_listen_socket_reuseable(evutil_socket_t sock)
{
#ifndef WIN32
	int one = 1;
	/* REUSEADDR on Unix means, "don't hang on to this address after the
	 * listener is closed."  On Windows, though, it means "don't keep other
	 * processes from binding to this address while we're using it. */
	return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one,
	    (socklen_t)sizeof(one));
#else
	return 0;
#endif
}

ev_int64_t
evutil_strtoll(const char *s, char **endptr, int base)
{
#ifdef _EVENT_HAVE_STRTOLL
	return (ev_int64_t)strtoll(s, endptr, base);
#elif _EVENT_SIZEOF_LONG == 8
	return (ev_int64_t)strtol(s, endptr, base);
#elif defined(WIN32) && defined(_MSC_VER) && _MSC_VER < 1300
	/* XXXX on old versions of MS APIs, we only support base
	 * 10. */
	ev_int64_t r;
	if (base != 10)
		return 0;
	r = (ev_int64_t) _atoi64(s);
	while (isspace(*s))
		++s;
	while (isdigit(*s))
		++s;
	if (endptr)
		*endptr = (char*) s;
	return r;
#elif defined(WIN32)
	return (ev_int64_t) _strtoi64(s, endptr, base);
#else
#error "I don't know how to parse 64-bit integers."
#endif
}

#ifndef _EVENT_HAVE_GETTIMEOFDAY
int
evutil_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct _timeb tb;

	if(tv == NULL)
		return -1;

	_ftime(&tb);
	tv->tv_sec = (long) tb.time;
	tv->tv_usec = ((int) tb.millitm) * 1000;
	return 0;
}
#endif

#ifdef WIN32
int
evutil_socket_geterror(evutil_socket_t sock)
{
	int optval, optvallen=sizeof(optval);
	int err = WSAGetLastError();
	if (err == WSAEWOULDBLOCK && sock >= 0) {
		if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)&optval,
					   &optvallen))
			return err;
		if (optval)
			return optval;
	}
	return err;
}
#endif

#ifdef WIN32
#define E(code, s) { code, (s " [" #code " ]") }
static struct { int code; const char *msg; } windows_socket_errors[] = {
  E(WSAEINTR, "Interrupted function call"),
  E(WSAEACCES, "Permission denied"),
  E(WSAEFAULT, "Bad address"),
  E(WSAEINVAL, "Invalid argument"),
  E(WSAEMFILE, "Too many open files"),
  E(WSAEWOULDBLOCK,  "Resource temporarily unavailable"),
  E(WSAEINPROGRESS, "Operation now in progress"),
  E(WSAEALREADY, "Operation already in progress"),
  E(WSAENOTSOCK, "Socket operation on nonsocket"),
  E(WSAEDESTADDRREQ, "Destination address required"),
  E(WSAEMSGSIZE, "Message too long"),
  E(WSAEPROTOTYPE, "Protocol wrong for socket"),
  E(WSAENOPROTOOPT, "Bad protocol option"),
  E(WSAEPROTONOSUPPORT, "Protocol not supported"),
  E(WSAESOCKTNOSUPPORT, "Socket type not supported"),
  /* What's the difference between NOTSUPP and NOSUPPORT? :) */
  E(WSAEOPNOTSUPP, "Operation not supported"),
  E(WSAEPFNOSUPPORT,  "Protocol family not supported"),
  E(WSAEAFNOSUPPORT, "Address family not supported by protocol family"),
  E(WSAEADDRINUSE, "Address already in use"),
  E(WSAEADDRNOTAVAIL, "Cannot assign requested address"),
  E(WSAENETDOWN, "Network is down"),
  E(WSAENETUNREACH, "Network is unreachable"),
  E(WSAENETRESET, "Network dropped connection on reset"),
  E(WSAECONNABORTED, "Software caused connection abort"),
  E(WSAECONNRESET, "Connection reset by peer"),
  E(WSAENOBUFS, "No buffer space available"),
  E(WSAEISCONN, "Socket is already connected"),
  E(WSAENOTCONN, "Socket is not connected"),
  E(WSAESHUTDOWN, "Cannot send after socket shutdown"),
  E(WSAETIMEDOUT, "Connection timed out"),
  E(WSAECONNREFUSED, "Connection refused"),
  E(WSAEHOSTDOWN, "Host is down"),
  E(WSAEHOSTUNREACH, "No route to host"),
  E(WSAEPROCLIM, "Too many processes"),

  /* Yes, some of these start with WSA, not WSAE. No, I don't know why. */
  E(WSASYSNOTREADY, "Network subsystem is unavailable"),
  E(WSAVERNOTSUPPORTED, "Winsock.dll out of range"),
  E(WSANOTINITIALISED, "Successful WSAStartup not yet performed"),
  E(WSAEDISCON, "Graceful shutdown now in progress"),
#ifdef WSATYPE_NOT_FOUND
  E(WSATYPE_NOT_FOUND, "Class type not found"),
#endif
  E(WSAHOST_NOT_FOUND, "Host not found"),
  E(WSATRY_AGAIN, "Nonauthoritative host not found"),
  E(WSANO_RECOVERY, "This is a nonrecoverable error"),
  E(WSANO_DATA, "Valid name, no data record of requested type)"),

  /* There are some more error codes whose numeric values are marked
   * <b>OS dependent</b>. They start with WSA_, apparently for the same
   * reason that practitioners of some craft traditions deliberately
   * introduce imperfections into their baskets and rugs "to allow the
   * evil spirits to escape."  If we catch them, then our binaries
   * might not report consistent results across versions of Windows.
   * Thus, I'm going to let them all fall through.
   */
  { -1, NULL },
};
#undef E
/** Equivalent to strerror, but for windows socket errors. */
const char *
evutil_socket_error_to_string(int errcode)
{
  /* XXXX Is there really no built-in function to do this? */
  int i;
  for (i=0; windows_socket_errors[i].code >= 0; ++i) {
    if (errcode == windows_socket_errors[i].code)
      return windows_socket_errors[i].msg;
  }
  return strerror(errcode);
}
#endif

int
evutil_snprintf(char *buf, size_t buflen, const char *format, ...)
{
	int r;
	va_list ap;
	va_start(ap, format);
	r = evutil_vsnprintf(buf, buflen, format, ap);
	va_end(ap);
	return r;
}

int
evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap)
{
        int r;
        if (!buflen)
                return 0;
#ifdef _MSC_VER
	r = _vsnprintf(buf, buflen, format, ap);
	if (r < 0)
		r = _vscprintf(format, ap);
#else
	r = vsnprintf(buf, buflen, format, ap);
#endif
	buf[buflen-1] = '\0';
	return r;
}

#define USE_INTERNAL_NTOP
#define USE_INTERNAL_PTON

const char *
evutil_inet_ntop(int af, const void *src, char *dst, size_t len)
{
#if defined(_EVENT_HAVE_INET_NTOP) && !defined(USE_INTERNAL_NTOP)
	return inet_ntop(af, src, dst, len);
#else
	if (af == AF_INET) {
		const struct in_addr *in = src;
		const ev_uint32_t a = ntohl(in->s_addr);
		int r;
		r = evutil_snprintf(dst, len, "%d.%d.%d.%d",
							(int)(ev_uint8_t)((a>>24)&0xff),
							(int)(ev_uint8_t)((a>>16)&0xff),
							(int)(ev_uint8_t)((a>>8 )&0xff),
							(int)(ev_uint8_t)((a    )&0xff));
		if (r<0||(size_t)r>=len)
			return NULL;
		else
			return dst;
#ifdef AF_INET6
	} else if (af == AF_INET6) {
		const struct in6_addr *addr = src;
		char buf[64], *cp;
		int longestGapLen = 0, longestGapPos = -1, i,
			curGapPos = -1, curGapLen = 0;
		ev_uint16_t words[8];
		for (i = 0; i < 8; ++i) {
			words[i] =
				(((ev_uint16_t)addr->s6_addr[2*i])<<8) + addr->s6_addr[2*i+1];
		}
		if (words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0 &&
			words[4] == 0 && ((words[5] == 0 && words[6] && words[7]) ||
							  (words[5] == 0xffff))) {
			/* This is an IPv4 address. */
			if (words[5] == 0) {
				evutil_snprintf(buf, sizeof(buf), "::%d.%d.%d.%d",
								addr->s6_addr[12], addr->s6_addr[13],
								addr->s6_addr[14], addr->s6_addr[15]);
			} else {
				evutil_snprintf(buf, sizeof(buf), "::%x:%d.%d.%d.%d", words[5],
								addr->s6_addr[12], addr->s6_addr[13],
								addr->s6_addr[14], addr->s6_addr[15]);
			}
			if (strlen(buf) > len)
				return NULL;
			strlcpy(dst, buf, len);
			return dst;
		}
		i = 0;
		while (i < 8) {
			if (words[i] == 0) {
				curGapPos = i++;
				curGapLen = 1;
				while (i<8 && words[i] == 0) {
					++i; ++curGapLen;
				}
				if (curGapLen > longestGapLen) {
					longestGapPos = curGapPos;
					longestGapLen = curGapLen;
				}
			} else {
				++i;
			}
		}
		if (longestGapLen<=1)
			longestGapPos = -1;

		cp = buf;
		for (i = 0; i < 8; ++i) {
			if (words[i] == 0 && longestGapPos == i) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				while (i < 8 && words[i] == 0)
					++i;
				--i; /* to compensate for loop increment. */
			} else {
				evutil_snprintf(cp,
								sizeof(buf)-(cp-buf), "%x", (unsigned)words[i]);
				cp += strlen(cp);
				if (i != 7)
					*cp++ = ':';
			}
		}
		*cp = '\0';
		if (strlen(buf) > len)
			return NULL;
		strlcpy(dst, buf, len);
		return dst;
#endif
	} else {
		return NULL;
	}
#endif
}

int
evutil_inet_pton(int af, const char *src, void *dst)
{
#if defined(_EVENT_HAVE_INET_PTON) && !defined(USE_INTERNAL_PTON)
	return inet_pton(af, src, dst);
#else
	if (af == AF_INET) {
		int a,b,c,d;
		char more;
		struct in_addr *addr = dst;
		if (sscanf(src, "%d.%d.%d.%d%c", &a,&b,&c,&d,&more) != 4)
			return 0;
		if (a < 0 || a > 255) return 0;
		if (b < 0 || b > 255) return 0;
		if (c < 0 || c > 255) return 0;
		if (d < 0 || d > 255) return 0;
		addr->s_addr = htonl((a<<24) | (b<<16) | (c<<8) | d);
		return 1;
#ifdef AF_INET6
	} else if (af == AF_INET6) {
		struct in6_addr *out = dst;
		ev_uint16_t words[8];
		int gapPos = -1, i, setWords=0;
		const char *dot = strchr(src, '.');
		const char *eow; /* end of words. */
		if (dot == src)
			return 0;
		else if (!dot)
			eow = src+strlen(src);
		else {
			int byte1,byte2,byte3,byte4;
			char more;
			for (eow = dot-1; eow >= src && EVUTIL_ISDIGIT(*eow); --eow)
				;
			++eow;

			/* We use "scanf" because some platform inet_aton()s are too lax
			 * about IPv4 addresses of the form "1.2.3" */
			if (sscanf(eow, "%d.%d.%d.%d%c",
					   &byte1,&byte2,&byte3,&byte4,&more) != 4)
				return 0;

			if (byte1 > 255 || byte1 < 0 ||
				byte2 > 255 || byte2 < 0 ||
				byte3 > 255 || byte3 < 0 ||
				byte4 > 255 || byte4 < 0)
				return 0;

			words[6] = (byte1<<8) | byte2;
			words[7] = (byte3<<8) | byte4;
			setWords += 2;
		}

		i = 0;
		while (src < eow) {
			if (i > 7)
				return 0;
			if (EVUTIL_ISXDIGIT(*src)) {
				char *next;
				long r = strtol(src, &next, 16);
				if (next > 4+src)
					return 0;
				if (next == src)
					return 0;
				if (r<0 || r>65536)
					return 0;

				words[i++] = (ev_uint16_t)r;
				setWords++;
				src = next;
				if (*src != ':' && src != eow)
					return 0;
				++src;
			} else if (*src == ':' && i > 0 && gapPos==-1) {
				gapPos = i;
				++src;
			} else if (*src == ':' && i == 0 && src[1] == ':' && gapPos==-1) {
				gapPos = i;
				src += 2;
			} else {
				return 0;
			}
		}

		if (setWords > 8 ||
			(setWords == 8 && gapPos != -1) ||
			(setWords < 8 && gapPos == -1))
			return 0;

		if (gapPos >= 0) {
			int nToMove = setWords - (dot ? 2 : 0) - gapPos;
			int gapLen = 8 - setWords;
			/* assert(nToMove >= 0); */
			if (nToMove < 0)
				return -1; /* should be impossible */
			memmove(&words[gapPos+gapLen], &words[gapPos],
					sizeof(ev_uint16_t)*nToMove);
			memset(&words[gapPos], 0, sizeof(ev_uint16_t)*gapLen);
		}
		for (i = 0; i < 8; ++i) {
			out->s6_addr[2*i  ] = words[i] >> 8;
			out->s6_addr[2*i+1] = words[i] & 0xff;
		}

		return 1;
#endif
	} else {
		return -1;
	}
#endif
}

int
evutil_parse_sockaddr_port(const char *ip_as_string, struct sockaddr *out, int *outlen)
{
	int port;
	char buf[128];
	const char *cp, *addr_part, *port_part;
	int is_ipv6;
	/* recognized formats are:
	 * [ipv6]:port
	 * ipv6
	 * [ipv6]
	 * ipv4:port
	 * ipv4
	 */

	cp = strchr(ip_as_string, ':');
	if (*ip_as_string == '[') {
		int len;
		if (!(cp = strchr(ip_as_string, ']'))) {
			return -1;
		}
		len = cp-(ip_as_string + 1);
		if (len > (int)sizeof(buf)-1) {
			return -1;
		}
		memcpy(buf, ip_as_string+1, len);
		buf[len] = '\0';
		addr_part = buf;
		if (cp[1] == ':')
			port_part = cp+2;
		else
			port_part = NULL;
		is_ipv6 = 1;
	} else if (cp && strchr(cp+1, ':')) {
		is_ipv6 = 1;
		addr_part = ip_as_string;
		port_part = NULL;
	} else if (cp) {
		is_ipv6 = 0;
		if (cp - ip_as_string > (int)sizeof(buf)-1) {
			return -1;
		}
		memcpy(buf, ip_as_string, cp-ip_as_string);
		buf[cp-ip_as_string] = '\0';
		addr_part = buf;
		port_part = cp+1;
	} else {
		addr_part = ip_as_string;
		port_part = NULL;
		is_ipv6 = 0;
	}

	if (port_part == NULL) {
		port = 0;
	} else {
		port = atoi(port_part);
		if (port <= 0 || port > 65535) {
			return -1;
		}
	}

	if (!addr_part)
		return -1; /* Should be impossible. */
#ifdef AF_INET6
	if (is_ipv6)
	{
		struct sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
#ifdef _EVENT_HAVE_STRUCT_SOCKADDR_IN6_SIN6_LEN
		sin6.sin6_len = sizeof(sin6);
#endif
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port = htons(port);
		if (1 != evutil_inet_pton(AF_INET6, addr_part, &sin6.sin6_addr))
			return -1;
		if (sizeof(sin6) > *outlen)
			return -1;
		memset(out, 0, *outlen);
		memcpy(out, &sin6, sizeof(sin6));
                *outlen = sizeof(sin6);
		return 0;
	}
	else
#endif
	{
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
#ifdef _EVENT_HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		sin.sin_len = sizeof(sin);
#endif
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port);
		if (1 != evutil_inet_pton(AF_INET, addr_part, &sin.sin_addr))
			return -1;
		if (sizeof(sin) > *outlen)
			return -1;
		memset(out, 0, *outlen);
		memcpy(out, &sin, sizeof(sin));
                *outlen = sizeof(sin);
		return 0;
	}
}

/* Tables to implement ctypes-replacement EVUTIL_IS*() functions.  Each table
 * has 256 bits to look up whether a character is in some set or not.  This
 * fails on non-ASCII platforms, but so does every other place where we
 * take a char and write it onto the network.
 **/
const ev_uint32_t EVUTIL_ISALPHA_TABLE[8] =
  { 0, 0, 0x7fffffe, 0x7fffffe, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISALNUM_TABLE[8] =
  { 0, 0x3ff0000, 0x7fffffe, 0x7fffffe, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISSPACE_TABLE[8] = { 0x3e00, 0x1, 0, 0, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISXDIGIT_TABLE[8] =
  { 0, 0x3ff0000, 0x7e, 0x7e, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISDIGIT_TABLE[8] = { 0, 0x3ff0000, 0, 0, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISPRINT_TABLE[8] =
  { 0, 0xffffffff, 0xffffffff, 0x7fffffff, 0, 0, 0, 0x0 };
const ev_uint32_t EVUTIL_ISUPPER_TABLE[8] = { 0, 0, 0x7fffffe, 0, 0, 0, 0, 0 };
const ev_uint32_t EVUTIL_ISLOWER_TABLE[8] = { 0, 0, 0, 0x7fffffe, 0, 0, 0, 0 };
/* Upper-casing and lowercasing tables to map characters to upper/lowercase
 * equivalents. */
const char EVUTIL_TOUPPER_TABLE[256] = {
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
  32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
  48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
  64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
  80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,
  96,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
  80,81,82,83,84,85,86,87,88,89,90,123,124,125,126,127,
  128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
  144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
  160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
  176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
  192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
  208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
  224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
  240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
};
const char EVUTIL_TOLOWER_TABLE[256] = {
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,
  32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,
  48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,
  64,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
  112,113,114,115,116,117,118,119,120,121,122,91,92,93,94,95,
  96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,
  112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,
  128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
  144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,
  160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,
  176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,
  192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,
  208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,
  224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,
  240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
};

int
evutil_strcasecmp(const char *s1, const char *s2)
{
	char c1, c2;
	while (1) {
		c1 = EVUTIL_TOLOWER(*s1++);
		c2 = EVUTIL_TOLOWER(*s2++);
		if (c1 < c2)
			return -1;
		else if (c1 > c2)
			return 1;
		else if (c1 == 0)
			return 0;
	}
}
int evutil_strncasecmp(const char *s1, const char *s2, size_t n)
{
	char c1, c2;
	while (n--) {
		c1 = EVUTIL_TOLOWER(*s1++);
		c2 = EVUTIL_TOLOWER(*s2++);
		if (c1 < c2)
			return -1;
		else if (c1 > c2)
			return 1;
		else if (c1 == 0)
			return 0;
	}
	return 0;
}
