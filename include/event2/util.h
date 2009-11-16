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
#ifndef _EVENT2_UTIL_H_
#define _EVENT2_UTIL_H_

/** @file event2/util.h

  Common convenience functions for cross-platform portability and
  related socket manipulations.

 */

#ifdef __cplusplus
extern "C" {
#endif

#include <event-config.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef _EVENT_HAVE_STDINT_H
#include <stdint.h>
#elif defined(_EVENT_HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#ifdef _EVENT_HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef _EVENT_HAVE_STDDEF_H
#include <stddef.h>
#endif
#ifdef _MSC_VER
#include <BaseTsd.h>
#endif
#include <stdarg.h>
#ifdef _EVENT_HAVE_NETDB_H
#define _GNU_SOURCE
#include <netdb.h>
#endif

/* Integer type definitions for types that are supposed to be defined in the
 * C99-specified stdint.h.  Shamefully, some platforms do not include
 * stdint.h, so we need to replace it.  (If you are on a platform like this,
 * your C headers are now 10 years out of date.  You should bug them to do
 * something about this.)
 *
 * We define:
 *    ev_uint64_t, ev_uint32_t, ev_uint16_t, ev_uint8_t -- unsigned integer
 *      types of exactly 64, 32, 16, and 8 bits respectively.
 *    ev_int64_t, ev_int32_t, ev_int16_t, ev_int8_t -- signed integer
 *      types of exactly 64, 32, 16, and 8 bits respectively.
 */
#ifdef _EVENT_HAVE_UINT64_T
#define ev_uint64_t uint64_t
#define ev_int64_t int64_t
#elif defined(WIN32)
#define ev_uint64_t unsigned __int64
#define ev_int64_t signed __int64
#elif _EVENT_SIZEOF_LONG_LONG == 8
#define ev_uint64_t unsigned long long
#define ev_int64_t long long
#elif _EVENT_SIZEOF_LONG == 8
#define ev_uint64_t unsigned long
#define ev_int64_t long
#else
#error "No way to define ev_uint64_t"
#endif

#ifdef _EVENT_HAVE_UINT32_T
#define ev_uint32_t uint32_t
#elif defined(WIN32)
#define ev_uint32_t unsigned int
#elif _EVENT_SIZEOF_LONG == 4
#define ev_uint32_t unsigned long
#elif _EVENT_SIZEOF_INT == 4
#define ev_uint32_t unsigned int
#else
#error "No way to define ev_uint32_t"
#endif

#ifdef _EVENT_HAVE_UINT16_T
#define ev_uint16_t uint16_t
#elif defined(WIN32)
#define ev_uint16_t unsigned short
#elif _EVENT_SIZEOF_INT == 2
#define ev_uint16_t unsigned int
#elif _EVENT_SIZEOF_SHORT == 2
#define ev_uint16_t unsigned short
#else
#error "No way to define ev_uint16_t"
#endif

#ifdef _EVENT_HAVE_UINT8_T
#define ev_uint8_t uint8_t
#else
#define ev_uint8_t unsigned char
#endif

#ifdef _EVENT_ssize_t
#define ev_ssize_t _EVENT_ssize_t
#else
#define ev_ssize_t ssize_t
#endif

#ifdef WIN32
#define ev_socklen_t int
#elif defined(_EVENT_socklen_t)
#define ev_socklen_t _EVENT_socklen_t
#else
#define ev_socklen_t socklen_t
#endif

#ifdef WIN32
/** A type wide enough to hold the output of "socket()" or "accept()".  On
 * Windows, this is an intptr_t; elsewhere, it is an int. */
#define evutil_socket_t intptr_t
#else
#define evutil_socket_t int
#endif

/** Create two new sockets that are connected to each other.  On Unix, this
    simply calls socketpair().  On Windows, it uses the loopback network
    interface on 127.0.0.1, and only AF_INET,SOCK_STREAM are supported.

    (This may fail on some Windows hosts where firewall software has cleverly
    decided to keep 127.0.0.1 from talking to itself.)

    Parameters and return values are as for socketpair()
*/
int evutil_socketpair(int d, int type, int protocol, evutil_socket_t sv[2]);
/** Do platform-specific operations as needed to make a socket nonblocking.

    @param sock The socket to make nonblocking
    @return 0 on success, -1 on failure
 */
int evutil_make_socket_nonblocking(evutil_socket_t sock);

/** Do platform-specific operations on a listener socket to make sure that
    another program will be able to bind this address right after we've
    closed the listener

    @param sock The socket to make reusable
    @return 0 on success, -1 on failure
 */
int evutil_make_listen_socket_reuseable(evutil_socket_t);

#ifdef WIN32
/** Do the platform-specific call needed to close a socket returned from
    socket() or accept(). */
#define EVUTIL_CLOSESOCKET(s) closesocket(s)
#else
/** Do the platform-specific call needed to close a socket returned from
    socket() or accept(). */
#define EVUTIL_CLOSESOCKET(s) close(s)
#endif

/* Winsock handles socket errors differently from the rest of the world.
 * Elsewhere, a socket error is like any other error and is stored in errno.
 * But winsock functions require you to retrieve the error with a special
 * function, and don't let you use strerror for the error codes.  And handling
 * EWOULDBLOCK is ... different. */

#ifdef WIN32
/** Return the most recent socket error.  Not idempotent on all platforms. */
#define EVUTIL_SOCKET_ERROR() WSAGetLastError()
/** Replace the most recent socket error with errcode */
#define EVUTIL_SET_SOCKET_ERROR(errcode)		\
	do { WSASetLastError(errcode); } while (0)
/** Return the most recent socket error to occur on sock. */
int evutil_socket_geterror(evutil_socket_t sock);
/** Convert a socket error to a string. */
const char *evutil_socket_error_to_string(int errcode);
#else
#define EVUTIL_SOCKET_ERROR() (errno)
#define EVUTIL_SET_SOCKET_ERROR(errcode)		\
		do { errno = (errcode); } while (0)
#define evutil_socket_geterror(sock) (errno)
#define evutil_socket_error_to_string(errcode) (strerror(errcode))
#endif

/*
 * Manipulation macros for struct timeval.  We define replacements
 * for timeradd, timersub, timerclear, timercmp, and timerisset.
 */
#ifdef _EVENT_HAVE_TIMERADD
#define evutil_timeradd(tvp, uvp, vvp) timeradd((tvp), (uvp), (vvp))
#define evutil_timersub(tvp, uvp, vvp) timersub((tvp), (uvp), (vvp))
#else
#define evutil_timeradd(tvp, uvp, vvp)					\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)
#define	evutil_timersub(tvp, uvp, vvp)					\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* !_EVENT_HAVE_HAVE_TIMERADD */

#ifdef _EVENT_HAVE_TIMERCLEAR
#define evutil_timerclear(tvp) timerclear(tvp)
#else
#define	evutil_timerclear(tvp)	(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

/** Return true iff the tvp is related to uvp according to the relational
 * operator cmp.  Recognized values for cmp are ==, <=, <, >=, and >. */
#define	evutil_timercmp(tvp, uvp, cmp)					\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) :				\
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))

#ifdef _EVENT_HAVE_TIMERISSET
#define evutil_timerisset(tvp) timerisset(tvp)
#else
#define	evutil_timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)
#endif

/* Replacement for offsetof on platforms that don't define it. */
#ifdef offsetof
#define evutil_offsetof(type, field) offsetof(type, field)
#else
#define evutil_offsetof(type, field) ((off_t)(&((type *)0)->field))
#endif

/* big-int related functions */
/** Parse a 64-bit value from a string.  Arguments are as for strtol. */
ev_int64_t evutil_strtoll(const char *s, char **endptr, int base);

/* Replacement for gettimeofday on platforms that lack it. */
#ifdef _EVENT_HAVE_GETTIMEOFDAY
#define evutil_gettimeofday(tv, tz) gettimeofday((tv), (tz))
#else
struct timezone;
int evutil_gettimeofday(struct timeval *tv, struct timezone *tz);
#endif

#ifdef __GNUC__
/** Helper macro; used to tell the compiler that a given function takes a
 * printf-like format string as argument number 'a', and a set of printf-like
 * arguments starting in argument 'b'. */
#define EVUTIL_CHECK_FMT(a,b) __attribute__((format(printf, a, b)))
#else
#define EVUTIL_CHECK_FMT(a,b)
#endif

/** Replacement for snprintf to get consistent behavior on platforms for
    which the return value of snprintf does not conform to C99.
 */
int evutil_snprintf(char *buf, size_t buflen, const char *format, ...)
	EVUTIL_CHECK_FMT(3,4);
int evutil_vsnprintf(char *buf, size_t buflen, const char *format, va_list ap);

/** Replacement for inet_ntop for platforms which lack it. */
const char *evutil_inet_ntop(int af, const void *src, char *dst, size_t len);
/** Replacement for inet_pton for platforms which lack it. */
int evutil_inet_pton(int af, const char *src, void *dst);
struct sockaddr;

/** Parse an IPv4 or IPv6 address, with optional port, from a string.

    Recognized formats are:
    - [IPv6Address]:port
    - [IPv6Address]
    - IPv6Address
    - IPv4Address:port
    - IPv4Address

    If no port is specified, the port in the output is set to 0.

    @param str The string to parse.
    @param out A struct sockaddr to hold the result.  This should probably be
       a struct sockaddr_storage.
    @param outlen A pointer to the number of bytes that that 'out' can safely
       hold.  Set to the number of bytes used in 'out' on success.
    @return -1 if the address is not well-formed, if the port is out of range,
       or if out is not large enough to hold the result.  Otherwise returns
       0 on success.
*/
int evutil_parse_sockaddr_port(const char *str, struct sockaddr *out, int *outlen);

/** Compare two sockaddrs; return 0 if they are equal, or less than 0 if sa1
 * preceeds sa2, or greater than 0 if sa1 follows sa2.  If include_port is
 * true, consider the port as well as the address.  Only implemented for
 * AF_INET and AF_INET6 addresses. The ordering is not guaranteed to remain
 * the same between Libevent versions. */
int evutil_sockaddr_cmp(const struct sockaddr *sa1, const struct sockaddr *sa2,
    int include_port);

/** As strcasecmp, but always compares the characters in locale-independent
    ASCII.  That's useful if you're handling data in ASCII-based protocols.
 */
int evutil_ascii_strcasecmp(const char *str1, const char *str2);
/** As strncasecmp, but always compares the characters in locale-independent
    ASCII.  That's useful if you're handling data in ASCII-based protocols.
 */
int evutil_ascii_strncasecmp(const char *str1, const char *str2, size_t n);

/* Here we define evutil_addrinfo to the native addrinfo type, or redefinte it
 * if this system has no getaddrinfo(). */
#ifdef _EVENT_HAVE_STRUCT_ADDRINFO
#define evutil_addrinfo addrinfo
#else
struct evutil_addrinfo {
	int     ai_flags;     /* AI_PASSIVE, AI_CANONNAME, AI_NUMERICHOST */
	int     ai_family;    /* PF_xxx */
	int     ai_socktype;  /* SOCK_xxx */
	int     ai_protocol;  /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t  ai_addrlen;   /* length of ai_addr */
	char   *ai_canonname; /* canonical name for nodename */
	struct sockaddr  *ai_addr; /* binary address */
	struct evutil_addrinfo  *ai_next; /* next structure in linked list */
};
#endif
#ifdef EAI_ADDRFAMILY
#define EVUTIL_EAI_ADDRFAMILY EAI_ADDRFAMILY
#else
#define EVUTIL_EAI_ADDRFAMILY -901
#endif
#ifdef EAI_AGAIN
#define EVUTIL_EAI_AGAIN EAI_AGAIN
#else
#define EVUTIL_EAI_AGAIN -902
#endif
#ifdef EAI_BADFLAGS
#define EVUTIL_EAI_BADFLAGS EAI_BADFLAGS
#else
#define EVUTIL_EAI_BADFLAGS -903
#endif
#ifdef EAI_FAIL
#define EVUTIL_EAI_FAIL EAI_FAIL
#else
#define EVUTIL_EAI_FAIL -904
#endif
#ifdef EAI_FAMILY
#define EVUTIL_EAI_FAMILY EAI_FAMILY
#else
#define EVUTIL_EAI_FAMILY -905
#endif
#ifdef EAI_MEMORY
#define EVUTIL_EAI_MEMORY EAI_MEMORY
#else
#define EVUTIL_EAI_MEMORY -906
#endif
/* This test is a bit complicated, since some MS SDKs decide to
 * remove NODATA or redefine it to be the same as NONAME, in a
 * fun interpretation of RFC 2553 and RFC 3493. */
#if defined(EAI_NODATA) && (!defined(EAI_NONAME) || EAI_NODATA != EAI_NONAME)
#define EVUTIL_EAI_NODATA EAI_NODATA
#else
#define EVUTIL_EAI_NODATA -907
#endif
#ifdef EAI_NONAME
#define EVUTIL_EAI_NONAME EAI_NONAME
#else
#define EVUTIL_EAI_NONAME -908
#endif
#ifdef EAI_SERVICE
#define EVUTIL_EAI_SERVICE EAI_SERVICE
#else
#define EVUTIL_EAI_SERVICE -909
#endif
#ifdef EAI_SOCKTYPE
#define EVUTIL_EAI_SOCKTYPE EAI_SOCKTYPE
#else
#define EVUTIL_EAI_SOCKTYPE -910
#endif
#ifdef EAI_SYSTEM
#define EVUTIL_EAI_SYSTEM EAI_SYSTEM
#else
#define EVUTIL_EAI_SYSTEM -911
#endif

#define EVUTIL_EAI_CANCEL -90001

#ifdef AI_PASSIVE
#define EVUTIL_AI_PASSIVE AI_PASSIVE
#else
#define EVUTIL_AI_PASSIVE 0x1000
#endif
#ifdef AI_CANONNAME
#define EVUTIL_AI_CANONNAME AI_CANONNAME
#else
#define EVUTIL_AI_CANONNAME 0x2000
#endif
#ifdef AI_NUMERICHOST
#define EVUTIL_AI_NUMERICHOST AI_NUMERICHOST
#else
#define EVUTIL_AI_NUMERICHOST 0x4000
#endif
#ifdef AI_NUMERICSERV
#define EVUTIL_AI_NUMERICSERV AI_NUMERICSERV
#else
#define EVUTIL_AI_NUMERICSERV 0x8000
#endif
#ifdef AI_V4MAPPED
#define EVUTIL_AI_V4MAPPED AI_V4MAPPED
#else
#define EVUTIL_AI_V4MAPPED 0x10000
#endif
#ifdef AI_ALL
#define EVUTIL_AI_ALL AI_ALL
#else
#define EVUTIL_AI_ALL 0x20000
#endif
#ifdef AI_ADDRCONFIG
#define EVUTIL_AI_ADDRCONFIG AI_ADDRCONFIG
#else
#define EVUTIL_AI_ADDRCONFIG 0x40000
#endif

struct evutil_addrinfo;
/* This function clones getaddrinfo for systems that don't have it.  For full
 * details, see RFC 3493, section 6.1.
 *
 * Limitations:
 * - When the system has no getaddrinfo, we fall back to gethostbyname_r or
 *   gethostbyname, with their attendant issues.
 * - The AI_V4MAPPED and AI_ALL flags are not currently implemented.
 *
 * For a nonblocking variant, see evdns_getaddrinfo.
 */
int evutil_getaddrinfo(const char *nodename, const char *servname,
    const struct evutil_addrinfo *hints_in, struct evutil_addrinfo **res);

/* Release storage allocated by evutil_getaddrinfo or evdns_getaddrinfo. */
void evutil_freeaddrinfo(struct evutil_addrinfo *ai);

const char *evutil_gai_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* _EVUTIL_H_ */
