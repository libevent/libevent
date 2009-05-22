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
#ifndef _EVENT_UTIL_INTERNAL_H
#define _EVENT_UTIL_INTERNAL_H

#include "event-config.h"
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/* If we need magic to say "inline", get it for free internally. */
#ifdef _EVENT_inline
#define inline _EVENT_inline
#endif
#ifdef _EVENT___func__
#define __func__ _EVENT___func__
#endif

/* A good no-op to use in macro definitions. */
#define _EVUTIL_NIL_STMT ((void)0)

/* Internal use only: macros to match patterns of error codes in a
   cross-platform way.  We need these macros because of two historical
   reasons: first, nonblocking IO functions are generally written to give an
   error on the "blocked now, try later" case, so sometimes an error from a
   read, write, connect, or accept means "no error; just wait for more
   data," and we need to look at the error code.  Second, Windows defines
   a different set of error codes for sockets. */

#ifndef WIN32

/* True iff e is an error that means a read/write operation can be retried. */
#define EVUTIL_ERR_RW_RETRIABLE(e)				\
	((e) == EINTR || (e) == EAGAIN)
/* True iff e is an error that means an accept can be retried. */
#define EVUTIL_ERR_CONNECT_RETRIABLE(e)			\
	((e) == EINTR || (e) == EINPROGRESS)
/* True iff e is an error that means a connect can be retried. */
#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)			\
	((e) == EINTR || (e) == EAGAIN || (e) == ECONNABORTED)

#else

#define EVUTIL_ERR_RW_RETRIABLE(e)					\
	((e) == WSAEWOULDBLOCK ||					\
	    (e) == WSAEINTR)

#define EVUTIL_ERR_CONNECT_RETRIABLE(e)					\
	((e) == WSAEWOULDBLOCK ||					\
	    (e) == WSAEINTR ||						\
	    (e) == WSAEINPROGRESS ||					\
	    (e) == WSAEINVAL)

#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)			\
	EVUTIL_ERR_RW_RETRIABLE(e)

#endif

#ifdef _EVENT_socklen_t
#define socklen_t _EVENT_socklen_t
#endif

/* Locale-independent replacements for some ctypes functions.  Use these
 * when you care about ASCII's notion of character types, because you are about
 * to send those types onto the wire.
 */
#define DECLARE_CTYPE_FN(name)                                          \
        static int EVUTIL_##name(char c);                               \
        extern const ev_uint32_t EVUTIL_##name##_TABLE[];               \
        static inline int EVUTIL_##name(char c) {                       \
                ev_uint8_t u = c;                                       \
                return !!(EVUTIL_##name##_TABLE[(u >> 5) & 7] & (1 << (u & 31))); \
        }
DECLARE_CTYPE_FN(ISALPHA)
DECLARE_CTYPE_FN(ISALNUM)
DECLARE_CTYPE_FN(ISSPACE)
DECLARE_CTYPE_FN(ISDIGIT)
DECLARE_CTYPE_FN(ISXDIGIT)
DECLARE_CTYPE_FN(ISPRINT)
DECLARE_CTYPE_FN(ISLOWER)
DECLARE_CTYPE_FN(ISUPPER)
extern const char EVUTIL_TOUPPER_TABLE[];
extern const char EVUTIL_TOLOWER_TABLE[];
#define EVUTIL_TOLOWER(c) (EVUTIL_TOLOWER_TABLE[(ev_uint8_t)c])
#define EVUTIL_TOUPPER(c) (EVUTIL_TOUPPER_TABLE[(ev_uint8_t)c])
int evutil_strcasecmp(const char *, const char *);
int evutil_strncasecmp(const char *, const char *, size_t);

/** Helper macro.  If we know that a given pointer points to a field in a
    structure, return a pointer to the structure itself.  Used to implement
    our half-baked C OO.  Example:

    struct subtype {
         int x;
	 struct supertype common;
	 int y;
    };
    ...
    void fn(struct supertype *super) {
         struct subtype *sub = EVUTIL_UPCAST(super, struct subtype, common);
         ...
    }
 */
#define EVUTIL_UPCAST(ptr, type, field)				\
	((type *)((char*)ptr) - evutil_offsetof(type, field))

#ifdef __cplusplus
}
#endif

#endif
