
#ifndef _EVENT_UTIL_INTERNAL_H
#define _EVENT_UTIL_INTERNAL_H

#include "event-config.h"
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#define EVUTIL_ERR_RW_RETRIABLE(e)								\
	((e) == WSAEAGAIN ||										\
	 (e) == WSAEWOULDBLOCK ||									\
	 (e) == WSAEINTR)

#define EVUTIL_ERR_CONNECT_RETRIABLE(e)			\
	((e) == WSAEWOULDBLOCK ||					\
	 (e) == WSAEINTR ||							\
	 (e) == WSAEINPROGRESS ||					\
	 (e) == WSAEINVAL))

#define EVUTIL_ERR_ACCEPT_RETRIABLE(e)			\
	EVUTIL_ERR_RW_RETRIABLE(e)

#endif

#ifdef __cplusplus
}
#endif

#endif
