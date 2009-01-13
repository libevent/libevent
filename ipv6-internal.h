/* Internal use only: Fake IPv6 structures and values on platforms that
 * do not have them */

#ifndef _EVENT_IPV6_INTERNAL_H
#define _EVENT_IPV6_INTERNAL_H

#include <sys/types.h>
#include "event-config.h"
#include <event2/util.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _EVENT_HAVE_STRUCT_IN6_ADDR
struct in6_addr {
	ev_uint8_t s6_addr[16];
};
#endif

#ifndef _EVENT_HAVE_SA_FAMILY_T
typedef int sa_family_t;
#endif

#ifndef _EVENT_HAVE_STRUCT_SOCKADDR_IN6
struct sockaddr_in6 {
	sa_family_t sin6_family;
	ev_uint16_t sin6_port;
	struct in6_addr sin6_addr;
};
#endif

#ifdef __cplusplus
}
#endif

#endif
