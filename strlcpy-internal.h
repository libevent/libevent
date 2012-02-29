#ifndef STRLCPY_INTERNAL_H_INCLUDED_
#define STRLCPY_INTERNAL_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include "event2/event-config.h"
#include "evconfig-private.h"

#ifndef EVENT__HAVE_STRLCPY
#include <string.h>
size_t _event_strlcpy(char *dst, const char *src, size_t siz);
#define strlcpy _event_strlcpy
#endif

#ifdef __cplusplus
}
#endif

#endif

