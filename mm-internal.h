
#ifndef _EVENT_MM_INTERNAL_H
#define _EVENT_MM_INTERNAL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal use only: Memory allocation functions. */
void *event_malloc(size_t sz);
void *event_calloc(size_t count, size_t size);
char *event_strdup(const char *s);
void *event_realloc(void *p, size_t sz);
void event_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
