
#ifndef _EVENT_MM_INTERNAL_H
#define _EVENT_MM_INTERNAL_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Internal use only: Memory allocation functions. */
void *mm_malloc(size_t sz);
void *mm_calloc(size_t count, size_t size);
char *mm_strdup(const char *s);
void *mm_realloc(void *p, size_t sz);
void mm_free(void *p);

#ifdef __cplusplus
}
#endif

#endif
