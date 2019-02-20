#ifndef EVENT2_DTRACE_H_INCLUDED_
#define EVENT2_DTRACE_H_INCLUDED_

#ifdef EVENT__ENABLE_DTRACE

#include <sys/sdt.h>

#ifndef EVENT__DTRACE_PVDR_NAME
#define EVENT__DTRACE_PVDR_NAME libevent.so
#endif

#define EVENT__PROBE(name, n, ...) \
    EVENT__PROBE_1(EVENT__DTRACE_PVDR_NAME, name, n, ## __VA_ARGS__)

#define EVENT__PROBE_1(lib, name, n, ...) \
    DTRACE_PROBE ## n(lib, name, ## __VA_ARGS__)

#define EVENT__PROBE0 DTRACE_PROBE
#else
#define EVENT__PROBE(name, n, ...)
#endif

#endif
