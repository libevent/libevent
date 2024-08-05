#ifndef EVDNS_INTERNAL_H_INCLUDED_
#define EVDNS_INTERNAL_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

#include "event2/event_struct.h"

#ifdef _WIN32

EVENT2_EXPORT_SYMBOL
int load_nameservers_with_getadaptersaddresses(struct evdns_base *base);

#endif

#ifdef __cplusplus
}
#endif

#endif

