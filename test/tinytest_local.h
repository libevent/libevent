
#ifdef WIN32
#include <winsock2.h>
#endif

#include "event2/util.h"
#include "util-internal.h"

#ifdef snprintf
#undef snprintf
#endif
#define snprintf evutil_snprintf
