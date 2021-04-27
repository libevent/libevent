#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

#include <mbedtls/version.h>
#if MBEDTLS_VERSION_MAJOR < 2 || (MBEDTLS_VERSION_MAJOR == 2 && MBEDTLS_VERSION_MINOR < 4)
#include <mbedtls/net.h>
#else
#include <mbedtls/net_sockets.h>
#endif

#endif // LIBEVENT_MBEDTLS_COMPAT_H
