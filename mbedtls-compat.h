#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_MAJOR >= 3
# if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wcpp"
# elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wcpp"
# endif

# include <mbedtls/compat-2.x.h>

# if defined(__clang__)
#  pragma clang diagnostic pop
# elif defined(__GNUC__)
#  pragma GCC diagnostic pop
# endif
#endif // MBEDTLS_VERSION_MAJOR >= 3

#if MBEDTLS_VERSION_MAJOR < 2 || (MBEDTLS_VERSION_MAJOR == 2 && MBEDTLS_VERSION_MINOR < 4)
# include <mbedtls/net.h>
#else
# include <mbedtls/net_sockets.h>
#endif

#endif // LIBEVENT_MBEDTLS_COMPAT_H
