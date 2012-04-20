/*
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "event2/event-config.h"
#include "evconfig-private.h"

#ifdef _WIN32
#include <winsock2.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#endif

#include <sys/types.h>
#ifdef EVENT__HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <errno.h>
#include <limits.h>
#ifndef EVENT__HAVE_GETTIMEOFDAY
#include <sys/timeb.h>
#endif
#if !defined(EVENT__HAVE_NANOSLEEP) && !defined(EVENT_HAVE_USLEEP) && \
	!defined(_WIN32)
#include <sys/select.h>
#endif
#include <time.h>
#include <sys/stat.h>

#include "event2/util.h"
#include "util-internal.h"
#include "log-internal.h"

#ifndef EVENT__HAVE_GETTIMEOFDAY
/* No gettimeofday; this must be windows. */
int
evutil_gettimeofday(struct timeval *tv, struct timezone *tz)
{
#ifdef _MSC_VER
#define U64_LITERAL(n) n##ui64
#else
#define U64_LITERAL(n) n##llu
#endif

	/* Conversion logic taken from Tor, which in turn took it
	 * from Perl.  GetSystemTimeAsFileTime returns its value as
	 * an unaligned (!) 64-bit value containing the number of
	 * 100-nanosecond intervals since 1 January 1601 UTC. */
#define EPOCH_BIAS U64_LITERAL(116444736000000000)
#define UNITS_PER_SEC U64_LITERAL(10000000)
#define USEC_PER_SEC U64_LITERAL(1000000)
#define UNITS_PER_USEC U64_LITERAL(10)
	union {
		FILETIME ft_ft;
		ev_uint64_t ft_64;
	} ft;

	if (tv == NULL)
		return -1;

	GetSystemTimeAsFileTime(&ft.ft_ft);

	if (EVUTIL_UNLIKELY(ft.ft_64 < EPOCH_BIAS)) {
		/* Time before the unix epoch. */
		return -1;
	}
	ft.ft_64 -= EPOCH_BIAS;
	tv->tv_sec = (long) (ft.ft_64 / UNITS_PER_SEC);
	tv->tv_usec = (long) ((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
	return 0;
}
#endif

#define MAX_SECONDS_IN_MSEC_LONG \
	(((LONG_MAX) - 999) / 1000)

long
evutil_tv_to_msec_(const struct timeval *tv)
{
	if (tv->tv_usec > 1000000 || tv->tv_sec > MAX_SECONDS_IN_MSEC_LONG)
		return -1;

	return (tv->tv_sec * 1000) + ((tv->tv_usec + 999) / 1000);
}

void
evutil_usleep_(const struct timeval *tv)
{
	if (!tv)
		return;
#if defined(_WIN32)
	{
		long msec = evutil_tv_to_msec_(tv);
		Sleep((DWORD)msec);
	}
#elif defined(EVENT__HAVE_NANOSLEEP)
	{
		struct timespec ts;
		ts.tv_sec = tv->tv_sec;
		ts.tv_nsec = tv->tv_usec*1000;
		nanosleep(&ts, NULL);
	}
#elif defined(EVENT__HAVE_USLEEP)
	/* Some systems don't like to usleep more than 999999 usec */
	sleep(tv->tv_sec);
	usleep(tv->tv_usec);
#else
	select(0, NULL, NULL, NULL, tv);
#endif
}

