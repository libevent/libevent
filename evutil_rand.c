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

/* Use the platform RNG without maintaining a separate userspace generator. */

#include "event2/event-config.h"
#include "evconfig-private.h"

#include <limits.h>
#include <errno.h>

#include "util-internal.h"
#include "evthread-internal.h"
#include "log-internal.h"

#ifdef EVENT__HAVE_ARC4RANDOM
#include <stdlib.h>
#include <string.h>
int
evutil_secure_rng_set_urandom_device_file(char *fname)
{
	(void) fname;
	return -1;
}
int
evutil_secure_rng_init(void)
{
	/* call arc4random() now to force it to self-initialize */
	(void)! arc4random();
	return 0;
}
#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
evutil_secure_rng_global_setup_locks_(const int enable_locks)
{
	return 0;
}
#endif
static void
evutil_free_secure_rng_globals_locks(void)
{
}

static void
ev_arc4random_buf(void *buf, size_t n)
{
#if defined(EVENT__HAVE_ARC4RANDOM_BUF) && !defined(__APPLE__)
	arc4random_buf(buf, n);
	return;
#else
	unsigned char *b = buf;

#if defined(EVENT__HAVE_ARC4RANDOM_BUF)
	/* OSX 10.7 introduced arc4random_buf, so if you build your program
	 * there, you'll get surprised when older versions of OSX fail to run.
	 * To solve this, we can check whether the function pointer is set,
	 * and fall back otherwise.  (OSX does this using some linker
	 * trickery.)
	 */
	{
		void (*tptr)(void *,size_t) =
		    (void (*)(void*,size_t))arc4random_buf;
		if (tptr != NULL) {
			arc4random_buf(buf, n);
			return;
		}
	}
#endif
	/* Make sure that we start out with b at a 4-byte alignment; plenty
	 * of CPUs care about this for 32-bit access. */
	if (n >= 4 && ((ev_uintptr_t)b) & 3) {
		ev_uint32_t u = arc4random();
		int n_bytes = 4 - (((ev_uintptr_t)b) & 3);
		memcpy(b, &u, n_bytes);
		b += n_bytes;
		n -= n_bytes;
	}
	while (n >= 4) {
		*(ev_uint32_t*)b = arc4random();
		b += 4;
		n -= 4;
	}
	if (n) {
		ev_uint32_t u = arc4random();
		memcpy(b, &u, n);
	}
#endif
}

#else /* !EVENT__HAVE_ARC4RANDOM { */

#ifdef EVENT__ssize_t
#define ssize_t EVENT__ssize_t
#endif
#ifndef EVENT__DISABLE_THREAD_SUPPORT
static void *rng_lock;
#endif

#ifdef _WIN32
#ifdef EVENT__HAVE_BCRYPTGENRANDOM
#include <bcrypt.h>
#else
#include <wincrypt.h>
static HCRYPTPROV rng_provider;
#endif
#else
#include <fcntl.h>
#include <unistd.h>
#ifdef EVENT__HAVE_SYS_RANDOM_H
#include <sys/random.h>
#endif
static int rng_fd = -1;
static char *rng_filename;
#ifdef EVENT__HAVE_GETRANDOM
static int rng_use_getrandom;
#endif
#endif

static int rng_initialized;

static int
evutil_secure_rng_read_(unsigned char *buf, size_t n)
{
	while (n) {
#ifdef _WIN32
		ULONG len = n > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)n;
#ifdef EVENT__HAVE_BCRYPTGENRANDOM
		if (BCryptGenRandom(NULL, buf, len,
		    BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
			return -1;
#else
		if (!CryptGenRandom(rng_provider, len, buf))
			return -1;
#endif
#else
		size_t count = n > 256 ? 256 : n;
		ssize_t len;
#ifdef EVENT__HAVE_GETRANDOM
		if (rng_use_getrandom)
			len = getrandom(buf, count, 0);
		else
#endif
			len = read(rng_fd, buf, count);
		if (len < 0 && errno == EINTR)
			continue;
		if (len <= 0)
			return -1;
#endif
		buf += len;
		n -= len;
	}
	return 0;
}

static int
evutil_secure_rng_init_(void)
{
	unsigned char probe;

	if (rng_initialized)
		return 0;
#ifdef _WIN32
#ifndef EVENT__HAVE_BCRYPTGENRANDOM
	if (!rng_provider && !CryptAcquireContext(&rng_provider, NULL, NULL,
	    PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return -1;
#endif
	if (evutil_secure_rng_read_(&probe, 1) < 0)
		return -1;
#else
	{
		static const char *filenames[] = {
			"/dev/srandom", "/dev/urandom", "/dev/random", NULL
		};
		const char *filename;
		int i;
#ifdef EVENT__HAVE_GETRANDOM
		if (rng_filename == NULL) {
			ssize_t len;
			do {
				len = getrandom(&probe, 1, 0);
			} while (len < 0 && errno == EINTR);
			if (len == 1) {
				rng_use_getrandom = 1;
				rng_initialized = 1;
				return 0;
			}
			if (len == 0 || (errno != ENOSYS && errno != EPERM))
				return -1;
		}
#endif
		/* Retain the opened device so explicit init also works before chroot. */
		for (i = 0; (filename = rng_filename ? rng_filename : filenames[i]);
		    ++i) {
			rng_fd = evutil_open_closeonexec_(filename, O_RDONLY, 0);
			if (rng_fd >= 0) {
				if (evutil_secure_rng_read_(&probe, 1) == 0)
					break;
				close(rng_fd);
				rng_fd = -1;
			}
			if (rng_filename)
				break;
		}
		if (rng_fd < 0)
			return -1;
	}
#endif
	rng_initialized = 1;
	return 0;
}

#ifndef EVENT__DISABLE_THREAD_SUPPORT
int
evutil_secure_rng_global_setup_locks_(const int enable_locks)
{
	EVTHREAD_SETUP_GLOBAL_LOCK(rng_lock, 0);
	return 0;
}
#endif

static void
evutil_free_secure_rng_globals_locks(void)
{
	EVLOCK_LOCK(rng_lock, 0);
#ifdef _WIN32
#ifndef EVENT__HAVE_BCRYPTGENRANDOM
	if (rng_provider) {
		CryptReleaseContext(rng_provider, 0);
		rng_provider = 0;
	}
#endif
#else
	if (rng_fd >= 0) {
		close(rng_fd);
		rng_fd = -1;
	}
	rng_filename = NULL;
#ifdef EVENT__HAVE_GETRANDOM
	rng_use_getrandom = 0;
#endif
#endif
	rng_initialized = 0;
	EVLOCK_UNLOCK(rng_lock, 0);
#ifndef EVENT__DISABLE_THREAD_SUPPORT
	if (rng_lock != NULL) {
		EVTHREAD_FREE_LOCK(rng_lock, 0);
		rng_lock = NULL;
	}
#endif
	return;
}

int
evutil_secure_rng_set_urandom_device_file(char *fname)
{
#ifdef _WIN32
	(void) fname;
	return -1;
#else
	int result = -1;
	EVLOCK_LOCK(rng_lock, 0);
	if (!rng_initialized) {
		rng_filename = fname;
		result = 0;
	}
	EVLOCK_UNLOCK(rng_lock, 0);
	return result;
#endif
}

int
evutil_secure_rng_init(void)
{
	int val;

	EVLOCK_LOCK(rng_lock, 0);
	val = evutil_secure_rng_init_();
	EVLOCK_UNLOCK(rng_lock, 0);
	return val;
}

static void
ev_arc4random_buf(void *buf, size_t n)
{
	int result;
	EVLOCK_LOCK(rng_lock, 0);
	result = evutil_secure_rng_init_();
	if (result == 0)
		result = evutil_secure_rng_read_(buf, n);
	if (result < 0)
		evutil_memclear_(buf, n);
	EVLOCK_UNLOCK(rng_lock, 0);
	if (result < 0)
		event_errx(1, "%s: unable to obtain operating-system randomness",
		    __func__);
}

#endif /* } !EVENT__HAVE_ARC4RANDOM */

void
evutil_secure_rng_get_bytes(void *buf, size_t n)
{
	if (n)
		ev_arc4random_buf(buf, n);
}

void
evutil_secure_rng_add_bytes(const char *buf, size_t n)
{
#if defined(EVENT__HAVE_ARC4RANDOM) && defined(EVENT__HAVE_ARC4RANDOM_STIR)
    arc4random_stir();
#endif
	(void) buf;
	(void) n;
}

void
evutil_free_secure_rng_globals_(void)
{
    evutil_free_secure_rng_globals_locks();
}
