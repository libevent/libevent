/* Portable arc4random.c based on arc4random.c from OpenBSD.
 * Portable version by Chris Davis, adapted for Libevent by Nick Mathewson
 *
 * Note that in Libevent, this file isn't compiled directly.  Instead,
 * it's included from evutil_rand.c
 */

/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Arc4 random number generator for OpenBSD.
 *
 * This code is derived from section 17.1 of Applied Cryptography,
 * second edition, which describes a stream cipher allegedly
 * compatible with RSA Labs "RC4" cipher (the actual description of
 * which is a trade secret).  The same algorithm is used as a stream
 * cipher called "arcfour" in Tatu Ylonen's ssh package.
 *
 * Here the stream cipher has been modified always to include the time
 * when initializing the state.  That makes it impossible to
 * regenerate the same random sequence twice, so this can't be used
 * for encryption, but will generate good random numbers.
 *
 * RC4 is a registered trademark of RSA Laboratories.
 */

#ifndef ARC4RANDOM_EXPORT
#define ARC4RANDOM_EXPORT
#endif

#ifndef ARC4RANDOM_UINT32
#define ARC4RANDOM_UINT32 uint32_t
#endif

#ifndef ARC4RANDOM_NO_INCLUDES
#ifdef WIN32
#include <wincrypt.h>
#include <process.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/time.h>
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#endif

/* Add platform entropy 32 bytes (256 bits) at a time. */
#define ADD_ENTROPY 32

/* Re-seed from the platform RNG after generating this many bytes. */
#define BYTES_BEFORE_RESEED 1600000

struct arc4_stream {
	unsigned char i;
	unsigned char j;
	unsigned char s[256];
};

#ifdef WIN32
#define getpid _getpid
#define pid_t int
#endif

static int rs_initialized;
static struct arc4_stream rs;
static pid_t arc4_stir_pid;
static int arc4_count;
static int arc4_seeded_ok;

static inline unsigned char arc4_getbyte(void);

static inline void
arc4_init(void)
{
	int     n;

	for (n = 0; n < 256; n++)
		rs.s[n] = n;
	rs.i = 0;
	rs.j = 0;
}

static inline void
arc4_addrandom(const unsigned char *dat, int datlen)
{
	int     n;
	unsigned char si;

	rs.i--;
	for (n = 0; n < 256; n++) {
		rs.i = (rs.i + 1);
		si = rs.s[rs.i];
		rs.j = (rs.j + si + dat[n % datlen]);
		rs.s[rs.i] = rs.s[rs.j];
		rs.s[rs.j] = si;
	}
	rs.j = rs.i;
}

#ifndef WIN32
static ssize_t
read_all(int fd, unsigned char *buf, size_t count)
{
	size_t numread = 0;
	ssize_t result;

	while (numread < count) {
		result = read(fd, buf+numread, count-numread);
		if (result<0)
			return -1;
		else if (result == 0)
			break;
		numread += result;
	}

	return (ssize_t)numread;
}
#endif

/* This is adapted from Tor's crypto_seed_rng() */
static int
arc4_seed(void)
{
	unsigned char buf[ADD_ENTROPY];

	/* local variables */
#ifdef WIN32
	static int provider_set = 0;
	static HCRYPTPROV provider;
#else
	static const char *filenames[] = {
		"/dev/srandom", "/dev/urandom", "/dev/random", NULL
	};
	int fd, i;
	size_t n;
#endif

#ifdef WIN32
	if (!provider_set) {
		if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL,
		    CRYPT_VERIFYCONTEXT)) {
			if ((unsigned long)GetLastError() != (unsigned long)NTE_BAD_KEYSET)
				return -1;
		}
		provider_set = 1;
	}
	if (!CryptGenRandom(provider, sizeof(buf), buf))
		return -1;
	arc4_addrandom(buf, sizeof(buf));
	memset(buf, 0, sizeof(buf));
	arc4_seeded_ok = 1;
	return 0;
#else
	for (i = 0; filenames[i]; ++i) {
		fd = open(filenames[i], O_RDONLY, 0);
		if (fd<0)
			continue;
		n = read_all(fd, buf, sizeof(buf));
		close(fd);
		if (n != sizeof(buf))
			return -1;
		arc4_addrandom(buf, sizeof(buf));
		memset(buf, 0, sizeof(buf));
		arc4_seeded_ok = 1;
		return 0;
	}

	return -1;
#endif
}

static void
arc4_stir(void)
{
	int     i;

	if (!rs_initialized) {
		arc4_init();
		rs_initialized = 1;
	}

	arc4_seed();

	/*
	 * Discard early keystream, as per recommendations in
	 * "Weaknesses in the Key Scheduling Algorithm of RC4" by
	 * Scott Fluhrer, Itsik Mantin, and Adi Shamir.
	 * http://www.wisdom.weizmann.ac.il/~itsik/RC4/Papers/Rc4_ksa.ps
	 *
	 * Ilya Mironov's "(Not So) Random Shuffles of RC4" suggests that
	 * we drop at least 2*256 bytes, with 12*256 as a conservative
	 * value.
	 *
	 * RFC4345 says to drop 6*256.
	 *
	 * At least some versions of this code drop 4*256, in a mistaken
	 * belief that "words" in the Fluhrer/Mantin/Shamir paper refers
	 * to processor words.
	 *
	 * We add another sect to the cargo cult, and choose 12*256.
	 */
	for (i = 0; i < 12*256; i++)
		(void)arc4_getbyte();
	arc4_count = BYTES_BEFORE_RESEED;
}


static void
arc4_stir_if_needed(void)
{
	pid_t pid = getpid();

	if (arc4_count <= 0 || !rs_initialized || arc4_stir_pid != pid)
	{
		arc4_stir_pid = pid;
		arc4_stir();
	}
}

static inline unsigned char
arc4_getbyte(void)
{
	unsigned char si, sj;

	rs.i = (rs.i + 1);
	si = rs.s[rs.i];
	rs.j = (rs.j + si);
	sj = rs.s[rs.j];
	rs.s[rs.i] = sj;
	rs.s[rs.j] = si;
	return (rs.s[(si + sj) & 0xff]);
}

static inline unsigned int
arc4_getword(void)
{
	unsigned int val;

	val = arc4_getbyte() << 24;
	val |= arc4_getbyte() << 16;
	val |= arc4_getbyte() << 8;
	val |= arc4_getbyte();

	return val;
}

#ifndef ARC4RANDOM_NOSTIR
ARC4RANDOM_EXPORT int
arc4random_stir(void)
{
	int val;
	_ARC4_LOCK();
	val = arc4_stir();
	_ARC4_UNLOCK();
	return val;
}
#endif

#ifndef ARC4RANDOM_NOADDRANDOM
ARC4RANDOM_EXPORT void
arc4random_addrandom(const unsigned char *dat, int datlen)
{
	int j;
	_ARC4_LOCK();
	if (!rs_initialized)
		arc4_stir();
	for (j = 0; j < datlen; j += 256) {
		/* arc4_addrandom() ignores all but the first 256 bytes of
		 * its input.  We want to make sure to look at ALL the
		 * data in 'dat', just in case the user is doing something
		 * crazy like passing us all the files in /var/log. */
		arc4_addrandom(dat + j, datlen - j);
	}
	_ARC4_UNLOCK();
}
#endif

#ifndef ARC4RANDOM_NORANDOM
ARC4RANDOM_EXPORT ARC4RANDOM_UINT32
arc4random(void)
{
	ARC4RANDOM_UINT32 val;
	_ARC4_LOCK();
	arc4_count -= 4;
	arc4_stir_if_needed();
	val = arc4_getword();
	_ARC4_UNLOCK();
	return val;
}
#endif

ARC4RANDOM_EXPORT void
arc4random_buf(void *_buf, size_t n)
{
	unsigned char *buf = _buf;
	_ARC4_LOCK();
	arc4_stir_if_needed();
	while (n--) {
		if (--arc4_count <= 0)
			arc4_stir();
		buf[n] = arc4_getbyte();
	}
	_ARC4_UNLOCK();
}

#ifndef ARC4RANDOM_NOUNIFORM
/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
ARC4RANDOM_EXPORT unsigned int
arc4random_uniform(unsigned int upper_bound)
{
	ARC4RANDOM_UINT32 r, min;

	if (upper_bound < 2)
		return 0;

#if (UINT_MAX > 0xffffffffUL)
	min = 0x100000000UL % upper_bound;
#else
	/* Calculate (2**32 % upper_bound) avoiding 64-bit math */
	if (upper_bound > 0x80000000)
		min = 1 + ~upper_bound;		/* 2**32 - upper_bound */
	else {
		/* (2**32 - (x * 2)) % x == 2**32 % x when x <= 2**31 */
		min = ((0xffffffff - (upper_bound * 2)) + 1) % upper_bound;
	}
#endif

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = arc4random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}
#endif
