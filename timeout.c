/* ==========================================================================
 * timer.c - Tickless hierarchical timing wheel.
 * --------------------------------------------------------------------------
 * Copyright (c) 2013  William Ahern
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ==========================================================================
 */

#include <limits.h>    /* CHAR_BIT */
#include <stddef.h>    /* NULL */
#include <inttypes.h>  /* UINT64_C uint64_t */

#include <string.h>

#include <sys/queue.h>

#include "timer.h"

#if TIMER_DEBUG - 0 || TIMER_MAIN - 0
#include "debug.h"
#endif


/*
 * A N C I L L A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define abstime_t timeout_t /* for documentation purposes */
#define reltime_t timeout_t /* "" */

#if !defined countof
#define countof(a) (sizeof (a) / sizeof *(a))
#endif

#if !defined endof
#define endof(a) (&(a)[countof(a)])
#endif

#if !defined MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
#endif

#if !defined MAX
#define MAX(a, b) (((a) > (b))? (a) : (b))
#endif

#if !defined TAILQ_CONCAT
#define	TAILQ_CONCAT(head1, head2, field) do {                          \
	if (!TAILQ_EMPTY(head2)) {                                      \
		*(head1)->tqh_last = (head2)->tqh_first;                \
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last; \
		(head1)->tqh_last = (head2)->tqh_last;                  \
		TAILQ_INIT((head2));                                    \
	}                                                               \
} while (0)
#endif


/*
 * B I T  M A N I P U L A T I O N  R O U T I N E S
 *
 * The macros and routines below implement wheel parameterization. The
 * inputs are:
 *
 *   WHEEL_BIT - The number of value bits mapped in each wheel. The
 *               lowest-order WHEEL_BIT bits index the lowest-order (highest
 *               resolution) wheel, the next group of WHEEL_BIT bits the
 *               higher wheel, etc.
 *
 *   WHEEL_NUM - The number of wheels. WHEEL_BIT * WHEEL_NUM = the number of
 *               value bits used by all the wheels. For the default of 6 and
 *               4, only the low 24 bits are processed. Any timeout value
 *               larger than this will cycle through again.
 *
 * The implementation uses bit fields to remember which slot in each wheel
 * is populated, and to generate masks of expiring slots according to the
 * current update interval (i.e. the "tickless" aspect). The slots to
 * process in a wheel are (populated-set & interval-mask).
 *
 * WHEEL_BIT cannot be larger than 6 bits because 2^6 -> 64 is the largest
 * number of slots which can be tracked in a uint64_t integer bit field.
 * WHEEL_BIT cannot be smaller than 3 bits because of our rotr and rotl
 * routines, which only operate on all the value bits in an integer, and
 * there's no integer smaller than uint8_t.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if !defined WHEEL_BIT
#define WHEEL_BIT 6
#endif

#if !defined WHEEL_NUM
#define WHEEL_NUM 4
#endif

#define WHEEL_LEN (1U << WHEEL_BIT)
#define WHEEL_MAX (WHEEL_LEN - 1)
#define WHEEL_MASK (WHEEL_LEN - 1)
#define TIMEOUT_MAX ((TIMEOUT_C(1) << (WHEEL_BIT * WHEEL_NUM)) - 1)

#if WHEEL_BIT == 6

#define WHEEL_C(n) UINT64_C(n)
#define WHEEL_PRIu PRIu64
#define WHEEL_PRIx PRIx64

typedef uint64_t wheel_t;

#define ctz(n) __builtin_ctzll(n)
#define fls(n) ((int)(sizeof (long long) * CHAR_BIT) - __builtin_clzll(n))

#elif WHEEL_BIT == 5

#define WHEEL_C(n) UINT32_C(n)
#define WHEEL_PRIu PRIu32
#define WHEEL_PRIx PRIx32

typedef uint32_t wheel_t;

#define ctz(n) __builtin_ctzl(n)
#define fls(n) ((int)(sizeof (long) * CHAR_BIT) - __builtin_clzl(n))

#elif WHEEL_BIT == 4

#define WHEEL_C(n) UINT16_C(n)
#define WHEEL_PRIu PRIu16
#define WHEEL_PRIx PRIx16

typedef uint16_t wheel_t;

#define ctz(n) __builtin_ctz(n)
#define fls(n) ((int)(sizeof (int) * CHAR_BIT) - __builtin_clz(n))

#elif WHEEL_BIT == 3

#define WHEEL_C(n) UINT8_C(n)
#define WHEEL_PRIu PRIu8
#define WHEEL_PRIx PRIx8

typedef uint8_t wheel_t;

#define ctz(n) __builtin_ctz(n)
#define fls(n) ((int)(sizeof (int) * CHAR_BIT) - __builtin_clz(n))

#else
#error invalid WHEEL_BIT value
#endif


static inline wheel_t rotl(const wheel_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v << c) | (v >> (sizeof v * CHAR_BIT - c));
} /* rotl() */


static inline wheel_t rotr(const wheel_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v >> c) | (v << (sizeof v * CHAR_BIT - c));
} /* rotr() */


/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

TAILQ_HEAD(timeout_list, timeout);

struct timeouts {
	struct timeout_list wheel[WHEEL_NUM][WHEEL_LEN], expired;

	wheel_t pending[WHEEL_NUM];

	timeout_t curtime;
	timeout_t hertz;
}; /* struct timeouts */


static struct timeouts *timeouts_init(struct timeouts *T, timeout_t hz) {
	unsigned i, j;

	for (i = 0; i < countof(T->wheel); i++) {
		for (j = 0; j < countof(T->wheel[i]); j++) {
			TAILQ_INIT(&T->wheel[i][j]);
		}
	}

	TAILQ_INIT(&T->expired);

	for (i = 0; i < countof(T->pending); i++) {
		T->pending[i] = 0;
	}

	T->curtime = 0;
	T->hertz = (hz)? hz : TIMEOUT_mHZ;

	return T;
} /* timeouts_init() */


void timeouts_del(struct timeouts *T, struct timeout *to) {
	if (to->pending) {
		if (to->pending != &T->expired && TAILQ_EMPTY(to->pending)) {
			ptrdiff_t index = to->pending - &T->wheel[0][0];
			int wheel = index / WHEEL_LEN;
			int slot = index % WHEEL_LEN;

			T->pending[wheel] &= ~(WHEEL_C(1) << slot);
		}

		TAILQ_REMOVE(to->pending, to, tqe);
		to->pending = NULL;
		to->timeouts = NULL;
	}
} /* timeouts_del() */


static inline reltime_t timeout_rem(struct timeouts *T, struct timeout *to) {
	return to->expires - T->curtime;
} /* timeout_rem() */


static inline int timeout_wheel(timeout_t timeout) {
	return (fls(MIN(timeout, TIMEOUT_MAX)) - 1) / WHEEL_BIT;
} /* timeout_wheel() */


static inline int timeout_slot(int wheel, timeout_t expires) {
	return WHEEL_MASK & ((expires >> (wheel * WHEEL_BIT)) - !!wheel);
} /* timeout_slot() */


static void timeouts_sched(struct timeouts *T, struct timeout *to, timeout_t expires) {
	timeout_t rem;
	int wheel, slot;

	timeouts_del(T, to);

	to->expires = expires;

	to->timeouts = T;

	if (expires > T->curtime) {
		rem = timeout_rem(T, to);

		wheel = timeout_wheel(rem);
		slot = timeout_slot(wheel, to->expires);

		to->pending = &T->wheel[wheel][slot];
		TAILQ_INSERT_TAIL(to->pending, to, tqe);

		T->pending[wheel] |= WHEEL_C(1) << slot;
	} else {
		to->pending = &T->expired;
		TAILQ_INSERT_TAIL(to->pending, to, tqe);
	}
} /* timeouts_sched() */


static void timeouts_readd(struct timeouts *T, struct timeout *to) {
	to->expires += to->interval;

	if (to->expires <= T->curtime) {
		if (to->expires < T->curtime) {
			timeout_t n = T->curtime - to->expires;
			timeout_t q = n / to->interval;
			timeout_t r = n % to->interval;

			if (r)
				to->expires += (to->interval * q) + (to->interval - r);
			else
				to->expires += (to->interval * q);
		} else {
			to->expires += to->interval;
		}
	}

	timeouts_sched(T, to, to->expires);
} /* timeouts_readd() */


void timeouts_add(struct timeouts *T, struct timeout *to, timeout_t timeout) {
	if (to->flags & TIMEOUT_INT)
		to->interval = MAX(1, timeout);

	if (to->flags & TIMEOUT_ABS)
		timeouts_sched(T, to, timeout);
	else
		timeouts_sched(T, to, T->curtime + timeout);
} /* timeouts_add() */


void timeouts_addf(struct timeouts *T, struct timeout *to, double timeout) {
	timeouts_add(T, to, timeout * T->hertz);
} /* timeouts_addf() */


void timeouts_update(struct timeouts *T, abstime_t curtime) {
	timeout_t elapsed = curtime - T->curtime;
	struct timeout_list todo;
	int wheel;

	TAILQ_INIT(&todo);

	/*
	 * There's no avoiding looping over every wheel. It's best to keep
	 * WHEEL_NUM smallish.
	 */
	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		wheel_t pending;

		/*
		 * Calculate the slots expiring in this wheel
		 *
		 * If the elapsed time is greater than the maximum period of
		 * the wheel, mark every position as expiring.
		 *
		 * Otherwise, to determine the expired slots fill in all the
		 * bits between the last slot processed and the current
		 * slot, inclusive of the last slot. We'll bitwise-AND this
		 * with our pending set below.
		 *
		 * If a wheel rolls over, force a tick of the next higher
		 * wheel.
		 */
		if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
			pending = (wheel_t)~WHEEL_C(0);
		} else {
			wheel_t _elapsed = WHEEL_MASK & (elapsed >> (wheel * WHEEL_BIT));
			int slot = WHEEL_MASK & (curtime >> (wheel * WHEEL_BIT));
			pending = rotr(rotl(((WHEEL_C(1) << _elapsed) - 1), slot), _elapsed);
			pending |= WHEEL_C(1) << slot;
		}

		while (pending & T->pending[wheel]) {
			int slot = ctz(pending & T->pending[wheel]);
			TAILQ_CONCAT(&todo, &T->wheel[wheel][slot], tqe);
			T->pending[wheel] &= ~(UINT64_C(1) << slot);
		}

		if (!(0x1 & pending))
			break; /* break if we didn't wrap around end of wheel */

		/* if we're continuing, the next wheel must tick at least once */
		elapsed = MAX(elapsed, (WHEEL_LEN << (wheel * WHEEL_BIT)));
	}

	T->curtime = curtime;

	while (!TAILQ_EMPTY(&todo)) {
		struct timeout *to = TAILQ_FIRST(&todo);

		TAILQ_REMOVE(&todo, to, tqe);
		to->pending = 0;

		timeouts_sched(T, to, to->expires);
	}

	return;
} /* timeouts_update() */


void timeouts_step(struct timeouts *T, reltime_t elapsed) {
	timeouts_update(T, T->curtime + elapsed);
} /* timeouts_step() */


bool timeouts_pending(struct timeouts *T) {
	wheel_t pending = 0;
	int wheel;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		pending |= T->pending[wheel];
	}

	return !!pending;
} /* timeouts_pending() */


bool timeouts_expired(struct timeouts *T) {
	return !TAILQ_EMPTY(&T->expired);
} /* timeouts_expired() */


/*
 * Calculate the interval before needing to process any timeouts pending on
 * any wheel.
 *
 * (This is separated from the public API routine so we can evaluate our
 * wheel invariant assertions irrespective of the expired queue.)
 *
 * This might return a timeout value sooner than any installed timeout if
 * only higher-order wheels have timeouts pending. We can only know when to
 * process a wheel, not precisely when a timeout is scheduled. Our timeout
 * accuracy could be off by 2^(N*M)-1 units where N is the wheel number and
 * M is WHEEL_BIT. Only timeouts which have fallen through to wheel 0 can be
 * known exactly.
 *
 * We should never return a timeout larger than the lowest actual timeout.
 */
static timeout_t timeouts_int(struct timeouts *T) {
	timeout_t timeout = ~TIMEOUT_C(0), _timeout;
	timeout_t relmask;
	int wheel, slot;

	relmask = 0;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		if (T->pending[wheel]) {
			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));

			_timeout = (ctz(rotr(T->pending[wheel], slot)) + !!wheel) << (wheel * WHEEL_BIT);
			/* +1 to higher order wheels as those timeouts are one rotation in the future (otherwise they'd be on a lower wheel or expired) */

			_timeout -= relmask & T->curtime;
			/* reduce by how much lower wheels have progressed */

			timeout = MIN(_timeout, timeout);
		}

		relmask <<= WHEEL_BIT; 
		relmask |= WHEEL_MASK;
	}

	return timeout;
} /* timeouts_int() */


/*
 * Calculate the interval our caller can wait before needing to process
 * events.
 */
timeout_t timeouts_timeout(struct timeouts *T) {
	if (!TAILQ_EMPTY(&T->expired))
		return 0;

	return timeouts_int(T);
} /* timeouts_timeout() */


struct timeout *timeouts_get(struct timeouts *T) {
	if (!TAILQ_EMPTY(&T->expired)) {
		struct timeout *to = TAILQ_FIRST(&T->expired);

		TAILQ_REMOVE(&T->expired, to, tqe);
		to->pending = 0;

		if ((to->flags & TIMEOUT_INT) && to->interval > 0) {
			timeouts_readd(T, to);
		} else {
			to->timeouts = 0;
		}

		return to;
	} else {
		return 0;
	}
} /* timeouts_get() */


/*
 * Use dumb looping to locate the earliest timeout pending on the wheel so
 * our invariant assertions can check the result of our optimized code.
 */
static struct timeout *timeouts_min(struct timeouts *T) {
	struct timeout *to, *min = NULL;
	unsigned i, j;

	for (i = 0; i < countof(T->wheel); i++) {
		for (j = 0; j < countof(T->wheel[i]); j++) {
			TAILQ_FOREACH(to, &T->wheel[i][j], tqe) {
				if (!min || to->expires < min->expires)
					min = to;
			}
		}
	}

	return min;
} /* timeouts_min() */


/*
 * Check some basic algorithm invariants. If these invariants fail then
 * something is definitely broken.
 */
#define report(...) do { \
	if ((fp)) \
		fprintf(fp, __VA_ARGS__); \
} while (0)

#define check(expr, ...) do { \
	if (!(expr)) { \
		report(__VA_ARGS__); \
		return 0; \
	} \
} while (0)

bool timeouts_check(struct timeouts *T, FILE *fp) {
	timeout_t timeout;
	struct timeout *to;

	if ((to = timeouts_min(T))) {
		check(to->expires > T->curtime, "missed timeout (expires:%" TIMEOUT_PRIu " <= curtime:%" TIMEOUT_PRIu ")\n", to->expires, T->curtime);

		timeout = timeouts_int(T);
		check(timeout <= to->expires - T->curtime, "wrong soft timeout (soft:%" TIMEOUT_PRIu " > hard:%" TIMEOUT_PRIu ") (expires:%" TIMEOUT_PRIu "; curtime:%" TIMEOUT_PRIu ")\n", timeout, (to->expires - T->curtime), to->expires, T->curtime);

		timeout = timeouts_timeout(T);
		check(timeout <= to->expires - T->curtime, "wrong soft timeout (soft:%" TIMEOUT_PRIu " > hard:%" TIMEOUT_PRIu ") (expires:%" TIMEOUT_PRIu "; curtime:%" TIMEOUT_PRIu ")\n", timeout, (to->expires - T->curtime), to->expires, T->curtime);
	} else {
		timeout = timeouts_timeout(T);

		if (!TAILQ_EMPTY(&T->expired))
			check(timeout == 0, "wrong soft timeout (soft:%" TIMEOUT_PRIu " != hard:%" TIMEOUT_PRIu ")\n", timeout, TIMEOUT_C(0));
		else
			check(timeout == ~TIMEOUT_C(0), "wrong soft timeout (soft:%" TIMEOUT_PRIu " != hard:%" TIMEOUT_PRIu ")\n", timeout, ~TIMEOUT_C(0));
	}

	return 1;
} /* timeouts_check() */


/*
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeout *timeout_init(struct timeout *to, int flags) {
	memset(to, 0, sizeof *to);

	to->flags = flags;

	return to;
} /* timeout_init() */


bool timeout_pending(struct timeout *to) {
	return to->pending && to->pending != &to->timeouts->expired;
} /* timeout_pending() */


bool timeout_expired(struct timeout *to) {
	return to->pending && to->pending == &to->timeouts->expired;
} /* timeout_expired() */


void timeout_del(struct timeout *to) {
	timeouts_del(to->timeouts, to);
} /* timeout_del() */


#if TIMER_MAIN - 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static timeout_t slow_timeout(struct timeouts *T) {
	struct timeout *to = timeouts_min(T);

	return (to)? to->expires - T->curtime : 0;
} /* slow_timeout() */



int main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	struct timeouts T;
	struct timeout to[16];
	struct timeout *expired;
	uint64_t time = 0, step = 1, stop = 0;
	unsigned count = 0;
	int opt;

	while (-1 != (opt = getopt(argc, argv, "s:t:v"))) {
		switch (opt) {
		case 's': {
			char *end;

			time = strtoul(optarg, &end, 10);

			if (*end == ':')
				stop = strtoul(end + 1, 0, 10);

			break;
		}
		case 't':
			if (!(step = strtoul(optarg, 0, 10)))
				PANIC("%llu: invalid tick count", step);

			break;
		case 'v':
			timer_debug++;

			break;
		}
	} /* while() */

	argc -= optind;
	argv += optind;

	timeouts_init(&T, TIMEOUT_mHZ);
	timeouts_update(&T, time);
	timeouts_add(&T, timeout_init(&to[0], 0), 62); count++;
	timeouts_add(&T, timeout_init(&to[1], 0), 63); count++;
	timeouts_add(&T, timeout_init(&to[2], 0), 64); count++;
	timeouts_add(&T, timeout_init(&to[3], 0), 65); count++;
	timeouts_add(&T, timeout_init(&to[5], 0), 192); count++;
	timeouts_add(&T, timeout_init(&to[6], 0), 6); count++;
	timeouts_add(&T, timeout_init(&to[7], 0), 7); count++;
	timeouts_add(&T, timeout_init(&to[8], 0), 8); count++;

	while (count > 0 && time <= stop - 1) {
		time += step;

		SAY("timeout -> %" TIMEOUT_PRIu " (actual:%" TIMEOUT_PRIu " curtime:%" TIMEOUT_PRIu ")", timeouts_timeout(&T), slow_timeout(&T), T.curtime);

		timeouts_check(&T, stderr);
		timeouts_update(&T, time);
		timeouts_check(&T, stderr);

		while ((expired = timeouts_get(&T))) {
			timeouts_del(&T, expired);
			SAY("step %llu expired %llu @@@@@@@@@@@@@@@@@@@@", time, expired->expires);
			count--;
		}
	}

	SAY("%s curtime: %llu", (count == 0)? "OK" : "FAIL", T.curtime);

	return 0;
} /* main() */

#endif /* TIMER_MAIN */
