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
#include "debug.h"


#define abstime_t timeout_t /* for documentation purposes */
#define reltime_t timeout_t /* "" */


/*
 * A N C I L L A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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

#define CIRCLEQ_CONCAT(head1, head2, field) do {			\
	if (!CIRCLEQ_EMPTY(head2)) {					\
		if (!CIRCLEQ_EMPTY(head1)) {				\
			(head1)->cqh_last->field.cqe_next =		\
			    (head2)->cqh_first;				\
			(head2)->cqh_first->field.cqe_prev =		\
			    (head1)->cqh_last;				\
		} else {						\
			(head1)->cqh_first = (head2)->cqh_first;	\
			(head2)->cqh_first->field.cqe_prev =		\
			    (void *)(head1);				\
		}							\
		(head1)->cqh_last = (head2)->cqh_last;			\
		(head2)->cqh_last->field.cqe_next =			\
		    (void *)(head1);					\
		CIRCLEQ_INIT(head2);					\
	}								\
} while (0)


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
 * NOTE: Whether our bit-fiddling solution is quicker than looping through
 * all the slots is unproven. I hope to do this after this library
 * stabilizes.
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
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

CIRCLEQ_HEAD(timeout_list, timeout);

#define TIMEOUT_INITIALIZER { 0, 0, { 0, 0 } }

struct timeout {
	int flags;

	timeout_t expires;

	struct timeout_list *pending;
	CIRCLEQ_ENTRY(timeout) cqe;
}; /* struct timeout */


struct timeout *timeout_init(struct timeout *to, int flags) {
	memset(to, 0, sizeof *to);

	to->flags = flags;

	return to;
} /* timeout_init() */


/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

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
			CIRCLEQ_INIT(&T->wheel[i][j]);
		}
	}

	CIRCLEQ_INIT(&T->expired);

	for (i = 0; i < countof(T->pending); i++) {
		T->pending[i] = 0;
	}

	T->curtime = 0;
	T->hertz = (hz)? hz : TIMEOUT_mHZ;

	return T;
} /* timeouts_init() */


void timeouts_del(struct timeouts *T, struct timeout *to) {
	if (to->pending) {
		if (to->pending != &T->expired && CIRCLEQ_EMPTY(to->pending)) {
			ptrdiff_t index = to->pending - &T->wheel[0][0];
			int wheel = index / WHEEL_LEN;
			int slot = index % WHEEL_LEN;

			T->pending[wheel] &= ~(WHEEL_C(1) << slot);
		}

		CIRCLEQ_REMOVE(to->pending, to, cqe);
		to->pending = NULL;
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


void timeouts_add(struct timeouts *T, struct timeout *to, timeout_t expires) {
	timeout_t rem;
	int wheel, slot;

	timeouts_del(T, to);

	to->expires = expires;

	if (expires > T->curtime) {
		rem = timeout_rem(T, to);

		wheel = timeout_wheel(rem);
		slot = timeout_slot(wheel, to->expires);

		to->pending = &T->wheel[wheel][slot];
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);

		T->pending[wheel] |= WHEEL_C(1) << slot;
	} else {
		to->pending = &T->expired;
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);
	}
} /* timeouts_add() */


void timeouts_step(struct timeouts *T, abstime_t curtime) {
	timeout_t elapsed = curtime - T->curtime;
	struct timeout_list todo;
	int wheel;

	CIRCLEQ_INIT(&todo);

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
		 * slot, inclusive of the last slot.
		 */
		if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
			pending = (wheel_t)~WHEEL_C(0);
		} else {
			wheel_t _elapsed;
			int slot;

			_elapsed = WHEEL_MASK & (elapsed >> (wheel * WHEEL_BIT));

//			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));
//			pending = rotl(((UINT64_C(1) << _elapsed) - 1), slot);

			slot = WHEEL_MASK & (curtime >> (wheel * WHEEL_BIT));
			pending = rotr(rotl(((WHEEL_C(1) << _elapsed) - 1), slot), _elapsed);
			pending |= WHEEL_C(1) << slot;
		}

		while (pending & T->pending[wheel]) {
			int slot = ctz(pending & T->pending[wheel]);
			CIRCLEQ_CONCAT(&todo, &T->wheel[wheel][slot], cqe);
			T->pending[wheel] &= ~(UINT64_C(1) << slot);
		}

		if (!(0x1 & pending))
			break; /* break if we didn't reach end of wheel */

		/* if we're continuing, the next wheel must tick at least once */ 
		elapsed = MAX(elapsed, (WHEEL_LEN << (wheel * WHEEL_BIT)));
	}

	T->curtime = curtime;

	while (!CIRCLEQ_EMPTY(&todo)) {
		struct timeout *to = CIRCLEQ_FIRST(&todo);

		CIRCLEQ_REMOVE(&todo, to, cqe);
		to->pending = 0;

		timeouts_add(T, to, to->expires);
	}

	return;
} /* timeouts_step() */


bool timeouts_pending(struct timeouts *T) {
	wheel_t pending = 0;
	int wheel;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		pending |= T->pending[wheel];
	}

	return !!pending;
} /* timeouts_pending() */


timeout_t timeouts_timeout(struct timeouts *T) {
	timeout_t timeout = ~TIMEOUT_C(0), _timeout;
	timeout_t relmask;
	int wheel, slot;

	if (!CIRCLEQ_EMPTY(&T->expired))
		return 0;

	relmask = 0;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		if (T->pending[wheel]) {
			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));
			_timeout = (ctz(rotr(T->pending[wheel], slot)) + !!wheel) << (wheel * WHEEL_BIT);
			_timeout -= relmask & T->curtime;
			timeout = MIN(_timeout, timeout);
		}

		relmask <<= WHEEL_BIT; 
		relmask |= WHEEL_MASK;
	}

	return timeout;
} /* timeouts_timeout() */


struct timeout *timeouts_get(struct timeouts *T) {
	if (!CIRCLEQ_EMPTY(&T->expired)) {
		struct timeout *to = CIRCLEQ_FIRST(&T->expired);

		CIRCLEQ_REMOVE(&T->expired, to, cqe);
		to->pending = 0;

		return to;
	} else {
		return 0;
	}
} /* timeouts_get() */


#if TIMER_MAIN - 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static timeout_t timeouts_min(struct timeouts *T) {
	struct timeout *to, *min = NULL;
	unsigned i, j;

	for (i = 0; i < countof(T->wheel); i++) {
		for (j = 0; j < countof(T->wheel[i]); j++) {
			CIRCLEQ_FOREACH(to, &T->wheel[i][j], cqe) {
				if (!min || to->expires < min->expires)
					min = to;
			}
		}
	}

	return (min)? min->expires : 0;
} /* timeouts_min() */

static inline timeout_t slow_timeout(struct timeouts *T) {
	return timeouts_min(T) - T->curtime;
} /* slow_timeout() */


int main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	struct timeouts T;
	struct timeout to[8];
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
	timeouts_step(&T, time);
	timeouts_add(&T, timeout_init(&to[0], 0), time + 62); count++;
	timeouts_add(&T, timeout_init(&to[1], 0), time + 63); count++;
	timeouts_add(&T, timeout_init(&to[2], 0), time + 64); count++;
	timeouts_add(&T, timeout_init(&to[3], 0), time + 65); count++;
	timeouts_add(&T, timeout_init(&to[5], 0), time + 192); count++;

	while (count > 0 && time <= stop - 1) {
		time += step;

//		SAY("timeout -> %" TIMEOUT_PRIu " (actual:%" TIMEOUT_PRIu " curtime:%" TIMEOUT_PRIu ")", timeouts_timeout(&T), slow_timeout(&T), T.curtime);

		timeouts_step(&T, time);

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
