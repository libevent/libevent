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
#include <stdint.h>    /* UINT64_C uint64_t */

#include <string.h>

#include <sys/queue.h>
#include <sys/param.h>

#include "timer.h"


/*
 * D E B U G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if TIMER_DEBUG - 0 || TIMER_MAIN - 0
#include <stdlib.h>
#include <stdio.h>

#undef TIMER_DEBUG
#define TIMER_DEBUG 1
#define DEBUG_LEVEL timer_debug

static int timer_debug;

#define SAYit_(lvl, fmt, ...) do { \
	if (DEBUG_LEVEL >= (lvl)) \
		fprintf(stderr, fmt "%s", __FILE__, __LINE__, __func__, __VA_ARGS__); \
} while (0)

#define SAYit(lvl, ...) SAYit_((lvl), "%s:%d:%s: " __VA_ARGS__, "\n")

#define PANIC(...) do { \
	SAYit(0, __VA_ARGS__); \
	_Exit(EXIT_FAILURE); \
} while (0)
#else
#undef TIMER_DEBUG
#define TIMER_DEBUG 0
#define DEBUG_LEVEL 0

#define SAYit(...) (void)0
#endif

#define SAY(...) SAYit(1, __VA_ARGS__)
#define HAI SAY("HAI")


static inline char *fmt_(char *buf, uint64_t ts) {
	char *p = buf;
	int period, n, i;

	for (period = 2; period >= 0; period--) {
		n = 63 & (ts >> (period * 6));

		for (i = 5; i >= 0; i--) {
			*p++ = '0' + !!(n & (1 << i));
		}

		if (period != 0)
			*p++ = ':';
	}

	*p = 0;

	return buf;
} /* fmt_() */

#define fmt(ts) fmt_(((char[64]){ 0 }), (ts))


static inline char *bin64_(char *buf, uint64_t n) {
	char *p = buf;
	int i;

	for (i = 0; i < 64; i++) {
		*p++ = "01"[0x1 & (n >> (63 - i))];
	}

	*p = 0;

	return buf;
} /* bin64_() */

#define bin64(ts) bin64_(((char[65]){ 0 }), (ts))


/*
 * A N C I L L A R Y  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define countof(a) (sizeof (a) / sizeof *(a))
#define endof(a) (&(a)[countof(a)])

#if !defined MIN
#define MIN(a, b) (((a) < (b))? (a) : (b))
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
 * These routines implement wheel parameterization.
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMER_BIT (sizeof (timer_t) * CHAR_BIT)

#if !defined WHEEL_BIT
#define WHEEL_BIT 6
#endif

#if !defined WHEEL_NUM
#define WHEEL_NUM 4
#endif

#define WHEEL_LEN (1U << WHEEL_BIT)
#define WHEEL_MAX (WHEEL_LEN - 1)
#define WHEEL_MASK (WHEEL_LEN - 1)
#define TIMEOUT_MAX ((TIMER_C(1) << (WHEEL_BIT * WHEEL_NUM)) - 1)

#if WHEEL_BIT == 6

#define WHEEL_C(n) UINT64_C(n)
#define WHEEL_PRIu PRIu64
#define WHEEL_PRIx PRIx64

typedef uint64_t wheel_t;

#define ctz(n) __builtin_ctzll(n)
#define fls(n) ((1 << WHEEL_BIT) - __builtin_clzll(n))

#elif WHEEL_BIT == 5

#define WHEEL_C(n) UINT32_C(n)
#define WHEEL_PRIu PRIu32
#define WHEEL_PRIx PRIx32

typedef uint32_t wheel_t;

#define ctz(n) __builtin_ctzl(n)
#define fls(n) ((1 << WHEEL_BIT) - __builtin_clzl(n))

#elif WHEEL_BIT == 4

#define WHEEL_C(n) UINT16_C(n)
#define WHEEL_PRIu PRIu16
#define WHEEL_PRIx PRIx16

typedef uint16_t wheel_t;

#define ctz(n) __builtin_ctz(n)
#define fls(n) ((1 << WHEEL_BIT) - __builtin_clz(n))

#elif WHEEL_BIT == 3

#define WHEEL_C(n) UINT8_C(n)
#define WHEEL_PRIu PRIu8
#define WHEEL_PRIx PRIx8

typedef uint8_t wheel_t;

#define ctz(n) __builtin_ctz(n)
#define fls(n) ((1 << WHEEL_BIT) - __builtin_clz(n))

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


static inline int timeout_wheel(timeout_t timeout) {
	return (fls(MIN(timeout, TIMEOUT_MAX)) - 1) / WHEEL_BIT;
} /* timeout_wheel() */


static inline int timer_slot(int wheel, timer_t expires) {
	return WHEEL_MASK & ((expires >> (wheel * WHEEL_BIT)) - !!wheel);
} /* timer_slot() */


/*
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

CIRCLEQ_HEAD(timeouts, timeout);

#define TIMEOUT_INITIALIZER { 0, 0, { 0, 0 } }

struct timeout {
	int flags;

	timer_t expires;

	struct timeouts *pending;
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

struct timer {
	struct timeouts wheel[WHEEL_NUM][WHEEL_LEN], expired;

	wheel_t pending[WHEEL_NUM];

	timer_t curtime;
	timer_t hertz;
}; /* struct timer */


struct timer *timer_init(struct timer *T, timer_t hz) {
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
	T->hertz = (hz)? hz : TIMER_mHZ;

	return T;
} /* timer_init() */


void timer_del(struct timer *T, struct timeout *to) {
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
} /* timer_del() */


static inline timeout_t timer_rem(struct timer *T, struct timeout *to) {
	return to->expires - T->curtime;
} /* timer_rem() */


void timer_add(struct timer *T, struct timeout *to, timer_t expires) {
	timeout_t rem;
	int wheel, slot;

	timer_del(T, to);

	to->expires = expires;

	if (expires > T->curtime) {
		rem = timer_rem(T, to);

		wheel = timeout_wheel(rem);
		slot = timer_slot(wheel, to->expires);

		SAY("%llu rem:%llu wheel:%d (fls:%d) slot:%d", expires, timer_rem(T, to), wheel, fls(timer_rem(T, to)) - 1, slot);
		SAY("clock: %s", fmt(expires));

		to->pending = &T->wheel[wheel][slot];
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);

		T->pending[wheel] |= WHEEL_C(1) << slot;
	} else {
		to->pending = &T->expired;
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);
	}
} /* timer_add() */


void timeout_add(struct timer *T, struct timeout *to, timeout_t timeout) {
	timer_add(T, to, T->curtime + timeout);
} /* timeout_add() */


void timer_step(struct timer *T, timer_t curtime) {
	timeout_t elapsed = curtime - T->curtime;
	struct timeouts todo;
	int wheel, slot;
	wheel_t _elapsed;

	CIRCLEQ_INIT(&todo);

	SAY("\n");
	SAY("== step =========================================");
	SAY("%" TIMER_PRIu " -> %" TIMER_PRIu, T->curtime, curtime);
	SAY("%s -> %s", fmt(T->curtime), fmt(curtime));

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		wheel_t pending;

		SAYit(2, "-- wheel (%u) ------------------------------------", wheel);

		if ((elapsed >> (wheel * WHEEL_BIT)) > WHEEL_MAX) {
			pending = ~WHEEL_C(0);
		} else {
			_elapsed = WHEEL_MASK & (elapsed >> (wheel * WHEEL_BIT));

			slot = WHEEL_MASK & (T->curtime >> (wheel * WHEEL_BIT));
			SAYit(2, "wheel:%u _elapsed:%llu slot:%d", wheel, _elapsed, slot);
			pending = rotl(((UINT64_C(1) << _elapsed) - 1), slot);

			slot = WHEEL_MASK & (curtime >> (wheel * WHEEL_BIT));
			SAYit(2, "slot: %d", slot);
			pending |= WHEEL_C(1) << slot;
			pending |= rotr(rotl(((WHEEL_C(1) << _elapsed) - 1), slot), _elapsed);
			SAYit(2, "rotl:%.*" TIMEOUT_PRIx " pending:%.*" WHEEL_PRIx, (int)(sizeof _elapsed * CHAR_BIT / 4), ((TIMEOUT_C(1) << _elapsed) - 1), (int)(sizeof pending * CHAR_BIT / 4), pending);
		}

		SAYit(2, "pending   : %s", bin64(pending));
		SAYit(2, "populated : %s", bin64(T->pending[wheel]));

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

		timer_add(T, to, to->expires);
	}

	return;
} /* timer_step() */


bool timer_pending(struct timer *T) {
	wheel_t pending = 0;
	int wheel;

	for (wheel = 0; wheel < WHEEL_NUM; wheel++) {
		pending |= T->pending[wheel];
	}

	return !!pending;
} /* timer_pending() */


timeout_t timer_timeout(struct timer *T) {
	timeout_t timeout = ~TIMEOUT_C(0), _timeout;
	timer_t relmask;
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
} /* timer_timeout() */


struct timeout *timer_get(struct timer *T) {
	if (!CIRCLEQ_EMPTY(&T->expired)) {
		return CIRCLEQ_FIRST(&T->expired);
	} else {
		return 0;
	}
} /* timer_get() */


#if TIMER_MAIN - 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static timer_t timer_min(struct timer *T) {
	struct timeout *to, *min = NULL;
	unsigned i, j;

	for (i = 0; i < countof(T->wheel); i++) {
		for (j = 0; j < countof(T->wheel[i]); j++) {
			CIRCLEQ_FOREACH(to, &T->wheel[i][j], cqe) {
				if (!min || min->expires > to->expires)
					min = to;
			}
		}
	}

	return (min)? min->expires : 0;
} /* timer_min() */

static inline timeout_t slow_timeout(struct timer *T) {
	return timer_min(T) - T->curtime;
} /* slow_timeout() */


int main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	struct timer T;
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

	timer_init(&T, TIMER_mHZ);
	timer_step(&T, time);
	timer_add(&T, timeout_init(&to[0], 0), time + 62); count++;
	timer_add(&T, timeout_init(&to[1], 0), time + 63); count++;
	timer_add(&T, timeout_init(&to[2], 0), time + 64); count++;
	timer_add(&T, timeout_init(&to[3], 0), time + 65); count++;
	timer_add(&T, timeout_init(&to[5], 0), time + 192); count++;

	while (count > 0 && time <= stop - 1) {
		time += step;
//printf("step: %llu\n", time);
SAY("timeout -> %" TIMEOUT_PRIu " (actual:%" TIMEOUT_PRIu " curtime:%" TIMER_PRIu ")", timer_timeout(&T), slow_timeout(&T), T.curtime);
		timer_step(&T, time);
//SAY("timeout <- %" TIMEOUT_PRIu " (curtime:%" TIMER_PRIu ")", timer_timeout(&T), T.curtime);

		while ((expired = timer_get(&T))) {
			timer_del(&T, expired);
			SAY("step %llu expired %llu @@@@@@@@@@@@@@@@@@@@", time, expired->expires);
			count--;
		}
	}

	SAY("%s curtime: %llu", (count == 0)? "OK" : "FAIL", T.curtime);

	return 0;
} /* main() */

#endif /* TIMER_MAIN */
