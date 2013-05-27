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


/*
 * D E B U G  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if TIMER_DEBUG - 0 || TIMER_MAIN - 0
#include <stdlib.h>
#include <stdio.h>

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


static inline uint64_t rotl(const uint64_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v << c) | (v >> (sizeof v * CHAR_BIT - c));
} /* rotl() */


static inline uint64_t rotr(const uint64_t v, int c) {
	if (!(c &= (sizeof v * CHAR_BIT - 1)))
		return v;

	return (v >> c) | (v << (sizeof v * CHAR_BIT - c));
} /* rotr() */


/*
 * From http://groups.google.com/group/comp.lang.c/msg/0cef41f343f0e875.
 *
 * The bitwise pattern 0x43147259a7abb7e can derive every permutation of 0
 * to 2^6-1, each permutation overlapping bitwise in the pattern, offset by
 * 1 bit. Multiplying by a power of 2 shifts one of the permutations into
 * the high 6 bits of the word, which is then shifted down 58 bits and
 * reduced modulo 2^6.
 *
 * The constant was found by brute force search with a sieve to quickly
 * discard invalid patterns. The following program generates constants for
 * mapping words of length 2^N (0 <= N <= 6), although it's not exhaustive.
 * Decode with `sed -e 's/^ \* //' | uudecode -p | gunzip -c`.
 *
 * begin 644 -
 * M'XL(`+J'&E$``\53VV[30!!]SG[%M%'3W=:T<5-%2$XL`4\(@9"@3S2*XAM=
 * MD:PC7Q"H[;]S=G;=NB$2[1-6K'CG<F;F[)FA-NFZS7*:U4VF37-V$]/Y"5V]
 * M__1U>KE\1RUL^&CHY%P,^[%KG=C8IT9=6IL%V%9(+.1$V40AAEE>:)/3QS=?
 * M/DB3Z*8.2"N24G:59*AH-B/G5(I>$0PCDEJI7O;G+GFS^JY3QK@6Y)\^.)`Y
 * M!/49@^(8MG"G1/>)&D+4S:K1*2W?EN6:RA^KWS(M3=T\4N!K.BN,Y++I5@P>
 * M8NH\-S2G<4`)FHR$&!1EA0X0K:T]PA]:X$9<.BRGIPPR2!"QP\??(^\$:!4A
 * M4Q<DN?2($H7SH,J;MC*HAP,[[N:4X'"/CKPOC,2]O2H>U=^3Y^!GJ3/4V[Z`
 * M`7M"QK?IY>+Y4Z,YF_.,(1>`T2\"]@H\I*,L.`RX-[U0%F+;-NG-JI+'U^98
 * M>1+LL'LX@.PRN7_\!VM1MB;[ARPV@65?\#TQ"L4TIM'(D>]Q.UW>]KH?_SHZ
 * M>\TOS6/"'-S-Y&+9J`XHILF%ZCN<\"-'[E-P:W37[[6P`8L.![NVNXQ^$+N*
 * M"-^CSDTWTX%,`,!,*$L^\^9P$18&SD5W=BNZ3E"<`Z#,,/J_K;`$.-!KP*E9
 * >&VE5P#?"7JPU?E-N_G'#O(`0[;+_`)GB4OE4!0``
 * `
 * end
 */
#define FFS64_HASH UINT64_C(0x43147259a7abb7e)
#define FFS64_MLEN 6
#define FFS64_INDEX(v) (((UINT64_C(1) << FFS64_MLEN) - 1) & ((((v) & -(v)) * FFS64_HASH) >> ((UINT64_C(1) << FFS64_MLEN) - FFS64_MLEN)))

static inline int ffs64(const uint64_t v) {
	static const int map[] = {
		63,  0,  1,  6,  2, 12,  7, 18,  3, 24, 13, 27,  8, 33, 19, 39,
		 4, 16, 25, 37, 14, 45, 28, 47,  9, 30, 34, 53, 20, 49, 40, 56,
		62,  5, 11, 17, 23, 26, 32, 38, 15, 36, 44, 46, 29, 52, 48, 55,
		61, 10, 22, 31, 35, 43, 51, 54, 60, 21, 42, 50, 59, 41, 58, 57,
	};

	return (v)? map[FFS64_INDEX(v)] + 1 : 0;
} /* ffs64() */


static inline int fls64(const uint64_t v) {
#if 0
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v |= v >> 32;
	v++;
#endif

	return (v)? ((sizeof v * CHAR_BIT) - 1) - __builtin_clzll(v) : 0;
} /* fls64 */


/*
 * T I M E O U T  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

CIRCLEQ_HEAD(timeouts, timeout);

#define TIMEOUT_INITIALIZER { 0, 0, { 0, 0 } }

struct timeout {
	uint64_t expires;

	struct timeouts *pending;
	CIRCLEQ_ENTRY(timeout) cqe;
}; /* struct timeout */


static inline struct timeout *timeout_init(struct timeout *to) {
	return memset(to, 0, sizeof *to);
} /* timeout_init() */


/*
 * T I M E R  R O U T I N E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define PERIOD_BIT 6
#define PERIOD_LEN (1 << PERIOD_BIT)
#define PERIOD_MAX (PERIOD_LEN - 1)
#define PERIOD_NUM 4
#define PERIOD_MASK (PERIOD_LEN - 1)
#define ELAPSED_MAX ((UINT64_C(1) << (PERIOD_BIT * PERIOD_NUM)) - 1)
#define TIMEOUT_PERIOD(elapsed) (fls64(MIN(ELAPSED_MAX, elapsed)) / PERIOD_BIT)
#define TIMEOUT_MINUTE(period, curtime, elapsed) (PERIOD_MASK & (((curtime) >> ((period) * PERIOD_BIT)) + ((elapsed) >> ((period) * PERIOD_BIT))))

static uint64_t timeout_minute(uint64_t period, uint64_t expires) {
	return PERIOD_MASK & ((expires >> (period * PERIOD_BIT)) - !!period);
} /* timeout_minute() */

#undef TIMEOUT_MINUTE
#define TIMEOUT_MINUTE(...) timeout_minute(__VA_ARGS__)


struct timer {
	struct timeouts wheel[4][64], expired;

	uint64_t pending[4];

	uint64_t curtime;
	uint64_t hertz;
}; /* struct timer */


struct timer *timer_init(struct timer *T) {
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

	return T;
} /* timer_init() */


void timer_del(struct timer *T, struct timeout *to) {
	if (to->pending) {
		if (to->pending != &T->expired && CIRCLEQ_EMPTY(to->pending)) {
			ptrdiff_t index = to->pending - &T->wheel[0][0];
			int period = index / 64;
			int minute = index % 64;

			T->pending[period] &= ~(UINT64_C(1) << minute);
		}

		CIRCLEQ_REMOVE(to->pending, to, cqe);
		to->pending = NULL;
	}
} /* timer_del() */


static inline uint64_t timer_rem(struct timer *T, struct timeout *to) {
	return to->expires - T->curtime;
} /* timer_rem() */


void timer_add(struct timer *T, struct timeout *to, uint64_t expires) {
	uint64_t rem;
	unsigned period, minute;

	timer_del(T, to);

	to->expires = expires;

	if (expires > T->curtime) {
		rem = timer_rem(T, to);

		period = TIMEOUT_PERIOD(rem);
		minute = TIMEOUT_MINUTE(period, to->expires);

		SAY("%llu rem:%llu period:%u (fls:%d) minute:%u", expires, timer_rem(T, to), period, fls64(timer_rem(T, to)), minute);
		SAY("clock: %s", fmt(expires));

		to->pending = &T->wheel[period][minute];
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);

		T->pending[period] |= UINT64_C(1) << minute;
	} else {
		to->pending = &T->expired;
		CIRCLEQ_INSERT_HEAD(to->pending, to, cqe);
	}
} /* timer_add() */


void timer_step(struct timer *T, uint64_t curtime) {
	uint64_t elapsed = curtime - T->curtime;
	struct timeouts todo;
	unsigned period;

	CIRCLEQ_INIT(&todo);
#if DEBUG_LEVEL
fputc('\n', stderr);
SAY("-- step -----------------------------------------");
SAY("%llu -> %llu", T->curtime, curtime);
SAY("%s -> %s", fmt(T->curtime), fmt(curtime));
#endif
	for (period = 0; period < PERIOD_NUM; period++) {
		uint64_t pending;

//SAY("newtime: %llu elapsed:%llu", curtime, elapsed);
		if ((elapsed >> (period * PERIOD_BIT)) > PERIOD_MAX) {
			pending = ~UINT64_C(0);
		} else {
			uint64_t _elapsed = PERIOD_MASK & (elapsed >> (period * PERIOD_BIT));
//			SAY("period:%u _elapsed:%llu minute:%llu", period, _elapsed, TIMEOUT_MINUTE(period, T->curtime, elapsed));
			pending = rotl(rotl(((UINT64_C(1) << (_elapsed + 1)) - 1), TIMEOUT_MINUTE(period, T->curtime)), 1);
//			pending = rotl(((UINT64_C(1) << _elapsed) - 1), TIMEOUT_MINUTE(period, T->curtime, 0));
SAY("rotl:%.8x%.8x pending:%.8x%.8x", (unsigned)(((UINT64_C(1) << _elapsed) - 1) >> 32), (unsigned)((UINT64_C(1) << _elapsed) - 1), (unsigned)(pending >> 32), (unsigned)pending);
		}

SAY("pending:%.8x%.8x & populated:%.8x%.8x", (unsigned)(pending >> 32), (unsigned)pending, (unsigned)(T->pending[period] >> 32), (unsigned)T->pending[period]);
SAY("pending   : %s", bin64(pending));
SAY("populated : %s", bin64(T->pending[period]));
		while (pending & T->pending[period]) {
			int minute = ffs64(pending & T->pending[period]) - 1;
			CIRCLEQ_CONCAT(&todo, &T->wheel[period][minute], cqe);
			T->pending[period] &= ~(UINT64_C(1) << minute);
		}

		if (!((UINT64_C(1) << 63) & pending))
			break; /* break if we didn't reach end of period */

		/* if we're continuing, the next period must tick at least once */ 
		elapsed = MAX(elapsed, (UINT64_C(64) << (period * PERIOD_BIT)));
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


struct timeout *timer_expired(struct timer *T) {
	if (!CIRCLEQ_EMPTY(&T->expired)) {
		return CIRCLEQ_FIRST(&T->expired);
	} else {
		return 0;
	}
} /* timer_expired() */


#if TIMER_MAIN - 0

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
	extern int optind;
	extern char *optarg;
	struct timer T;
	struct timeout to[8];
	struct timeout *expired;
	uint64_t time = 0, step = 1;
	unsigned count = 0;
	int opt;

	while (-1 != (opt = getopt(argc, argv, "s:t:v"))) {
		switch (opt) {
		case 's':
			time = strtoul(optarg, 0, 10);

			break;
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

	timer_init(&T);
//	timer_step(&T, time = 100);
	timer_add(&T, timeout_init(&to[0]), time + 62); count++;
	timer_add(&T, timeout_init(&to[1]), time + 63); count++;
	timer_add(&T, timeout_init(&to[2]), time + 64); count++;
	timer_add(&T, timeout_init(&to[3]), time + 65); count++;
//	timer_add(&T, timeout_init(&to[4]), 100); count++;
	timer_add(&T, timeout_init(&to[5]), time + 192); count++;
//	timer_add(&T, timeout_init(&to[6]), 65536); count++;
//	timer_add(&T, timeout_init(&to[7]), 65535 + 62); count++;

	while (count > 0 && time < (1<<8)) {
		time += step;
//printf("step: %llu\n", time);
		timer_step(&T, time);

		while ((expired = timer_expired(&T))) {
			timer_del(&T, expired);
			SAY("step %llu expired %llu @@@@@@@@@@@@@@@@@@@@", time, expired->expires);
			count--;
		}
	}

	SAY("%s curtime: %llu", (count == 0)? "OK" : "FAIL", T.curtime);

	return 0;
} /* main() */

#endif /* TIMER_MAIN */
