/* ==========================================================================
 * timeout.h - Tickless hierarchical timing wheel.
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
#ifndef TIMEOUT_H
#define TIMEOUT_H

#include <stdbool.h>    /* bool */
#include <stdio.h>      /* FILE */

#include <inttypes.h>   /* PRIu64 PRIx64 PRIX64 uint64_t */

#include <sys/queue.h>  /* TAILQ(3) */


/*
 * I N T E G E R  T Y P E  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_C(n) UINT64_C(n)
#define TIMEOUT_PRIu PRIu64
#define TIMEOUT_PRIx PRIx64
#define TIMEOUT_PRIX PRIX64

#define TIMEOUT_mHZ TIMEOUT_C(1000)
#define TIMEOUT_uHZ TIMEOUT_C(1000000)
#define TIMEOUT_nHZ TIMEOUT_C(1000000000)

typedef uint64_t timeout_t;


/*
 * C A L L B A C K  I N T E R F A C E
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeout_cb {
	void (*fn)();
	void *arg;
}; /* struct timeout_cb */


/*
 * T I M E O U T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_INT 0x01 /* interval (repeating) timeout */
#define TIMEOUT_ABS 0x02 /* treat timeout values as absolute */

#define TIMEOUT_INITIALIZER(flags) { (flags), 0, 0, 0, { 0, 0 } }

#define timeout_setcb(to, fn, arg) do { \
	(to)->callback.fn = (fn);       \
	(to)->callback.arg = (arg);     \
} while (0)

struct timeout {
	int flags;

	timeout_t interval;
	/* timeout interval if periodic */

	timeout_t expires;
	/* absolute expiration time */

	struct timeouts *timeouts;
	/* timeouts collection if member of */

	struct timeout_list *pending;
	/* timeout list if pending on wheel or expiry queue */

	struct timeout_cb callback;
	/* optional callback information */

	TAILQ_ENTRY(timeout) tqe;
}; /* struct timeout */


struct timeout *timeout_init(struct timeout *, int);
/* initialize timeout structure (same as TIMEOUT_INITIALIZER) */

bool timeout_pending(struct timeout *);
/* true if on timing wheel, false otherwise */
 
bool timeout_expired(struct timeout *);
/* true if on expired queue, false otherwise */

void timeout_del(struct timeout *);
/* remove timeout from any timing wheel (okay if not member of any) */


/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct timeouts;

struct timeouts *timeouts_open(timeout_t);
/* open a new timing wheel, setting optional HZ */

void timeouts_close(struct timeouts *);
/* destroy timing wheel */

void timeouts_update(struct timeouts *, timeout_t);
/* update timing wheel with current absolute time */

void timeouts_step(struct timeouts *, timeout_t);
/* step timing wheel by relative time */

timeout_t timeouts_timeout(struct timeouts *);
/* return interval to next required update */

void timeouts_add(struct timeouts *, struct timeout *, timeout_t);
/* add timeout to timing wheel */

void timeouts_addf(struct timeouts *, struct timeout *, double);
/* add timeout to timing wheel, translating floating point timeout */

void timeouts_del(struct timeouts *, struct timeout *);
/* remove timeout from any timing wheel or expired queue (okay if on neither) */

bool timeouts_pending(struct timeouts *);
/* return true if any timeouts pending on timing wheel */

bool timeouts_expired(struct timeouts *);
/* return true if any timeouts on expired queue */

bool timeouts_check(struct timeouts *, FILE *);
/* return true if invariants hold. describes failures to optional file handle. */


#endif /* TIMEOUT_H */
