/* ==========================================================================
 * timer.h - Tickless hierarchical timing wheel.
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
#ifndef TIMER_H
#define TIMER_H

#include <stdbool.h>   /* bool */
#include <inttypes.h>  /* PRIu64 PRIx64 PRIX64 uint64_t */


/*
 * T I M I N G  W H E E L  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMER_mHZ TIMER_C(1000)
#define TIMER_uHZ TIMER_C(1000000)
#define TIMER_nHZ TIMER_C(1000000000)

#define TIMER_C(n) UINT64_C(n)
#define TIMER_PRIu PRIu64
#define TIMER_PRIx PRIx64
#define TIMER_PRIX PRIX64

#define TIMEOUT_C(n) TIMER_C(n)
#define TIMEOUT_PRIu TIMER_PRIu
#define TIMEOUT_PRIx TIMER_PRIx
#define TIMEOUT_PRIX TIMER_PRIX

typedef uint64_t timer_t;  /* absolute times */
typedef timer_t timeout_t; /* relative times */

struct timer;
struct timeout;

void timer_add(struct timer *, struct timeout *, timeout_t);

void timer_del(struct timer *, struct timeout *);

bool timer_pending(struct timer *);

timeout_t timer_timeout(struct timer *);





/*
 * T I M E O U T  C O N T E X T  I N T E R F A C E S
 *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define TIMEOUT_PERIODIC 0x01

struct timeout *timeout_init(struct timeout *, int);

bool timeout_pending(struct timeout *);
/* true if pending in a timing wheel or on expired queue, false otherwise */
 
bool timeout_expired(struct timeout *);
/* true if currently or previously on expired queue, false otherwise */

#endif /* TIMER_H */
