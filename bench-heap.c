/*
 * Copyright (c) 2006 Maxim Yegorushkin <maxim.yegorushkin@gmail.com>
 * All rights reserved.
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
#ifndef _MIN_HEAP_H_
#define _MIN_HEAP_H_

#include <stdlib.h>
#include <err.h>
#include "timeout.h"
#include "bench.h"

#define min_heap_idx interval

typedef timeout_t min_heap_idx_t;

typedef struct min_heap
{
    struct timeout** p;
    unsigned n, a;
} min_heap_t;

static inline void           min_heap_ctor(min_heap_t* s);
static inline void           min_heap_dtor(min_heap_t* s);
static inline void           min_heap_elem_init(struct timeout* e);
static inline int            min_heap_elem_greater(struct timeout *a, struct timeout *b);
static inline int            min_heap_empty(min_heap_t* s);
static inline unsigned       min_heap_size(min_heap_t* s);
static inline struct timeout*  min_heap_top(min_heap_t* s);
static inline int            min_heap_reserve(min_heap_t* s, unsigned n);
static inline int            min_heap_push(min_heap_t* s, struct timeout* e);
static inline struct timeout*  min_heap_pop(min_heap_t* s);
static inline int            min_heap_erase(min_heap_t* s, struct timeout* e);
static inline void           min_heap_shift_up_(min_heap_t* s, unsigned hole_index, struct timeout* e);
static inline void           min_heap_shift_down_(min_heap_t* s, unsigned hole_index, struct timeout* e);

int min_heap_elem_greater(struct timeout *a, struct timeout *b)
{
    return a->expires > b->expires;
}

void min_heap_ctor(min_heap_t* s) { s->p = 0; s->n = 0; s->a = 0; }
void min_heap_dtor(min_heap_t* s) { if(s->p) free(s->p); }
void min_heap_elem_init(struct timeout* e) { e->min_heap_idx = -1; }
int min_heap_empty(min_heap_t* s) { return 0u == s->n; }
unsigned min_heap_size(min_heap_t* s) { return s->n; }
struct timeout* min_heap_top(min_heap_t* s) { return s->n ? *s->p : 0; }

int min_heap_push(min_heap_t* s, struct timeout* e)
{
    if(min_heap_reserve(s, s->n + 1))
        return -1;
    min_heap_shift_up_(s, s->n++, e);
    return 0;
}

struct timeout* min_heap_pop(min_heap_t* s)
{
    if(s->n)
    {
        struct timeout* e = *s->p;
        min_heap_shift_down_(s, 0u, s->p[--s->n]);
        e->min_heap_idx = -1;
        return e;
    }
    return 0;
}

int min_heap_erase(min_heap_t* s, struct timeout* e)
{
    if(((min_heap_idx_t)-1) != e->min_heap_idx)
    {
        struct timeout *last = s->p[--s->n];
        unsigned parent = (e->min_heap_idx - 1) / 2;
	/* we replace e with the last element in the heap.  We might need to
	   shift it upward if it is less than its parent, or downward if it is
	   greater than one or both its children. Since the children are known
	   to be less than the parent, it can't need to shift both up and
	   down. */
        if (e->min_heap_idx > 0 && min_heap_elem_greater(s->p[parent], last))
             min_heap_shift_up_(s, e->min_heap_idx, last);
        else
             min_heap_shift_down_(s, e->min_heap_idx, last);
        e->min_heap_idx = -1;
        return 0;
    }
    return -1;
}

int min_heap_reserve(min_heap_t* s, unsigned n)
{
    if(s->a < n)
    {
        struct timeout** p;
        unsigned a = s->a ? s->a * 2 : 8;
        if(a < n)
            a = n;
        if(!(p = (struct timeout**)realloc(s->p, a * sizeof *p)))
            return -1;
        s->p = p;
        s->a = a;
    }
    return 0;
}

void min_heap_shift_up_(min_heap_t* s, unsigned hole_index, struct timeout* e)
{
    unsigned parent = (hole_index - 1) / 2;
    while(hole_index && min_heap_elem_greater(s->p[parent], e))
    {
        (s->p[hole_index] = s->p[parent])->min_heap_idx = hole_index;
        hole_index = parent;
        parent = (hole_index - 1) / 2;
    }
    (s->p[hole_index] = e)->min_heap_idx = hole_index;
}

void min_heap_shift_down_(min_heap_t* s, unsigned hole_index, struct timeout* e)
{
    unsigned min_child = 2 * (hole_index + 1);
    while(min_child <= s->n)
	{
        min_child -= min_child == s->n || min_heap_elem_greater(s->p[min_child], s->p[min_child - 1]);
        if(!(min_heap_elem_greater(e, s->p[min_child])))
            break;
        (s->p[hole_index] = s->p[min_child])->min_heap_idx = hole_index;
        hole_index = min_child;
        min_child = 2 * (hole_index + 1);
	}
    min_heap_shift_up_(s, hole_index,  e);
}

#endif /* _MIN_HEAP_H_ */


static timeout_t curtime;
static min_heap_t timeouts;

static void init(struct timeout *timeout, size_t count, int verbose) {
    size_t i;

    min_heap_ctor(&timeouts);
    if (0 != min_heap_reserve(&timeouts, count))
        err(1, "realloc");

    for (i = 0; i < count; i++) {
        min_heap_elem_init(&timeout[i]);
    }
} /* init() */


static void add(struct timeout *to, timeout_t expires) {
    min_heap_erase(&timeouts, to);
    to->expires = curtime + expires;
    if (0 != min_heap_push(&timeouts, to))
        err(1, "realloc");
} /* add() */


static void del(struct timeout *to) {
    min_heap_erase(&timeouts, to);
} /* del() */


static struct timeout *get(void) {
    struct timeout *to;

    if ((to = min_heap_top(&timeouts)) && to->expires <= curtime)
        return min_heap_pop(&timeouts);

    return NULL;
} /* get() */


static void update(timeout_t ts) {
    curtime = ts;
} /* update() */


static void check(void) {
    return;
} /* check() */


const struct vops VOPS = {
    .init   = &init,
    .add    = &add,
    .del    = &del,
    .get    = &get,
    .update = &update,
    .check  = &check,
};

