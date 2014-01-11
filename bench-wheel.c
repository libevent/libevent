#include "timeout.h"
#include "timeout.c"
#include "bench.h"


static struct timeouts timeouts;

static void init(struct timeout *timeout, size_t count, int verbose) {
	size_t i;

	timeouts_init(&timeouts, TIMEOUT_mHZ);

	for (i = 0; i < count; i++) {
		timeout_init(&timeout[i], 0);
	}

#if TIMEOUT_DEBUG - 0
	timeout_debug = verbose;
#endif
} /* init() */


static void add(struct timeout *to, timeout_t expires) {
	timeouts_add(&timeouts, to, expires);
} /* add() */


static void del(struct timeout *to) {
    timeouts_del(&timeouts, to);
} /* del() */


static struct timeout *get(void) {
	return timeouts_get(&timeouts);
} /* get() */


static void update(timeout_t ts) {
	timeouts_update(&timeouts, ts);
} /* update() */


static void (check)(void) {
    if (!timeouts_check(&timeouts, stderr))
        _Exit(1);
} /* check() */


const struct vops VOPS = {
    .init   = &init,
    .add    = &add,
    .del    = &del,
    .get    = &get,
    .update = &update,
    .check  = &check,
};

