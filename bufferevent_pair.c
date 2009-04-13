/*
 * Copyright (c) 2009 Niels Provos, Nick Mathewson
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

#include <sys/types.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#include "event2/util.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/event.h"
#include "defer-internal.h"
#include "bufferevent-internal.h"
#include "mm-internal.h"
#include "util-internal.h"

struct bufferevent_pair {
	struct bufferevent_private bev;
	struct bufferevent_pair *partner;
	struct deferred_cb deferred_write_cb;
	struct deferred_cb deferred_read_cb;
};


/* Given a bufferevent that's really a bev part of a bufferevent_pair,
 * return that bufferevent_filtered. Returns NULL otherwise.*/
static inline struct bufferevent_pair *
upcast(struct bufferevent *bev)
{
	struct bufferevent_pair *bev_p;
	if (bev->be_ops != &bufferevent_ops_pair)
		return NULL;
	bev_p = EVUTIL_UPCAST(bev, struct bufferevent_pair, bev.bev);
	assert(bev_p->bev.bev.be_ops == &bufferevent_ops_pair);
	return bev_p;
}

#define downcast(bev_pair) (&(bev_pair)->bev.bev)

/* XXX Handle close */

static void be_pair_outbuf_cb(struct evbuffer *,
    const struct evbuffer_cb_info *, void *);

static void
run_callback(struct deferred_cb *cb, void *arg)
{
	struct bufferevent_pair *bufev = arg;
	struct bufferevent *bev = downcast(bufev);

	BEV_LOCK(bev);
	if (cb == &bufev->deferred_read_cb) {
		if (bev->readcb) {
			bev->readcb(bev, bev->cbarg);
		}
	} else {
		if (bev->writecb) {
			bev->writecb(bev, bev->cbarg);
		}
	}
	BEV_UNLOCK(bev);
}

static struct bufferevent_pair *
bufferevent_pair_elt_new(struct event_base *base,
    enum bufferevent_options options)
{
	struct bufferevent_pair *bufev;
	if (! (bufev = mm_calloc(1, sizeof(struct bufferevent_pair))))
		return NULL;
	if (bufferevent_init_common(&bufev->bev, base, &bufferevent_ops_pair,
		options)) {
		mm_free(bufev);
		return NULL;
	}
	/* XXX set read timeout event */
	/* XXX set write timeout event */
	if (!evbuffer_add_cb(bufev->bev.bev.output, be_pair_outbuf_cb, bufev)) {
		bufferevent_free(downcast(bufev));
		return NULL;
	}
	event_deferred_cb_init(&bufev->deferred_read_cb, run_callback, bufev);
	event_deferred_cb_init(&bufev->deferred_write_cb, run_callback, bufev);

	return bufev;
}

int
bufferevent_pair_new(struct event_base *base, enum bufferevent_options options,
    struct bufferevent *pair[2])
{
        struct bufferevent_pair *bufev1 = NULL, *bufev2 = NULL;
	enum bufferevent_options tmp_options = options & ~BEV_OPT_THREADSAFE;

	bufev1 = bufferevent_pair_elt_new(base, options);
	if (!bufev1)
		return -1;
	bufev2 = bufferevent_pair_elt_new(base, tmp_options);
	if (!bufev2) {
		bufferevent_free(downcast(bufev1));
		return -1;
	}

	if (options & BEV_OPT_THREADSAFE) {
		/*XXXX check return */
		bufferevent_enable_locking(downcast(bufev2), bufev1->bev.lock);
	}

	bufev1->partner = bufev2;
	bufev2->partner = bufev1;

	evbuffer_freeze(downcast(bufev1)->input, 0);
	evbuffer_freeze(downcast(bufev1)->output, 1);
	evbuffer_freeze(downcast(bufev2)->input, 0);
	evbuffer_freeze(downcast(bufev2)->output, 1);

	pair[0] = downcast(bufev1);
	pair[1] = downcast(bufev2);

	return 0;
}

static void
be_pair_transfer(struct bufferevent *src, struct bufferevent *dst,
    int ignore_wm)
{
	size_t src_size, dst_size;
	size_t n;

	evbuffer_unfreeze(src->output, 1);
	evbuffer_unfreeze(dst->input, 0);

	if (dst->wm_read.high) {
		size_t dst_size = evbuffer_get_length(dst->input);
		if (dst_size < dst->wm_read.high) {
			n = dst->wm_read.high - dst_size;
			evbuffer_remove_buffer(src->output, dst->input, n);
		} else {
			if (!ignore_wm)
				goto done;
			evbuffer_add_buffer(dst->input, src->output);
		}
	} else {
		evbuffer_add_buffer(dst->input, src->output);
	}

	src_size = evbuffer_get_length(src->output);
	dst_size = evbuffer_get_length(dst->input);

	if (dst_size >= dst->wm_read.low && dst->readcb) {
		event_deferred_cb_schedule(dst->ev_base,
		    &(upcast(dst)->deferred_read_cb));
	}
	if (src_size <= src->wm_write.low && src->writecb) {
		event_deferred_cb_schedule(src->ev_base,
		    &(upcast(src)->deferred_write_cb));
	}
done:
	evbuffer_freeze(src->output, 1);
	evbuffer_freeze(dst->input, 0);
}

static inline int
be_pair_wants_to_talk(struct bufferevent_pair *src,
    struct bufferevent_pair *dst)
{
	return (downcast(src)->enabled & EV_WRITE) &&
	    (downcast(dst)->enabled & EV_READ) &&
	    !dst->bev.read_suspended &&
	    evbuffer_get_length(downcast(src)->output);
}

static void
be_pair_outbuf_cb(struct evbuffer *outbuf,
    const struct evbuffer_cb_info *info, void *arg)
{
	struct bufferevent_pair *bev_pair = arg;
	struct bufferevent_pair *partner = bev_pair->partner;

	if (info->n_added > info->n_deleted && partner) {
		/* We got more data.  If the other side's reading, then
		   hand it over. */
		if (be_pair_wants_to_talk(bev_pair, partner)) {
			be_pair_transfer(downcast(bev_pair), downcast(partner), 0);
		}
	}
}

static int
be_pair_enable(struct bufferevent *bufev, short events)
{
	struct bufferevent_pair *bev_p = upcast(bufev);
	struct bufferevent_pair *partner = bev_p->partner;

	/* We're starting to read! Does the other side have anything to write?*/
	if ((events & EV_READ) && partner &&
	    be_pair_wants_to_talk(partner, bev_p)) {
		be_pair_transfer(downcast(partner), bufev, 0);
	}
	/* We're starting to write! Does the other side want to read? */
	if ((events & EV_WRITE) && partner &&
	    be_pair_wants_to_talk(bev_p, partner)) {
		be_pair_transfer(bufev, downcast(partner), 0);
	}
	return 0;
}

static int
be_pair_disable(struct bufferevent *bev, short events)
{
	return 0;
}

static void
be_pair_destruct(struct bufferevent *bev)
{
	struct bufferevent_pair *bev_p = upcast(bev);

	if (bev_p->partner) {
		bev_p->partner->partner = NULL;
		bev_p->partner = NULL;
	}
	event_deferred_cb_cancel(bev->ev_base, &bev_p->deferred_write_cb);
	event_deferred_cb_cancel(bev->ev_base, &bev_p->deferred_read_cb);
}

static void
be_pair_adj_timeouts(struct bufferevent *bev)
{
	/* TODO: implement. */
}

static int
be_pair_flush(struct bufferevent *bev, short iotype,
    enum bufferevent_flush_mode mode)
{
	struct bufferevent_pair *bev_p = upcast(bev);
	struct bufferevent *partner;
	if (!bev_p->partner)
		return -1;

	partner = downcast(bev_p->partner);

	if (mode == BEV_NORMAL)
		return 0;

	if ((iotype & EV_READ) != 0)
		be_pair_transfer(partner, bev, 1);

	if ((iotype & EV_WRITE) != 0)
		be_pair_transfer(bev, partner, 1);

	if (mode == BEV_FINISHED) {
		if (partner->errorcb)
			(*partner->errorcb)(partner,
			    iotype|EVBUFFER_EOF, partner->cbarg);
	}
	return 0;
}

const struct bufferevent_ops bufferevent_ops_pair = {
	"pair_elt",
	evutil_offsetof(struct bufferevent_pair, bev),
	be_pair_enable,
	be_pair_disable,
	be_pair_destruct,
	be_pair_adj_timeouts,
	be_pair_flush,
};
