/*
 * Copyright (c) 2009-2012 Niels Provos and Nick Mathewson
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

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include "event2/event-config.h"
#include "evconfig-private.h"

#include <sys/types.h>

#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef EVENT__HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef EVENT__HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "event2/bufferevent.h"
#include "event2/bufferevent_struct.h"
#include "event2/bufferevent_ssl.h"
#include "event2/buffer.h"
#include "event2/event.h"

#include "mm-internal.h"
#include "bufferevent-internal.h"
#include "log-internal.h"
#include "ssl-compat.h"

/* --------------------
   Now, here's the OpenSSL-based implementation of bufferevent.

   The implementation comes in two flavors: one that connects its SSL object
   to an underlying bufferevent using a BIO_bufferevent, and one that has the
   SSL object connect to a socket directly.  The latter should generally be
   faster, except on Windows, where your best bet is using a
   bufferevent_async.

   (OpenSSL supports many other BIO types, too.  But we can't use any unless
   we have a good way to get notified when they become readable/writable.)
   -------------------- */


static int be_ssl_enable(struct bufferevent *, short);
static int be_ssl_disable(struct bufferevent *, short);
static void be_ssl_unlink(struct bufferevent *);
static void be_ssl_destruct(struct bufferevent *);
static int be_ssl_adj_timeouts(struct bufferevent *);
static int be_ssl_flush(struct bufferevent *bufev,
    short iotype, enum bufferevent_flush_mode mode);
static int be_ssl_ctrl(struct bufferevent *, enum bufferevent_ctrl_op, union bufferevent_ctrl_data *);

const struct bufferevent_ops bufferevent_ops_ssl = {
	"ssl",
	evutil_offsetof(struct bufferevent_ssl, bev.bev),
	be_ssl_enable,
	be_ssl_disable,
	be_ssl_unlink,
	be_ssl_destruct,
	be_ssl_adj_timeouts,
	be_ssl_flush,
	be_ssl_ctrl,
};

/* Given a bufferevent, return a pointer to the bufferevent_ssl that
 * contains it, if any. */
struct bufferevent_ssl *
bufferevent_ssl_upcast(struct bufferevent *bev)
{
	struct bufferevent_ssl *bev_o;
	if (!BEV_IS_SSL(bev))
		return NULL;
	bev_o = (void*)( ((char*)bev) -
			 evutil_offsetof(struct bufferevent_ssl, bev.bev));
	EVUTIL_ASSERT(BEV_IS_SSL(&bev_o->bev.bev));
	return bev_o;
}

void
bufferevent_ssl_put_error(struct bufferevent_ssl *bev_ssl, unsigned long err)
{
	if (bev_ssl->n_errors == NUM_ERRORS)
		return;
	/* The error type according to openssl is "unsigned long", but
	   openssl never uses more than 32 bits of it.  It _can't_ use more
	   than 32 bits of it, since it needs to report errors on systems
	   where long is only 32 bits.
	 */
	bev_ssl->errors[bev_ssl->n_errors++] = (ev_uint32_t) err;
}

/* Have the base communications channel (either the underlying bufferevent or
 * ev_read and ev_write) start reading.  Take the read-blocked-on-write flag
 * into account. */
static int
start_reading(struct bufferevent_ssl *bev_ssl)
{
	if (bev_ssl->underlying) {
		bufferevent_unsuspend_read_(bev_ssl->underlying,
		    BEV_SUSPEND_FILT_READ);
		return 0;
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		int r;
		r = bufferevent_add_event_(&bev->ev_read, &bev->timeout_read);
		if (r == 0 && bev_ssl->read_blocked_on_write)
			r = bufferevent_add_event_(&bev->ev_write,
			    &bev->timeout_write);
		return r;
	}
}

/* Have the base communications channel (either the underlying bufferevent or
 * ev_read and ev_write) start writing.  Take the write-blocked-on-read flag
 * into account. */
static int
start_writing(struct bufferevent_ssl *bev_ssl)
{
	int r = 0;
	if (bev_ssl->underlying) {
		if (bev_ssl->write_blocked_on_read) {
			bufferevent_unsuspend_read_(bev_ssl->underlying,
			    BEV_SUSPEND_FILT_READ);
		}
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		r = bufferevent_add_event_(&bev->ev_write, &bev->timeout_write);
		if (!r && bev_ssl->write_blocked_on_read)
			r = bufferevent_add_event_(&bev->ev_read,
			    &bev->timeout_read);
	}
	return r;
}

void
bufferevent_ssl_stop_reading(struct bufferevent_ssl *bev_ssl)
{
	if (bev_ssl->write_blocked_on_read)
		return;
	if (bev_ssl->underlying) {
		bufferevent_suspend_read_(bev_ssl->underlying,
		    BEV_SUSPEND_FILT_READ);
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		event_del(&bev->ev_read);
	}
}

void
bufferevent_ssl_stop_writing(struct bufferevent_ssl *bev_ssl)
{
	if (bev_ssl->read_blocked_on_write)
		return;
	if (bev_ssl->underlying) {
		bufferevent_unsuspend_read_(bev_ssl->underlying,
		    BEV_SUSPEND_FILT_READ);
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		event_del(&bev->ev_write);
	}
}

static int
set_rbow(struct bufferevent_ssl *bev_ssl)
{
	if (!bev_ssl->underlying)
		bufferevent_ssl_stop_reading(bev_ssl);
	bev_ssl->read_blocked_on_write = 1;
	return start_writing(bev_ssl);
}

static int
set_wbor(struct bufferevent_ssl *bev_ssl)
{
	if (!bev_ssl->underlying)
		bufferevent_ssl_stop_writing(bev_ssl);
	bev_ssl->write_blocked_on_read = 1;
	return start_reading(bev_ssl);
}

static int
clear_rbow(struct bufferevent_ssl *bev_ssl)
{
	struct bufferevent *bev = &bev_ssl->bev.bev;
	int r = 0;
	bev_ssl->read_blocked_on_write = 0;
	if (!(bev->enabled & EV_WRITE))
		bufferevent_ssl_stop_writing(bev_ssl);
	if (bev->enabled & EV_READ)
		r = start_reading(bev_ssl);
	return r;
}


static int
clear_wbor(struct bufferevent_ssl *bev_ssl)
{
	struct bufferevent *bev = &bev_ssl->bev.bev;
	int r = 0;
	bev_ssl->write_blocked_on_read = 0;
	if (!(bev->enabled & EV_READ))
		bufferevent_ssl_stop_reading(bev_ssl);
	if (bev->enabled & EV_WRITE)
		r = start_writing(bev_ssl);
	return r;
}

#define OP_MADE_PROGRESS 1
#define OP_BLOCKED 2
#define OP_ERR 4

/* Return a bitmask of OP_MADE_PROGRESS (if we read anything); OP_BLOCKED (if
   we're now blocked); and OP_ERR (if an error occurred). */
static int
do_read(struct bufferevent_ssl *bev_ssl, int n_to_read) {
	/* Requires lock */
	struct bufferevent *bev = &bev_ssl->bev.bev;
	struct evbuffer *input = bev->input;
	int r, n, i = 0, atmost;
	struct evbuffer_iovec space[2];
	int result = 0;
	size_t len = 0;

	if (bev_ssl->bev.read_suspended)
		return 0;

	atmost = bufferevent_get_read_max_(&bev_ssl->bev);
	if (n_to_read > atmost)
		n_to_read = atmost;

	n = evbuffer_reserve_space(input, n_to_read, space, 2);
	if (n < 0)
		return OP_ERR;

	for (i = 0; i < n;) {
		if (bev_ssl->bev.read_suspended)
			break;
		bev_ssl->ssl_ops->clear_error();
		r = bev_ssl->ssl_ops->read(
			bev_ssl->ssl, (unsigned char *)space[i].iov_base + len, space[i].iov_len - len);
		if (r > 0) {
			result |= OP_MADE_PROGRESS;
			if (bev_ssl->read_blocked_on_write)
				if (clear_rbow(bev_ssl) < 0)
					return OP_ERR | result;
			bev_ssl->ssl_ops->decrement_buckets(bev_ssl);
			len += r;
			if (space[i].iov_len - len > 0) {
				continue;
			} else {
				space[i].iov_len = len;
				len = 0;
				++i;
			}
		} else {
			int err = bev_ssl->ssl_ops->get_error(bev_ssl->ssl, r);
			bev_ssl->ssl_ops->print_err(err);
			/* NOTE: we ignore the error in case of some progress was done,
			 * because currently we do not send close_notify, and this will
			 * lead to error from SSL_read() (it will return 0, and
			 * SSL_get_error() will return SSL_ERROR_SSL), and this is because
			 * of lack of close_notify
			 *
			 * But AFAICS some code uses it the same way (i.e. nginx) */
			if (result & OP_MADE_PROGRESS) {
				/* Process existing data */
				break;
			} else if (bev_ssl->ssl_ops->err_is_want_read(err)) {
				/* Can't read until underlying has more data. */
				if (bev_ssl->read_blocked_on_write)
					if (clear_rbow(bev_ssl) < 0)
						return OP_ERR | result;
			} else if (bev_ssl->ssl_ops->err_is_want_write(err)) {
				/* This read operation requires a write, and the
				 * underlying is full */
				if (!bev_ssl->read_blocked_on_write)
					if (set_rbow(bev_ssl) < 0)
						return OP_ERR | result;
			} else {
				bev_ssl->ssl_ops->conn_closed(bev_ssl, BEV_EVENT_READING, err, r);
			}
			result |= OP_BLOCKED;
			break; /* out of the loop */
		}
	}

	if (len > 0) {
		space[i].iov_len = len;
		++i;
	}

	if (i) {
		evbuffer_commit_space(input, space, i);
		if (bev_ssl->underlying)
			BEV_RESET_GENERIC_READ_TIMEOUT(bev);
	}

	return result;
}

/* Return a bitmask of OP_MADE_PROGRESS (if we wrote anything); OP_BLOCKED (if
   we're now blocked); and OP_ERR (if an error occurred). */
static int
do_write(struct bufferevent_ssl *bev_ssl, int atmost)
{
	int i, r, n, n_written = 0;
	struct bufferevent *bev = &bev_ssl->bev.bev;
	struct evbuffer *output = bev->output;
	struct evbuffer_iovec space[8];
	int result = 0;

	if (bev_ssl->last_write > 0)
		atmost = bev_ssl->last_write;
	else
		atmost = bufferevent_get_write_max_(&bev_ssl->bev);

	if (bev_ssl->flags & BUFFEREVENT_SSL_BATCH_WRITE) {
		/* Try to send as many as we can to avoid Nagle effect */
		evbuffer_pullup(output, -1);
	}

	n = evbuffer_peek(output, atmost, NULL, space, 8);
	if (n < 0)
		return OP_ERR | result;

	if (n > 8)
		n = 8;
	for (i=0; i < n;) {
		if (bev_ssl->bev.write_suspended)
			break;

		/* SSL_write will (reasonably) return 0 if we tell it to
		   send 0 data.  Skip this case so we don't interpret the
		   result as an error */
		if (space[i].iov_len == 0) {
			++i;
			continue;
		}

		bev_ssl->ssl_ops->clear_error();
		r = bev_ssl->ssl_ops->write(bev_ssl->ssl, space[i].iov_base,
		    space[i].iov_len);
		if (r > 0) {
			result |= OP_MADE_PROGRESS;
			if (bev_ssl->write_blocked_on_read)
				if (clear_wbor(bev_ssl) < 0)
					return OP_ERR | result;
			n_written += r;
			bev_ssl->last_write = -1;
			bev_ssl->ssl_ops->decrement_buckets(bev_ssl);
			space[i].iov_base = (unsigned char *)space[i].iov_base + r;
			space[i].iov_len -= r;
			if (space[i].iov_len == 0)
				++i;
		} else {
			int err = bev_ssl->ssl_ops->get_error(bev_ssl->ssl, r);
			bev_ssl->ssl_ops->print_err(err);
			if (bev_ssl->ssl_ops->err_is_want_write(err)) {
				/* Can't read until underlying has more data. */
				if (bev_ssl->write_blocked_on_read)
					if (clear_wbor(bev_ssl) < 0)
						return OP_ERR | result;
				bev_ssl->last_write = space[i].iov_len;
			} else if (bev_ssl->ssl_ops->err_is_want_read(err)) {
				/* This read operation requires a write, and the
				 * underlying is full */
				if (!bev_ssl->write_blocked_on_read)
					if (set_wbor(bev_ssl) < 0)
						return OP_ERR | result;
				bev_ssl->last_write = space[i].iov_len;
			} else {
				bev_ssl->ssl_ops->conn_closed(bev_ssl, BEV_EVENT_WRITING, err, r);
				bev_ssl->last_write = -1;
			}
			result |= OP_BLOCKED;
			break;
		}
	}
	if (n_written) {
		if (evbuffer_drain(output, n_written))
			return OP_ERR | result;

		if (bev_ssl->underlying)
			BEV_RESET_GENERIC_WRITE_TIMEOUT(bev);

		bufferevent_trigger_nolock_(bev, EV_WRITE, BEV_OPT_DEFER_CALLBACKS);
	}
	return result;
}

#define WRITE_FRAME 15000

/* Try to figure out how many bytes to read; return 0 if we shouldn't be
 * reading. */
static int
bytes_to_read(struct bufferevent_ssl *bev)
{
	struct evbuffer *input = bev->bev.bev.input;
	struct event_watermark *wm = &bev->bev.bev.wm_read;
	int result = 0;
	ev_ssize_t limit;
	/* XXX 99% of this is generic code that nearly all bufferevents will
	 * want. */

	if (bev->write_blocked_on_read) {
		return 0;
	}

	if (! (bev->bev.bev.enabled & EV_READ)) {
		return 0;
	}

	if (bev->bev.read_suspended) {
		return 0;
	}

	if (wm->high) {
		if (evbuffer_get_length(input) >= wm->high) {
			return 0;
		}

		result = wm->high - evbuffer_get_length(input);
	}

	/* Respect the rate limit */
	limit = bufferevent_get_read_max_(&bev->bev);
	if (result == 0 || result > limit) {
		result = limit;
	}

	return result;
}


/* Things look readable.  If write is blocked on read, write till it isn't.
 * Read from the underlying buffer until we block or we hit our high-water
 * mark.
 */
static void
consider_reading(struct bufferevent_ssl *bev_ssl)
{
	int r;
	int n_to_read;
	int all_result_flags = 0;

	while (bev_ssl->write_blocked_on_read) {
		r = do_write(bev_ssl, WRITE_FRAME);
		if (r & (OP_BLOCKED|OP_ERR))
			break;
	}
	if (bev_ssl->write_blocked_on_read)
		return;

	n_to_read = bytes_to_read(bev_ssl);

	while (n_to_read) {
		r = do_read(bev_ssl, n_to_read);
		all_result_flags |= r;

		if (r & (OP_BLOCKED|OP_ERR))
			break;

		if (bev_ssl->bev.read_suspended)
			break;

		/* Read all pending data.  This won't hit the network
		 * again, and will (most importantly) put us in a state
		 * where we don't need to read anything else until the
		 * socket is readable again.  It'll potentially make us
		 * overrun our read high-watermark (somewhat
		 * regrettable).  The damage to the rate-limit has
		 * already been done, since OpenSSL went and read a
		 * whole SSL record anyway. */
		n_to_read = bev_ssl->ssl_ops->pending(bev_ssl->ssl);

		/* XXX This if statement is actually a bad bug, added to avoid
		 * XXX a worse bug.
		 *
		 * The bad bug: It can potentially cause resource unfairness
		 * by reading too much data from the underlying bufferevent;
		 * it can potentially cause read looping if the underlying
		 * bufferevent is a bufferevent_pair and deferred callbacks
		 * aren't used.
		 *
		 * The worse bug: If we didn't do this, then we would
		 * potentially not read any more from bev_ssl->underlying
		 * until more data arrived there, which could lead to us
		 * waiting forever.
		 */
		if (!n_to_read && bev_ssl->underlying)
			n_to_read = bytes_to_read(bev_ssl);
	}

	if (all_result_flags & OP_MADE_PROGRESS) {
		struct bufferevent *bev = &bev_ssl->bev.bev;

		bufferevent_trigger_nolock_(bev, EV_READ, 0);
	}

	if (!bev_ssl->underlying) {
		/* Should be redundant, but let's avoid busy-looping */
		if (bev_ssl->bev.read_suspended ||
		    !(bev_ssl->bev.bev.enabled & EV_READ)) {
			event_del(&bev_ssl->bev.bev.ev_read);
		}
	}
}

static void
consider_writing(struct bufferevent_ssl *bev_ssl)
{
	int r;
	struct evbuffer *output = bev_ssl->bev.bev.output;
	struct evbuffer *target = NULL;
	struct event_watermark *wm = NULL;

	while (bev_ssl->read_blocked_on_write) {
		r = do_read(bev_ssl, 1024); /* XXXX 1024 is a hack */
		if (r & OP_MADE_PROGRESS) {
			struct bufferevent *bev = &bev_ssl->bev.bev;

			bufferevent_trigger_nolock_(bev, EV_READ, 0);
		}
		if (r & (OP_ERR|OP_BLOCKED))
			break;
	}
	if (bev_ssl->read_blocked_on_write)
		return;
	if (bev_ssl->underlying) {
		target = bev_ssl->underlying->output;
		wm = &bev_ssl->underlying->wm_write;
	}
	while ((bev_ssl->bev.bev.enabled & EV_WRITE) &&
	    (! bev_ssl->bev.write_suspended) &&
	    evbuffer_get_length(output) &&
	    (!target || (! wm->high || evbuffer_get_length(target) < wm->high))) {
		int n_to_write;
		if (wm && wm->high)
			n_to_write = wm->high - evbuffer_get_length(target);
		else
			n_to_write = WRITE_FRAME;
		r = do_write(bev_ssl, n_to_write);
		if (r & (OP_BLOCKED|OP_ERR))
			break;
	}

	if (!bev_ssl->underlying) {
		if (evbuffer_get_length(output) == 0) {
			event_del(&bev_ssl->bev.bev.ev_write);
		} else if (bev_ssl->bev.write_suspended ||
		    !(bev_ssl->bev.bev.enabled & EV_WRITE)) {
			/* Should be redundant, but let's avoid busy-looping */
			event_del(&bev_ssl->bev.bev.ev_write);
		}
	}
}

static void
be_ssl_readcb(struct bufferevent *bev_base, void *ctx)
{
	struct bufferevent_ssl *bev_ssl = ctx;
	consider_reading(bev_ssl);
}

static void
be_ssl_writecb(struct bufferevent *bev_base, void *ctx)
{
	struct bufferevent_ssl *bev_ssl = ctx;
	consider_writing(bev_ssl);
}

static void
be_ssl_eventcb(struct bufferevent *bev_base, short what, void *ctx)
{
	struct bufferevent_ssl *bev_ssl = ctx;
	int event = 0;

	if (what & BEV_EVENT_EOF) {
		if (bev_ssl->flags & BUFFEREVENT_SSL_DIRTY_SHUTDOWN)
			event = BEV_EVENT_EOF;
		else
			event = BEV_EVENT_ERROR;
	} else if (what & BEV_EVENT_TIMEOUT) {
		/* We sure didn't set this.  Propagate it to the user. */
		event = what;
	} else if (what & BEV_EVENT_ERROR) {
		/* An error occurred on the connection.  Propagate it to the user. */
		event = what;
	} else if (what & BEV_EVENT_CONNECTED) {
		/* Ignore it.  We're saying SSL_connect() already, which will
		   eat it. */
	}
	if (event)
		bufferevent_run_eventcb_(&bev_ssl->bev.bev, event, 0);
}

static void
be_ssl_readeventcb(evutil_socket_t fd, short what, void *ptr)
{
	struct bufferevent_ssl *bev_ssl = ptr;
	bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
	if (what == EV_TIMEOUT) {
		bufferevent_run_eventcb_(&bev_ssl->bev.bev,
		    BEV_EVENT_TIMEOUT|BEV_EVENT_READING, 0);
	} else {
		consider_reading(bev_ssl);
	}
	bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static void
be_ssl_writeeventcb(evutil_socket_t fd, short what, void *ptr)
{
	struct bufferevent_ssl *bev_ssl = ptr;
	bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
	if (what == EV_TIMEOUT) {
		bufferevent_run_eventcb_(&bev_ssl->bev.bev,
		    BEV_EVENT_TIMEOUT|BEV_EVENT_WRITING, 0);
	} else {
		consider_writing(bev_ssl);
	}
	bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static evutil_socket_t
be_ssl_auto_fd(struct bufferevent_ssl *bev_ssl, evutil_socket_t fd)
{
	if (!bev_ssl->underlying) {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		if (event_initialized(&bev->ev_read) && fd < 0) {
			fd = event_get_fd(&bev->ev_read);
		}
	}
	return fd;
}

static int
set_open_callbacks(struct bufferevent_ssl *bev_ssl, evutil_socket_t fd)
{
	if (bev_ssl->underlying) {
		bufferevent_setcb(bev_ssl->underlying,
		    be_ssl_readcb, be_ssl_writecb, be_ssl_eventcb,
		    bev_ssl);
		return 0;
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;
		int rpending=0, wpending=0, r1=0, r2=0;

		if (event_initialized(&bev->ev_read)) {
			rpending = event_pending(&bev->ev_read, EV_READ, NULL);
			wpending = event_pending(&bev->ev_write, EV_WRITE, NULL);

			event_del(&bev->ev_read);
			event_del(&bev->ev_write);
		}

		event_assign(&bev->ev_read, bev->ev_base, fd,
		    EV_READ|EV_PERSIST|EV_FINALIZE,
		    be_ssl_readeventcb, bev_ssl);
		event_assign(&bev->ev_write, bev->ev_base, fd,
		    EV_WRITE|EV_PERSIST|EV_FINALIZE,
		    be_ssl_writeeventcb, bev_ssl);

		if (rpending)
			r1 = bufferevent_add_event_(&bev->ev_read, &bev->timeout_read);
		if (wpending)
			r2 = bufferevent_add_event_(&bev->ev_write, &bev->timeout_write);

		return (r1<0 || r2<0) ? -1 : 0;
	}
}

static int
do_handshake(struct bufferevent_ssl *bev_ssl)
{
	int r;

	switch (bev_ssl->state) {
	default:
	case BUFFEREVENT_SSL_OPEN:
		EVUTIL_ASSERT(0);
		return -1;
	case BUFFEREVENT_SSL_CONNECTING:
	case BUFFEREVENT_SSL_ACCEPTING:
		bev_ssl->ssl_ops->clear_error();
		r = bev_ssl->ssl_ops->handshake(bev_ssl->ssl);
		break;
	}
	bev_ssl->ssl_ops->decrement_buckets(bev_ssl);

	if (bev_ssl->ssl_ops->handshake_is_ok(r)) {
		evutil_socket_t fd = event_get_fd(&bev_ssl->bev.bev.ev_read);
		/* We're done! */
		bev_ssl->state = BUFFEREVENT_SSL_OPEN;
		set_open_callbacks(bev_ssl, fd); /* XXXX handle failure */
		/* Call do_read and do_write as needed */
		bufferevent_enable(&bev_ssl->bev.bev, bev_ssl->bev.bev.enabled);
		bufferevent_run_eventcb_(&bev_ssl->bev.bev,
		    BEV_EVENT_CONNECTED, 0);
		return 1;
	} else {
		int err = bev_ssl->ssl_ops->get_error(bev_ssl->ssl, r);
		bev_ssl->ssl_ops->print_err(err);
		if (bev_ssl->ssl_ops->err_is_want_write(err)) {
			bufferevent_ssl_stop_reading(bev_ssl);
			return start_writing(bev_ssl);
		} else if (bev_ssl->ssl_ops->err_is_want_read(err)) {
			bufferevent_ssl_stop_writing(bev_ssl);
			return start_reading(bev_ssl);
		} else {
			bev_ssl->ssl_ops->conn_closed(bev_ssl, BEV_EVENT_READING, err, r);
			return -1;
		}
	}
}

static void
be_ssl_handshakecb(struct bufferevent *bev_base, void *ctx)
{
	struct bufferevent_ssl *bev_ssl = ctx;
	do_handshake(bev_ssl);/* XXX handle failure */
}

static void
be_ssl_handshakeeventcb(evutil_socket_t fd, short what, void *ptr)
{
	struct bufferevent_ssl *bev_ssl = ptr;

	bufferevent_incref_and_lock_(&bev_ssl->bev.bev);
	if (what & EV_TIMEOUT) {
		bufferevent_run_eventcb_(&bev_ssl->bev.bev, BEV_EVENT_TIMEOUT, 0);
	} else {
		int c = evutil_socket_finished_connecting_(fd);
		if (c < 0)
			bufferevent_run_eventcb_(&bev_ssl->bev.bev, BEV_EVENT_ERROR, 0);
		else
			do_handshake(bev_ssl);/* XXX handle failure */
	}
	bufferevent_decref_and_unlock_(&bev_ssl->bev.bev);
}

static int
set_handshake_callbacks(struct bufferevent_ssl *bev_ssl, evutil_socket_t fd)
{
	if (bev_ssl->underlying) {
		bufferevent_setcb(bev_ssl->underlying,
		    be_ssl_handshakecb, be_ssl_handshakecb,
		    be_ssl_eventcb,
		    bev_ssl);

		if (fd < 0)
			return 0;

		if (bufferevent_setfd(bev_ssl->underlying, fd))
			return 1;

		return do_handshake(bev_ssl);
	} else {
		struct bufferevent *bev = &bev_ssl->bev.bev;

		if (event_initialized(&bev->ev_read)) {
			event_del(&bev->ev_read);
			event_del(&bev->ev_write);
		}

		event_assign(&bev->ev_read, bev->ev_base, fd,
		    EV_READ|EV_PERSIST|EV_FINALIZE,
		    be_ssl_handshakeeventcb, bev_ssl);
		event_assign(&bev->ev_write, bev->ev_base, fd,
		    EV_WRITE|EV_PERSIST|EV_FINALIZE,
		    be_ssl_handshakeeventcb, bev_ssl);
		if (fd >= 0)
			bufferevent_enable(bev, bev->enabled);
		return 0;
	}
}

int
bufferevent_ssl_renegotiate_impl(struct bufferevent *bev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);
	if (!bev_ssl)
		return -1;
	if (bev_ssl->ssl_ops->renegotiate(bev_ssl->ssl) < 0)
		return -1;
	bev_ssl->state = BUFFEREVENT_SSL_CONNECTING;
	if (set_handshake_callbacks(bev_ssl, be_ssl_auto_fd(bev_ssl, -1)) < 0)
		return -1;
	if (!bev_ssl->underlying)
		return do_handshake(bev_ssl);
	return 0;
}

static void
be_ssl_outbuf_cb(struct evbuffer *buf,
    const struct evbuffer_cb_info *cbinfo, void *arg)
{
	struct bufferevent_ssl *bev_ssl = arg;
	int r = 0;
	/* XXX need to hold a reference here. */

	if (cbinfo->n_added && bev_ssl->state == BUFFEREVENT_SSL_OPEN) {
		if (cbinfo->orig_size == 0)
			r = bufferevent_add_event_(&bev_ssl->bev.bev.ev_write,
			    &bev_ssl->bev.bev.timeout_write);

		if (bev_ssl->underlying)
			consider_writing(bev_ssl);
	}
	/* XXX Handle r < 0 */
	(void)r;
}


static int
be_ssl_enable(struct bufferevent *bev, short events)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);
	int r1 = 0, r2 = 0;

	if (events & EV_READ)
		r1 = start_reading(bev_ssl);
	if (events & EV_WRITE)
		r2 = start_writing(bev_ssl);

	if (bev_ssl->underlying) {
		if (events & EV_READ)
			BEV_RESET_GENERIC_READ_TIMEOUT(bev);
		if (events & EV_WRITE)
			BEV_RESET_GENERIC_WRITE_TIMEOUT(bev);

		if (events & EV_READ)
			consider_reading(bev_ssl);
		if (events & EV_WRITE)
			consider_writing(bev_ssl);
	}
	return (r1 < 0 || r2 < 0) ? -1 : 0;
}

static int
be_ssl_disable(struct bufferevent *bev, short events)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);

	if (events & EV_READ)
		bufferevent_ssl_stop_reading(bev_ssl);
	if (events & EV_WRITE)
		bufferevent_ssl_stop_writing(bev_ssl);

	if (bev_ssl->underlying) {
		if (events & EV_READ)
			BEV_DEL_GENERIC_READ_TIMEOUT(bev);
		if (events & EV_WRITE)
			BEV_DEL_GENERIC_WRITE_TIMEOUT(bev);
	}
	return 0;
}

static void
be_ssl_unlink(struct bufferevent *bev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);

	if (bev_ssl->bev.options & BEV_OPT_CLOSE_ON_FREE) {
		if (bev_ssl->underlying) {
			if (BEV_UPCAST(bev_ssl->underlying)->refcnt < 2) {
				event_warnx("BEV_OPT_CLOSE_ON_FREE set on an "
				    "bufferevent with too few references");
			} else {
				bufferevent_free(bev_ssl->underlying);
				/* We still have a reference to it, via our
				 * BIO. So we don't drop this. */
				// bev_ssl->underlying = NULL;
			}
		}
	} else {
		if (bev_ssl->underlying) {
			if (bev_ssl->underlying->errorcb == be_ssl_eventcb)
				bufferevent_setcb(bev_ssl->underlying,
				    NULL,NULL,NULL,NULL);
			bufferevent_unsuspend_read_(bev_ssl->underlying,
			    BEV_SUSPEND_FILT_READ);
		}
	}
}

static void
be_ssl_destruct(struct bufferevent *bev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);

	if (bev_ssl->bev.options & BEV_OPT_CLOSE_ON_FREE) {
		if (! bev_ssl->underlying) {
			evutil_socket_t fd = bev_ssl->ssl_ops->get_fd(bev_ssl);
			/* NOTE: This is dirty shutdown, to send close_notify one of the
			 * following should be used:
			 * - SSL_shutdown()
			 * - mbedtls_ssl_close_notify() */
			if (fd >= 0)
				evutil_closesocket(fd);
		}
	}
	bev_ssl->ssl_ops->free(bev_ssl->ssl, bev_ssl->bev.options);
}

static int
be_ssl_adj_timeouts(struct bufferevent *bev)
{
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);

	if (bev_ssl->underlying) {
		return bufferevent_generic_adj_timeouts_(bev);
	} else {
		return bufferevent_generic_adj_existing_timeouts_(bev);
	}
}

static int
be_ssl_flush(struct bufferevent *bufev,
    short iotype, enum bufferevent_flush_mode mode)
{
	/* XXXX Implement this. */
	return 0;
}

static int
be_ssl_set_fd(struct bufferevent_ssl *bev_ssl,
    enum bufferevent_ssl_state state, evutil_socket_t fd)
{
	bev_ssl->state = state;

	switch (state) {
	case BUFFEREVENT_SSL_ACCEPTING:
		if (!bev_ssl->ssl_ops->clear(bev_ssl->ssl))
			return -1;
		bev_ssl->ssl_ops->set_accept_state(bev_ssl->ssl);
		if (set_handshake_callbacks(bev_ssl, fd) < 0)
			return -1;
		break;
	case BUFFEREVENT_SSL_CONNECTING:
		if (!bev_ssl->ssl_ops->clear(bev_ssl->ssl))
			return -1;
		bev_ssl->ssl_ops->set_connect_state(bev_ssl->ssl);
		if (set_handshake_callbacks(bev_ssl, fd) < 0)
			return -1;
		break;
	case BUFFEREVENT_SSL_OPEN:
		if (set_open_callbacks(bev_ssl, fd) < 0)
			return -1;
		break;
	default:
		return -1;
	}

	return 0;
}

static int
be_ssl_ctrl(struct bufferevent *bev,
    enum bufferevent_ctrl_op op, union bufferevent_ctrl_data *data)
{
	int ret = 0;
	struct bufferevent_ssl *bev_ssl = bufferevent_ssl_upcast(bev);
	switch (op) {
	case BEV_CTRL_SET_FD:
		if ((ret = bev_ssl->ssl_ops->bio_set_fd(bev_ssl, data->fd)) != 0)
			return ret;
		return be_ssl_set_fd(bev_ssl, bev_ssl->old_state, data->fd);
	case BEV_CTRL_GET_FD:
		if (bev_ssl->underlying) {
			data->fd = event_get_fd(&bev_ssl->underlying->ev_read);
		} else {
			data->fd = event_get_fd(&bev->ev_read);
		}
		return 0;
	case BEV_CTRL_GET_UNDERLYING:
		data->ptr = bev_ssl->underlying;
		return 0;
	case BEV_CTRL_CANCEL_ALL:
	default:
		return -1;
	}
}

struct bufferevent *
bufferevent_ssl_new_impl(struct event_base *base,
    struct bufferevent *underlying,
    evutil_socket_t fd,
    void *ssl,
    enum bufferevent_ssl_state state,
    int options,
	struct le_ssl_ops *ssl_ops)
{
	struct bufferevent_ssl *bev_ssl = NULL;
	struct bufferevent_private *bev_p = NULL;
	int tmp_options = options & ~BEV_OPT_THREADSAFE;

	/* Only one can be set. */
	if (underlying != NULL && fd >= 0)
		goto err;

	if (!(bev_ssl = mm_calloc(1, sizeof(struct bufferevent_ssl))))
		goto err;

	bev_p = &bev_ssl->bev;

	if (bufferevent_init_common_(bev_p, base,
		&bufferevent_ops_ssl, tmp_options) < 0)
		goto err;

	bev_ssl->ssl_ops = ssl_ops;

	bev_ssl->ssl = bev_ssl->ssl_ops->init(ssl);

	bev_ssl->underlying = underlying;

	bev_ssl->outbuf_cb = evbuffer_add_cb(bev_p->bev.output,
	    be_ssl_outbuf_cb, bev_ssl);

	if (options & BEV_OPT_THREADSAFE)
		bufferevent_enable_locking_(&bev_ssl->bev.bev, NULL);

	if (underlying) {
		bufferevent_init_generic_timeout_cbs_(&bev_ssl->bev.bev);
		bufferevent_incref_(underlying);
	}

	bev_ssl->old_state = state;
	bev_ssl->last_write = -1;

	bev_ssl->ssl_ops->init_bio_counts(bev_ssl);

	fd = be_ssl_auto_fd(bev_ssl, fd);
	if (be_ssl_set_fd(bev_ssl, state, fd))
		goto err;

	if (underlying) {
		bufferevent_setwatermark(underlying, EV_READ, 0, 0);
		bufferevent_enable(underlying, EV_READ|EV_WRITE);
		if (state == BUFFEREVENT_SSL_OPEN)
			bufferevent_suspend_read_(underlying,
			    BEV_SUSPEND_FILT_READ);
	}

	return &bev_ssl->bev.bev;
err:
	if (bev_ssl) {
		if (bev_ssl->ssl && (options & BEV_OPT_CLOSE_ON_FREE))
			bev_ssl->ssl_ops->free(bev_ssl->ssl, options);
		bev_ssl->ssl = NULL;
		bufferevent_free(&bev_ssl->bev.bev);
	} else {
		if (ssl && (options & BEV_OPT_CLOSE_ON_FREE))
			bev_ssl->ssl_ops->free_raw(bev_ssl->ssl);
	}
	return NULL;
}

unsigned long
bufferevent_get_ssl_error(struct bufferevent *bev)
{
	unsigned long err = 0;
	struct bufferevent_ssl *bev_ssl;
	BEV_LOCK(bev);
	bev_ssl = bufferevent_ssl_upcast(bev);
	if (bev_ssl && bev_ssl->n_errors) {
		err = bev_ssl->errors[--bev_ssl->n_errors];
	}
	BEV_UNLOCK(bev);
	return err;
}

ev_uint64_t bufferevent_ssl_get_flags(struct bufferevent *bev)
{
	ev_uint64_t flags = EV_UINT64_MAX;
	struct bufferevent_ssl *bev_ssl;

	BEV_LOCK(bev);
	bev_ssl = bufferevent_ssl_upcast(bev);
	if (bev_ssl)
		flags = bev_ssl->flags;
	BEV_UNLOCK(bev);

	return flags;
}
ev_uint64_t bufferevent_ssl_set_flags(struct bufferevent *bev, ev_uint64_t flags)
{
	ev_uint64_t old_flags = EV_UINT64_MAX;
	struct bufferevent_ssl *bev_ssl;

	flags &= (BUFFEREVENT_SSL_DIRTY_SHUTDOWN|BUFFEREVENT_SSL_BATCH_WRITE);
	if (!flags)
		return old_flags;

	BEV_LOCK(bev);
	bev_ssl = bufferevent_ssl_upcast(bev);
	if (bev_ssl) {
		old_flags = bev_ssl->flags;
		bev_ssl->flags |= flags;
	}
	BEV_UNLOCK(bev);

	return old_flags;
}
ev_uint64_t bufferevent_ssl_clear_flags(struct bufferevent *bev, ev_uint64_t flags)
{
	ev_uint64_t old_flags = EV_UINT64_MAX;
	struct bufferevent_ssl *bev_ssl;

	flags &= (BUFFEREVENT_SSL_DIRTY_SHUTDOWN|BUFFEREVENT_SSL_BATCH_WRITE);
	if (!flags)
		return old_flags;

	BEV_LOCK(bev);
	bev_ssl = bufferevent_ssl_upcast(bev);
	if (bev_ssl) {
		old_flags = bev_ssl->flags;
		bev_ssl->flags &= ~flags;
	}
	BEV_UNLOCK(bev);

	return old_flags;
}

int
bufferevent_ssl_get_allow_dirty_shutdown(struct bufferevent *bev)
{
	ev_uint64_t flags = bufferevent_ssl_get_flags(bev);
	if (flags == EV_UINT64_MAX)
		return flags;
	return !!(flags & BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
}

void
bufferevent_ssl_set_allow_dirty_shutdown(
	struct bufferevent *bev, int allow_dirty_shutdown)
{
	BEV_LOCK(bev);

	if (allow_dirty_shutdown)
		bufferevent_ssl_set_flags(bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);
	else
		bufferevent_ssl_clear_flags(bev, BUFFEREVENT_SSL_DIRTY_SHUTDOWN);

	BEV_UNLOCK(bev);
}
