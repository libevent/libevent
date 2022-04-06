/*	$OpenBSD: kqueue.c,v 1.5 2002/07/10 14:41:31 art Exp $	*/

/*
 * Copyright 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright 2007-2012 Niels Provos and Nick Mathewson
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
#include "event2/event-config.h"
#include "evconfig-private.h"
#ifdef EVENT__HAVE_PSN

#include <winsock2.h>
#include <windows.h>

#include "event-internal.h"
#include "log-internal.h"
#include "evmap-internal.h"
// #include "event2/thread.h"
// #include "event2/util.h"
#include "evthread-internal.h"
#include "changelist-internal.h"

#include "psntable-internal.h"

#define NEVENT		64

struct psnop {
	HANDLE cp;
	SOCK_NOTIFY_REGISTRATION* regs;
	int regs_size;
	OVERLAPPED_ENTRY* overs;
	int overs_size;
};


static void *psn_init(struct event_base *);
static int psn_dispatch(struct event_base *, struct timeval *);
static void psn_dealloc(struct event_base *);

const struct eventop psnops = {
	"psn",
	psn_init,
	event_changelist_add_,
	event_changelist_del_,
	psn_dispatch,
	psn_dealloc,
	1 /* need reinit */,
    EV_FEATURE_ET | EV_FEATURE_O1,
	EVENT_CHANGELIST_FDINFO_SIZE
};

static const char *
change_to_string(int change)
{
	change &= (EV_CHANGE_ADD|EV_CHANGE_DEL);
	if (change == EV_CHANGE_ADD) {
		return "add";
	} else if (change == EV_CHANGE_DEL) {
		return "del";
	} else if (change == 0) {
		return "none";
	} else {
		return "???";
	}
}

static const char *
psn_op_to_string(int op)
{
	return op == SOCK_NOTIFY_OP_ENABLE?"ENABLE":
	    op == SOCK_NOTIFY_OP_REMOVE?"REMOVE":
	    "???";
}

#define PRINT_CHANGES(op, events, ch, status)  \
	"PSN %s(%d) on fd %d " status ". "         \
	"Old events were %d; "                     \
	"read change was %d (%s); "                \
	"write change was %d (%s); "               \
	"close change was %d (%s)",                \
	psn_op_to_string(op),                      \
	events,                                    \
	ch->fd,                                    \
	ch->old_events,                            \
	ch->read_change,                           \
	change_to_string(ch->read_change),         \
	ch->write_change,                          \
	change_to_string(ch->write_change),        \
	ch->close_change,                          \
	change_to_string(ch->close_change)

static void *
psn_init(struct event_base *base)
{
	struct psnop *op = NULL;
	HANDLE cp = NULL;

	event_debug(("%s: entry", __func__));

	if (!(op = mm_calloc(1, sizeof(struct psnop)))) {
		event_debug(("%s: mm_calloc failed", __func__));
		goto err;
	}

	memset(op, 0, sizeof(struct psnop));

	if ((op->cp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0)) == NULL) {
		event_debug(("%s: CreateIoCompletionPort failed", __func__));
		goto err;
	}

	if (!(op->regs = mm_calloc(NEVENT, sizeof(SOCK_NOTIFY_REGISTRATION)))) {
		event_debug(("%s: mm_calloc failed", __func__));
		goto err;
	}
	if (!(op->overs = mm_calloc(NEVENT, sizeof(OVERLAPPED_ENTRY)))) {
		event_debug(("%s: mm_calloc failed", __func__));
		goto err;
	}
	op->overs_size = op->regs_size = NEVENT;

	if (evsig_init_(base) < 0) {
		event_debug(("%s: evsig_init_ failed", __func__));
		goto err;
	}

	return (op);

err:
	if (op != NULL) {
		if (op->cp != NULL)
			CloseHandle(op->cp);
		if (op->regs != NULL)
			mm_free(op->regs);
		if (op->overs != NULL)
			mm_free(op->overs);

		mm_free(op);
	}
	return (NULL);
}

static int
psn_apply_one_change(struct event_base *base,
    struct psnop *op,
    const struct event_change *ch)
{
	SOCK_NOTIFY_REGISTRATION reg;
	int operation, events = 0;
	int idx, res;

	idx = PSN_OP_TABLE_INDEX(ch);
	operation = psn_op_table[idx].op;
	events = psn_op_table[idx].events;

	if (!events) {
		EVUTIL_ASSERT(operation == 0);
		return 0;
	}

	if (events & SOCK_NOTIFY_REGISTER_EVENT_IN || events & SOCK_NOTIFY_REGISTER_EVENT_OUT) {
		events |= SOCK_NOTIFY_REGISTER_EVENT_HANGUP;
	}

	memset(&reg, 0, sizeof(reg));
	reg.socket = ch->fd;
	reg.completionKey = (PVOID)ch->fd;
	reg.eventFilter = events;
	reg.operation = operation;
	reg.triggerFlags = SOCK_NOTIFY_TRIGGER_PERSISTENT | SOCK_NOTIFY_TRIGGER_LEVEL;

	if ((res = ProcessSocketNotifications(op->cp, 1, &reg, 0, 0, NULL, NULL)) == 0) {
		event_debug((PRINT_CHANGES(operation, events, ch, "okay")));
		return 0;
	}

	event_debug((PRINT_CHANGES(operation, events, ch, "failed")));
	event_debug(("ProcessSocketNotifications res=%d, registrationResult=%d", res, reg.registrationResult));
	return -1;
}

static int
psn_apply_changes(struct event_base *base)
{
	struct event_changelist *changelist = &base->changelist;
	struct psnop *op = base->evbase;
	struct event_change *ch;

	int r = 0;
	int i;

	for (i = 0; i < changelist->n_changes; ++i) {
		ch = &changelist->changes[i];
		if (psn_apply_one_change(base, op, ch) < 0)
			r = -1;
	}

	return (r);
}

static int
psn_grow_overs(struct psnop *op, int new_size)
{
	OVERLAPPED_ENTRY *newresult;

	event_debug(("%s: entry", __func__));

	newresult = mm_realloc(op->overs,
	    new_size * sizeof(OVERLAPPED_ENTRY));

	if (newresult) {
		op->overs = newresult;
		op->overs_size = new_size;
		return 0;
	} else {
		return -1;
	}
}

static int
psn_dispatch(struct event_base *base, struct timeval *tv)
{
	struct psnop *op = base->evbase;
	OVERLAPPED_ENTRY *overs = op->overs;
	int timeout = 0;
	int i, res, n_returned = 0;

	event_debug(("%s: entry", __func__));

	if (tv != NULL) {
		timeout = tv->tv_sec * 1000 + tv->tv_usec / 1000;
	}

	/* Register all changes first */
	psn_apply_changes(base);

	event_debug(("%s: calling event_changelist_remove_all_", __func__));
	event_changelist_remove_all_(&base->changelist, base);

	EVBASE_RELEASE_LOCK(base, th_base_lock);

	event_debug(("%s: calling ProcessSocketNotifications completionPort=%d, registrationCount=%d, timeoutMs=%d, completionCount=%d",
		__func__, op->cp, 0, timeout, op->overs_size));

	res = ProcessSocketNotifications(op->cp, 0, NULL, timeout, op->overs_size, overs, &n_returned);

	EVBASE_ACQUIRE_LOCK(base, th_base_lock);

	event_debug(("%s: ProcessSocketNotifications reports res=%d, n_returned=%d", __func__, res, n_returned));

	if (res != NO_ERROR && res != WAIT_TIMEOUT) {
		event_warn("ProcessSocketNotifications");
		return (-1);
	}

	for (i = 0; i < n_returned; i++) {
		int events;
		int which = 0;

		events = SocketNotificationRetrieveEvents(&overs[i]);

		if (events & SOCK_NOTIFY_EVENT_ERR) {
			event_debug(("%s: ProcessSocketNotifications ERR on sock %d", __func__, overs[i].lpCompletionKey));
		}
		if (events & SOCK_NOTIFY_EVENT_HANGUP) {
			event_debug(("%s: ProcessSocketNotifications HANGUP on sock %d", __func__, overs[i].lpCompletionKey));
			which |= EV_READ;
			which |= EV_WRITE;
		}
		if (events & SOCK_NOTIFY_EVENT_IN) {
			event_debug(("%s: ProcessSocketNotifications IN on sock %d", __func__, overs[i].lpCompletionKey));
			which |= EV_READ;
		}
		if (events & SOCK_NOTIFY_EVENT_OUT) {
			event_debug(("%s: ProcessSocketNotifications OUT on sock %d", __func__, overs[i].lpCompletionKey));
			which |= EV_WRITE;
		}
		if (events & SOCK_NOTIFY_EVENT_REMOVE) {
			event_debug(("%s: ProcessSocketNotifications REMOVE on sock %d", __func__, overs[i].lpCompletionKey));
		}

		if (which) {
			evmap_io_active_(base, overs[i].lpCompletionKey, which);
		}
	}

	if (n_returned == op->overs_size) {
		/* We used all the events space that we have. Maybe we should
		   make it bigger. */
		psn_grow_overs(op, op->overs_size * 2);
	}

	return (0);
}

static void
psn_dealloc(struct event_base *base)
{
	struct psnop *op = base->evbase;

	event_debug(("%s: entry", __func__));

	EVUTIL_ASSERT(op != NULL);
	EVUTIL_ASSERT(op->cp != NULL);

	CloseHandle(op->cp);
	mm_free(op);
}

#endif /* EVENT__HAVE_PSN */
