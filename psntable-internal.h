/*
 * Copyright (c) 2000-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2012 Niels Provos and Nick Mathewson
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
#ifndef PSNTABLE_INTERNAL_H_INCLUDED_
#define PSNTABLE_INTERNAL_H_INCLUDED_
#include <winsock2.h>
/*
  Produced by make_psn_table.py.
*/

#define PSN_OP_TABLE_INDEX(c) \
	(   (((c)->close_change&(EV_CHANGE_ADD|EV_CHANGE_DEL))) |		\
	    (((c)->read_change&(EV_CHANGE_ADD|EV_CHANGE_DEL)) << 2) |	\
	    (((c)->write_change&(EV_CHANGE_ADD|EV_CHANGE_DEL)) << 4) |	\
	    (((c)->old_events&(EV_READ|EV_WRITE)) << 5) |		\
	    (((c)->old_events&(EV_CLOSED)) << 1)				\
	    )

#if EV_READ != 2 || EV_WRITE != 4 || EV_CLOSED != 0x80 || EV_CHANGE_ADD != 1 || EV_CHANGE_DEL != 2
#error "Libevent's internals changed!  Regenerate the op_table in psntable-internal.h"
#endif

static const struct operation {
	int events;
	int op;
} psn_op_table[] = {
	/* old=  0, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old=  0, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  0, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old=  0, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old=  0, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  0, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old=  0, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old=  0, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  0, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  0, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old=  0, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old=  0, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  0, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old=  0, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old=  0, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  0, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  0, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old=  0, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  0, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  0, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old=  0, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  0, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old=  0, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old=  0, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  0, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old=  0, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old=  0, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old=  0, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  0, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old=  0, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old=  0, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old=  0, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old=  0, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old=  0, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old=  0, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old=  0, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old=  0, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  0, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old=  0, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old=  0, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  r, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old=  r, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  r, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old=  r, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_REMOVE },
	/* old=  r, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  r, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old=  r, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  r, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old=  r, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old=  r, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  r, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  r, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old=  r, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old=  r, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  r, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old=  r, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old=  r, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  r, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  r, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old=  r, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old=  r, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  r, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  r, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old=  r, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  r, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old=  r, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old=  r, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  r, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old=  r, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old=  r, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old=  r, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  r, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old=  r, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old=  r, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old=  r, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old=  r, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old=  r, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old=  r, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old=  r, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old=  r, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  r, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old=  r, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old=  r, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  w, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old=  w, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  w, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old=  w, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old=  w, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  w, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old=  w, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old=  w, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  w, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  w, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old=  w, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old=  w, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  w, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old=  w, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old=  w, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  w, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old=  w, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  w, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  w, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old=  w, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old=  w, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  w, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  w, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old=  w, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  w, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old=  w, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old=  w, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  w, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old=  w, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old=  w, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old=  w, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  w, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old=  w, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old=  w, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old=  w, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old=  w, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old=  w, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old=  w, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old=  w, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old=  w, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  w, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old=  w, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old=  w, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= rw, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old= rw, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old= rw, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old= rw, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old= rw, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= rw, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old= rw, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old= rw, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= rw, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old= rw, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old= rw, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old= rw, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= rw, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old= rw, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old= rw, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= rw, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old= rw, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old= rw, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_REMOVE },
	/* old= rw, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= rw, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old= rw, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old= rw, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= rw, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old= rw, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old= rw, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= rw, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old= rw, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old= rw, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old= rw, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old= rw, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old= rw, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old= rw, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old= rw, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old= rw, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old= rw, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old= rw, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old= rw, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old= rw, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= rw, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old= rw, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old= rw, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  c, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old=  c, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  c, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  c, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old=  c, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  c, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old=  c, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  c, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old=  c, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old=  c, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  c, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  c, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old=  c, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old=  c, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  c, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old=  c, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old=  c, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  c, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  c, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  c, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old=  c, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=  c, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=  c, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old=  c, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  c, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old=  c, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old=  c, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=  c, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old=  c, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old=  c, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old=  c, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old=  c, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old=  c, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old=  c, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old=  c, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old=  c, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old=  c, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old=  c, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old=  c, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old=  c, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=  c, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old=  c, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old=  c, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cr, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old= cr, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cr, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old= cr, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old= cr, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old= cr, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cr, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old= cr, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old= cr, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cr, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cr, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old= cr, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old= cr, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cr, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old= cr, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old= cr, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cr, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cr, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old= cr, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cr, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old= cr, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old= cr, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cr, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old= cr, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old= cr, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cr, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old= cr, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old= cr, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old= cr, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cr, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old= cr, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old= cr, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old= cr, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old= cr, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old= cr, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old= cr, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old= cr, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old= cr, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cr, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old= cr, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old= cr, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cw, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old= cw, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cw, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old= cw, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old= cw, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cw, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old= cw, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old= cw, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cw, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cw, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old= cw, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old= cw, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cw, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old= cw, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old= cw, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cw, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old= cw, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cw, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old= cw, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old= cw, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old= cw, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old= cw, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cw, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old= cw, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old= cw, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old= cw, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old= cw, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old= cw, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old= cw, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old= cw, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old= cw, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old= cw, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old= cw, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old= cw, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old= cw, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old= cw, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old= cw, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old= cw, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old= cw, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old= cw, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old= cw, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=crw, write:  0, read:  0, close:  0 */
	{ 0, 0 },
	/* old=crw, write:  0, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:  0, close:xxx */
	{ 0, 255 },
	/* old=crw, write:  0, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:add, close:xxx */
	{ 0, 255 },
	/* old=crw, write:  0, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:  0, read:del, close:xxx */
	{ 0, 255 },
	/* old=crw, write:  0, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=crw, write:  0, read:xxx, close:add */
	{ 0, 255 },
	/* old=crw, write:  0, read:xxx, close:del */
	{ 0, 255 },
	/* old=crw, write:  0, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=crw, write:add, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:  0, close:xxx */
	{ 0, 255 },
	/* old=crw, write:add, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:add, close:xxx */
	{ 0, 255 },
	/* old=crw, write:add, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_OUT, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:add, read:del, close:xxx */
	{ 0, 255 },
	/* old=crw, write:add, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=crw, write:add, read:xxx, close:add */
	{ 0, 255 },
	/* old=crw, write:add, read:xxx, close:del */
	{ 0, 255 },
	/* old=crw, write:add, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=crw, write:del, read:  0, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:  0, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:  0, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:  0, close:xxx */
	{ 0, 255 },
	/* old=crw, write:del, read:add, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:add, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:add, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:add, close:xxx */
	{ 0, 255 },
	/* old=crw, write:del, read:del, close:  0 */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:del, close:add */
	{ SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_ENABLE },
	/* old=crw, write:del, read:del, close:del */
	{ SOCK_NOTIFY_REGISTER_EVENT_IN|SOCK_NOTIFY_REGISTER_EVENT_OUT|SOCK_NOTIFY_REGISTER_EVENT_HANGUP, SOCK_NOTIFY_OP_REMOVE },
	/* old=crw, write:del, read:del, close:xxx */
	{ 0, 255 },
	/* old=crw, write:del, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=crw, write:del, read:xxx, close:add */
	{ 0, 255 },
	/* old=crw, write:del, read:xxx, close:del */
	{ 0, 255 },
	/* old=crw, write:del, read:xxx, close:xxx */
	{ 0, 255 },
	/* old=crw, write:xxx, read:  0, close:  0 */
	{ 0, 255 },
	/* old=crw, write:xxx, read:  0, close:add */
	{ 0, 255 },
	/* old=crw, write:xxx, read:  0, close:del */
	{ 0, 255 },
	/* old=crw, write:xxx, read:  0, close:xxx */
	{ 0, 255 },
	/* old=crw, write:xxx, read:add, close:  0 */
	{ 0, 255 },
	/* old=crw, write:xxx, read:add, close:add */
	{ 0, 255 },
	/* old=crw, write:xxx, read:add, close:del */
	{ 0, 255 },
	/* old=crw, write:xxx, read:add, close:xxx */
	{ 0, 255 },
	/* old=crw, write:xxx, read:del, close:  0 */
	{ 0, 255 },
	/* old=crw, write:xxx, read:del, close:add */
	{ 0, 255 },
	/* old=crw, write:xxx, read:del, close:del */
	{ 0, 255 },
	/* old=crw, write:xxx, read:del, close:xxx */
	{ 0, 255 },
	/* old=crw, write:xxx, read:xxx, close:  0 */
	{ 0, 255 },
	/* old=crw, write:xxx, read:xxx, close:add */
	{ 0, 255 },
	/* old=crw, write:xxx, read:xxx, close:del */
	{ 0, 255 },
	/* old=crw, write:xxx, read:xxx, close:xxx */
	{ 0, 255 },

};

#endif
