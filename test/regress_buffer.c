/*
 * Copyright (c) 2003-2007 Niels Provos <provos@citi.umich.edu>
 * Copyright (c) 2007-2009 Niels Provos and Nick Mathewson
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

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef HAVE_CONFIG_H
#include "event-config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef _EVENT_HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/queue.h>
#ifndef WIN32
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "event2/event.h"
#include "event2/buffer.h"
#include "event2/buffer_compat.h"
#include "event2/util.h"

#include "evbuffer-internal.h"
#include "log-internal.h"

#include "regress.h"

/* Validates that an evbuffer is good. Returns false if it isn't, true if it
 * is*/
static int
_evbuffer_validate(struct evbuffer *buf)
{
	struct evbuffer_chain *chain, *previous = NULL;
	size_t sum = 0;

	if (buf->first == NULL) {
		tt_assert(buf->last == NULL);
		tt_assert(buf->previous_to_last == NULL);
		tt_assert(buf->total_len == 0);
	}

	if (buf->previous_to_last == NULL) {
		tt_assert(buf->first == buf->last);
	}

	chain = buf->first;
	while (chain != NULL) {
		sum += chain->off;
		if (chain->next == NULL) {
			tt_assert(buf->previous_to_last == previous);
			tt_assert(buf->last == chain);
		}
		tt_assert(chain->buffer_len >= chain->misalign + chain->off);
		previous = chain;
		chain = chain->next;
	}

	tt_assert(sum == buf->total_len);
	return 1;
 end:
	return 0;
}

#define evbuffer_validate(buf)			\
	TT_STMT_BEGIN if (!_evbuffer_validate(buf)) goto end; TT_STMT_END

static void
test_evbuffer(void *ptr)
{
	static char buffer[512], *tmp;
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_two = evbuffer_new();
	size_t sz_tmp;
	int i;

	evbuffer_validate(evb);
	evbuffer_add_printf(evb, "%s/%d", "hello", 1);
	evbuffer_validate(evb);

	tt_assert(EVBUFFER_LENGTH(evb) == 7);
	tt_assert(!memcmp((char*)EVBUFFER_DATA(evb), "hello/1", 1));

	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	evbuffer_drain(evb, strlen("hello/"));
	evbuffer_validate(evb);
	tt_assert(EVBUFFER_LENGTH(evb) == 1);
	tt_assert(!memcmp((char*)EVBUFFER_DATA(evb), "1", 1));

	evbuffer_add_printf(evb_two, "%s", "/hello");
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	tt_assert(EVBUFFER_LENGTH(evb_two) == 0);
	tt_assert(EVBUFFER_LENGTH(evb) == 7);
	tt_assert(!memcmp((char*)EVBUFFER_DATA(evb), "1/hello", 7) != 0);

	memset(buffer, 0, sizeof(buffer));
	evbuffer_add(evb, buffer, sizeof(buffer));
	evbuffer_validate(evb);
	tt_assert(EVBUFFER_LENGTH(evb) == 7 + 512);

	tmp = (char *)evbuffer_pullup(evb, 7 + 512);
	tt_assert(tmp);
	tt_assert(!strncmp(tmp, "1/hello", 7));
	tt_assert(!memcmp(tmp + 7, buffer, sizeof(buffer)));
	evbuffer_validate(evb);

	evbuffer_prepend(evb, "something", 9);
	evbuffer_validate(evb);
	evbuffer_prepend(evb, "else", 4);
	evbuffer_validate(evb);

	tmp = (char *)evbuffer_pullup(evb, 4 + 9 + 7);
	tt_assert(!strncmp(tmp, "elsesomething1/hello", 4 + 9 + 7));
	evbuffer_validate(evb);

	evbuffer_drain(evb, -1);
	evbuffer_validate(evb);
	evbuffer_drain(evb_two, -1);
	evbuffer_validate(evb);

	for (i = 0; i < 3; ++i) {
		evbuffer_add(evb_two, buffer, sizeof(buffer));
		evbuffer_validate(evb_two);
		evbuffer_add_buffer(evb, evb_two);
		evbuffer_validate(evb);
		evbuffer_validate(evb_two);
	}

	tt_assert(EVBUFFER_LENGTH(evb_two) == 0);
	tt_assert(EVBUFFER_LENGTH(evb) == i * sizeof(buffer));

	/* test remove buffer */
	sz_tmp = sizeof(buffer)*2.5;
	evbuffer_remove_buffer(evb, evb_two, sz_tmp);
	tt_assert(EVBUFFER_LENGTH(evb_two) == sz_tmp);
	tt_assert(EVBUFFER_LENGTH(evb) == sizeof(buffer) / 2);
	evbuffer_validate(evb);

	if (memcmp(evbuffer_pullup(
			   evb, -1), buffer, sizeof(buffer) / 2) != 0 ||
	    memcmp(evbuffer_pullup(
			   evb_two, -1), buffer, sizeof(buffer) != 0))
		tt_abort_msg("Pullup did not preserve content");

	evbuffer_validate(evb);


	/* testing reserve and commit */
	{
		u_char *buf;
		int i, j;

		for (i = 0; i < 3; ++i) {
			buf = evbuffer_reserve_space(evb, 10000);
			tt_assert(buf != NULL);
			evbuffer_validate(evb);
			for (j = 0; j < 10000; ++j) {
				buf[j] = j;
			}
			evbuffer_validate(evb);

			tt_assert(evbuffer_commit_space(evb, 10000) == 0);
			evbuffer_validate(evb);

			tt_assert(evbuffer_get_length(evb) >= 10000);

			evbuffer_drain(evb, j * 5000);
			evbuffer_validate(evb);
		}
	}

 end:
	evbuffer_free(evb);
	evbuffer_free(evb_two);
}

static int reference_cb_called;
static void
reference_cb(void *extra)
{
	tt_want(extra == (void *)0xdeadaffe);
	++reference_cb_called;
}

static void
test_evbuffer_reference(void *ptr)
{
	struct evbuffer *src = evbuffer_new();
	struct evbuffer *dst = evbuffer_new();
	unsigned char *tmp;
	const char *data = "this is what we add as read-only memory.";
	reference_cb_called = 0;

	tt_assert(evbuffer_add_reference(src, data, strlen(data),
		 reference_cb, (void *)0xdeadaffe) != -1);

	tmp = evbuffer_reserve_space(dst, strlen(data));
	tt_assert(evbuffer_remove(src, tmp, 10) != -1);

	evbuffer_validate(src);
	evbuffer_validate(dst);

	/* make sure that we don't write data at the beginning */
	evbuffer_prepend(src, "aaaaa", 5);
	evbuffer_validate(src);
	evbuffer_drain(src, 5);

	tt_assert(evbuffer_remove(src, tmp + 10, strlen(data) - 10) != -1);

	evbuffer_commit_space(dst, strlen(data));
	evbuffer_validate(src);
	evbuffer_validate(dst);

	tt_int_op(reference_cb_called, ==, 1);

	tt_assert(!memcmp(evbuffer_pullup(dst, strlen(data)),
			  data, strlen(data)));

 end:
	evbuffer_free(dst);
	evbuffer_free(src);
}

static void
test_evbuffer_readln(void *ptr)
{
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_tmp = evbuffer_new();
	const char *s;
	char *cp = NULL;
	size_t sz;

#define tt_line_eq(content)						\
	TT_STMT_BEGIN							\
	if (!cp || sz != strlen(content) || strcmp(cp, content)) { 	\
		TT_DIE(("Wanted %s; got %s [%d]", content, cp, (int)sz)); \
	}								\
	TT_STMT_END

	/* Test EOL_ANY. */
	s = "complex silly newline\r\n\n\r\n\n\rmore\0\n";
	evbuffer_add(evb, s, strlen(s)+2);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	tt_line_eq("complex silly newline");
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz != 5 || memcmp(cp, "more\0\0", 6))
		tt_abort_msg("Not as expected");
	tt_uint_op(EVBUFFER_LENGTH(evb), ==, 0);
	evbuffer_validate(evb);
	s = "\nno newline";
	evbuffer_add(evb, s, strlen(s));
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	tt_line_eq("");
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	tt_assert(!cp);
	evbuffer_validate(evb);
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	tt_assert(EVBUFFER_LENGTH(evb) == 0);
	evbuffer_validate(evb);

	/* Test EOL_CRLF */
	s = "Line with\rin the middle\nLine with good crlf\r\n\nfinal\n";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	tt_line_eq("Line with\rin the middle");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	tt_line_eq("Line with good crlf");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	tt_line_eq("");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	tt_line_eq("final");
	s = "x";
	evbuffer_validate(evb);
	evbuffer_add(evb, s, 1);
	evbuffer_validate(evb);
	free(cp);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	tt_assert(!cp);
	evbuffer_validate(evb);

	/* Test CRLF_STRICT */
	s = " and a bad crlf\nand a good one\r\n\r\nMore\r";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq("x and a bad crlf\nand a good one");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq("");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_assert(!cp);
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq("More");
	free(cp);
	tt_assert(EVBUFFER_LENGTH(evb) == 0);
	evbuffer_validate(evb);

	/* Test LF */
	s = "An\rand a nl\n\nText";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	tt_line_eq("An\rand a nl");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	tt_line_eq("");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	tt_assert(!cp);
	free(cp);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	tt_line_eq("Text");
	free(cp);
	evbuffer_validate(evb);

	/* Test CRLF_STRICT - across boundaries*/
	s = " and a bad crlf\nand a good one\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);
	s = "\n\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);
	s = "\nMore\r";
	evbuffer_add(evb_tmp, s, strlen(s));
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_tmp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq(" and a bad crlf\nand a good one");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq("");
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_assert(!cp);
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	tt_line_eq("More");
	free(cp); cp = NULL;
	evbuffer_validate(evb);
	tt_assert(EVBUFFER_LENGTH(evb) == 0);

	test_ok = 1;
 end:
	evbuffer_free(evb);
	evbuffer_free(evb_tmp);
	if (cp) free(cp);
}

static void
test_evbuffer_iterative(void *ptr)
{
	struct evbuffer *buf = evbuffer_new();
	const char *abc = "abcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyzabcdefghijklmnopqrstvuwxyz";
	int i, j, sum;

	sum = 0;
	for (i = 0; i < 1000; ++i) {
		for (j = 1; j < strlen(abc); ++j) {
			char format[32];

			evutil_snprintf(format, sizeof(format), "%%%d.%ds", j, j);
			evbuffer_add_printf(buf, format, abc);
			evbuffer_validate(buf);

			sum += j;
		}
	}

	tt_uint_op(sum, ==, EVBUFFER_LENGTH(buf));

 end:
	evbuffer_free(buf);

}

static void
test_evbuffer_find(void *ptr)
{
	u_char* p;
	const char* test1 = "1234567890\r\n";
	const char* test2 = "1234567890\r";
#define EVBUFFER_INITIAL_LENGTH 256
	char test3[EVBUFFER_INITIAL_LENGTH];
	unsigned int i;
	struct evbuffer * buf = evbuffer_new();

	/* make sure evbuffer_find doesn't match past the end of the buffer */
	evbuffer_add(buf, (u_char*)test1, strlen(test1));
	evbuffer_validate(buf);
	evbuffer_drain(buf, strlen(test1));
	evbuffer_validate(buf);
	evbuffer_add(buf, (u_char*)test2, strlen(test2));
	evbuffer_validate(buf);
	p = evbuffer_find(buf, (u_char*)"\r\n", 2);
        tt_want(p == NULL);

	/*
	 * drain the buffer and do another find; in r309 this would
	 * read past the allocated buffer causing a valgrind error.
	 */
	evbuffer_drain(buf, strlen(test2));
	evbuffer_validate(buf);
	for (i = 0; i < EVBUFFER_INITIAL_LENGTH; ++i)
		test3[i] = 'a';
	test3[EVBUFFER_INITIAL_LENGTH - 1] = 'x';
	evbuffer_add(buf, (u_char *)test3, EVBUFFER_INITIAL_LENGTH);
	evbuffer_validate(buf);
	p = evbuffer_find(buf, (u_char *)"xy", 2);
        tt_want(p == NULL);

	/* simple test for match at end of allocated buffer */
	p = evbuffer_find(buf, (u_char *)"ax", 2);
        tt_assert(p != NULL);
        tt_want(strncmp((char*)p, "ax", 2) == 0);

end:
        if (buf)
                evbuffer_free(buf);
}

static void
log_change_callback(struct evbuffer *buffer, size_t old_len, size_t new_len,
	       void *arg)
{
	struct evbuffer *out = arg;
	evbuffer_add_printf(out, "%lu->%lu; ", (unsigned long)old_len,
			    (unsigned long)new_len);
}
static void
self_draining_callback(struct evbuffer *evbuffer, size_t old_len,
		       size_t new_len, void *arg)
{
	if (new_len > old_len)
		evbuffer_drain(evbuffer, new_len);
}

static void
test_evbuffer_callbacks(void *ptr)
{
	struct evbuffer *buf = evbuffer_new();
	struct evbuffer *buf_out1 = evbuffer_new();
	struct evbuffer *buf_out2 = evbuffer_new();
	struct evbuffer_cb_entry *cb1, *cb2;

	cb1 = evbuffer_add_cb(buf, log_change_callback, buf_out1);
	cb2 = evbuffer_add_cb(buf, log_change_callback, buf_out2);

	/* Let's run through adding and deleting some stuff from the buffer
	 * and turning the callbacks on and off and removing them.  The callback
	 * adds a summary of length changes to buf_out1/buf_out2 when called. */
	/* size: 0-> 36. */
	evbuffer_add_printf(buf, "The %d magic words are spotty pudding", 2);
	evbuffer_cb_set_flags(buf, cb2, 0);
	evbuffer_drain(buf, 10); /*36->26*/
	evbuffer_prepend(buf, "Hello", 5);/*26->31*/
	evbuffer_cb_set_flags(buf, cb2, EVBUFFER_CB_ENABLED);
	evbuffer_add_reference(buf, "Goodbye", 7, NULL, NULL); /*31->38*/
	evbuffer_remove_cb_entry(buf, cb1);
	evbuffer_drain(buf, EVBUFFER_LENGTH(buf)); /*38->0*/;
	tt_assert(-1 == evbuffer_remove_cb(buf, log_change_callback, NULL));
	evbuffer_add(buf, "X", 1); /* 0->1 */
	tt_assert(!evbuffer_remove_cb(buf, log_change_callback, buf_out2));

	tt_str_op(evbuffer_pullup(buf_out1, -1), ==,
		  "0->36; 36->26; 26->31; 31->38; ");
	tt_str_op(evbuffer_pullup(buf_out2, -1), ==,
		  "0->36; 31->38; 38->0; 0->1; ");
	evbuffer_drain(buf_out1, EVBUFFER_LENGTH(buf_out1));
	evbuffer_drain(buf_out2, EVBUFFER_LENGTH(buf_out2));

	/* Let's test the obsolete buffer_setcb function too. */
	cb1 = evbuffer_add_cb(buf, log_change_callback, buf_out1);
	cb2 = evbuffer_add_cb(buf, log_change_callback, buf_out2);
	evbuffer_setcb(buf, self_draining_callback, NULL);
	evbuffer_add_printf(buf, "This should get drained right away.");
	tt_uint_op(EVBUFFER_LENGTH(buf), ==, 0);
	tt_uint_op(EVBUFFER_LENGTH(buf_out1), ==, 0);
	tt_uint_op(EVBUFFER_LENGTH(buf_out2), ==, 0);
	evbuffer_setcb(buf, NULL, NULL);
	evbuffer_add_printf(buf, "This will not.");
	tt_str_op(evbuffer_pullup(buf, -1), ==, "This will not.");

 end:
	if (buf)
		evbuffer_free(buf);
	if (buf_out1)
		evbuffer_free(buf_out1);
	if (buf_out2)
		evbuffer_free(buf_out2);
}

struct testcase_t evbuffer_testcases[] = {
	{ "evbuffer", test_evbuffer, 0, NULL, NULL },
	{ "reference", test_evbuffer_reference, 0, NULL, NULL },
	{ "iterative", test_evbuffer_iterative, 0, NULL, NULL },
	{ "readln", test_evbuffer_readln, 0, NULL, NULL },
	{ "find", test_evbuffer_find, 0, NULL, NULL },
	{ "callbacks", test_evbuffer_callbacks, 0, NULL, NULL },

	END_OF_TESTCASES
};
