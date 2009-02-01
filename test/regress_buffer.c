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

/* Validates that an evbuffer is good. */
static void
evbuffer_validate(struct evbuffer *buf)
{
	struct evbuffer_chain *chain, *previous = NULL;
	size_t sum = 0;

	if (buf->first == NULL) {
		assert(buf->last == NULL);
		assert(buf->previous_to_last == NULL);
		assert(buf->total_len == 0);
	}

	if (buf->previous_to_last == NULL) {
		assert(buf->first == buf->last);
	}

	chain = buf->first;
	while (chain != NULL) {
		sum += chain->off;
		if (chain->next == NULL) {
			assert(buf->previous_to_last == previous);
			assert(buf->last == chain);
		}
		assert(chain->buffer_len >= chain->misalign + chain->off);
		previous = chain;
		chain = chain->next;
	}

	assert(sum == buf->total_len);
}

static void
test_evbuffer(void)
{
	static char buffer[512], *tmp;
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_two = evbuffer_new();
	size_t sz_tmp;
	int i;

	evbuffer_validate(evb);
	evbuffer_add_printf(evb, "%s/%d", "hello", 1);
	evbuffer_validate(evb);

	if (EVBUFFER_LENGTH(evb) != 7 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "hello/1", 1) != 0)
		goto out;

	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	evbuffer_drain(evb, strlen("hello/"));
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 1 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "1", 1) != 0)
		goto out;

	evbuffer_add_printf(evb_two, "%s", "/hello");
	evbuffer_validate(evb);
	evbuffer_add_buffer(evb, evb_two);
	evbuffer_validate(evb);

	if (EVBUFFER_LENGTH(evb_two) != 0 ||
	    EVBUFFER_LENGTH(evb) != 7 ||
	    memcmp((char*)EVBUFFER_DATA(evb), "1/hello", 7) != 0)
		goto out;

	memset(buffer, 0, sizeof(buffer));
	evbuffer_add(evb, buffer, sizeof(buffer));
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 7 + 512)
		goto out;

	tmp = (char *)evbuffer_pullup(evb, 7 + 512);
	if (tmp == NULL)
		goto out;
	if (strncmp(tmp, "1/hello", 7) != 0)
		goto out;
	if (memcmp(tmp + 7, buffer, sizeof(buffer)) != 0)
		goto out;
	evbuffer_validate(evb);

	evbuffer_prepend(evb, "something", 9);
	evbuffer_validate(evb);
	evbuffer_prepend(evb, "else", 4);
	evbuffer_validate(evb);

	tmp = (char *)evbuffer_pullup(evb, 4 + 9 + 7);
	if (strncmp(tmp, "elsesomething1/hello", 4 + 9 + 7) != 0)
		goto out;
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

	if (EVBUFFER_LENGTH(evb_two) != 0 ||
	    EVBUFFER_LENGTH(evb) != i * sizeof(buffer))
		goto out;

	/* test remove buffer */
	sz_tmp = sizeof(buffer)*2.5;
	evbuffer_remove_buffer(evb, evb_two, sz_tmp);
	if (EVBUFFER_LENGTH(evb_two) != sz_tmp ||
	    EVBUFFER_LENGTH(evb) != sizeof(buffer) / 2)
		goto out;
	evbuffer_validate(evb);

	if (memcmp(evbuffer_pullup(
			   evb, -1), buffer, sizeof(buffer) / 2) != 0 ||
	    memcmp(evbuffer_pullup(
			   evb_two, -1), buffer, sizeof(buffer) != 0))
		goto out;
	evbuffer_validate(evb);


	/* testing reserve and commit */
	{
		u_char *buf;
		int i, j;

		for (i = 0; i < 3; ++i) {
			buf = evbuffer_reserve_space(evb, 10000);
			assert(buf != NULL);
			evbuffer_validate(evb);
			for (j = 0; j < 10000; ++j) {
				buf[j] = j;
			}
			evbuffer_validate(evb);

			assert(evbuffer_commit_space(evb, 10000) == 0);
			evbuffer_validate(evb);

			assert(evbuffer_get_length(evb) >= 10000);

			evbuffer_drain(evb, j * 5000);
			evbuffer_validate(evb);
		}
	}

	test_ok = 1;

out:
	evbuffer_free(evb);
	evbuffer_free(evb_two);

}

static void
reference_cb(void *extra)
{
	assert(extra = (void *)0xdeadaffe);
	test_ok = 1;
}

static void
test_evbuffer_reference(void)
{
	struct evbuffer *src = evbuffer_new();
	struct evbuffer *dst = evbuffer_new();
	unsigned char *tmp;
	const char *data = "this is what we add as read-only memory.";

	if (evbuffer_add_reference(src, data, strlen(data),
		reference_cb, (void *)0xdeadaffe) == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	tmp = evbuffer_reserve_space(dst, strlen(data));
	if (evbuffer_remove(src, tmp, 10) == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evbuffer_validate(src);
	evbuffer_validate(dst);

	/* make sure that we don't write data at the beginning */
	evbuffer_prepend(src, "aaaaa", 5);
	evbuffer_validate(src);
	evbuffer_drain(src, 5);

	if (evbuffer_remove(src, tmp + 10, strlen(data) - 10) == -1) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evbuffer_commit_space(dst, strlen(data));
	evbuffer_validate(src);
	evbuffer_validate(dst);

	if (memcmp(evbuffer_pullup(dst, strlen(data)),
		data, strlen(data)) != 0) {
		fprintf(stdout, "FAILED\n");
		exit(1);
	}

	evbuffer_free(dst);
	evbuffer_free(src);
}

static void
test_evbuffer_readln(void)
{
	struct evbuffer *evb = evbuffer_new();
	struct evbuffer *evb_tmp = evbuffer_new();
	const char *s;
	char *cp = NULL;
	size_t sz;

	/* Test EOL_ANY. */
	s = "complex silly newline\r\n\n\r\n\n\rmore\0\n";
	evbuffer_add(evb, s, strlen(s)+2);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz != strlen(cp) || strcmp(cp, "complex silly newline"))
		goto done;
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz != 5 || memcmp(cp, "more\0\0", 6))
		goto done;
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);
	s = "\nno newline";
	evbuffer_add(evb, s, strlen(s));
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (!cp || sz || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_ANY);
	if (cp)
		goto done;
	evbuffer_validate(evb);
	evbuffer_drain(evb, EVBUFFER_LENGTH(evb));
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);

	/* Test EOL_CRLF */
	s = "Line with\rin the middle\nLine with good crlf\r\n\nfinal\n";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Line with\rin the middle"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Line with good crlf"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "final"))
		goto done;
	s = "x";
	evbuffer_validate(evb);
	evbuffer_add(evb, s, 1);
	evbuffer_validate(evb);
	free(cp);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF);
	if (cp)
		goto done;
	evbuffer_validate(evb);

	/* Test CRLF_STRICT */
	s = " and a bad crlf\nand a good one\r\n\r\nMore\r";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) ||
	    strcmp(cp, "x and a bad crlf\nand a good one"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (cp)
		goto done;
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, "More"))
		goto done;
	free(cp);
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;
	evbuffer_validate(evb);

	/* Test LF */
	s = "An\rand a nl\n\nText";
	evbuffer_add(evb, s, strlen(s));
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "An\rand a nl"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (cp)
		goto done;
	free(cp);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_LF);
	if (!cp || sz != strlen(cp) || strcmp(cp, "Text"))
		goto done;
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
	if (!cp || sz != strlen(cp) ||
	    strcmp(cp, " and a bad crlf\nand a good one"))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, ""))
		goto done;
	free(cp);
	evbuffer_validate(evb);

	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (cp)
		goto done;
	free(cp);
	evbuffer_validate(evb);
	evbuffer_add(evb, "\n", 1);
	evbuffer_validate(evb);
	cp = evbuffer_readln(evb, &sz, EVBUFFER_EOL_CRLF_STRICT);
	if (!cp || sz != strlen(cp) || strcmp(cp, "More"))
		goto done;
	free(cp); cp = NULL;
	evbuffer_validate(evb);
	if (EVBUFFER_LENGTH(evb) != 0)
		goto done;


	test_ok = 1;
 done:
	evbuffer_free(evb);
	evbuffer_free(evb_tmp);
	if (cp) free(cp);
}

static void
test_evbuffer_iterative(void)
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

	if (sum == EVBUFFER_LENGTH(buf))
		test_ok = 1;

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

struct testcase_t evbuffer_testcases[] = {
	/* These need to fork because of evbuffer_validate. Otherwise
	 * they'd be fine in the main process, since they don't mess
	 * with global state. */
	LEGACY(evbuffer, TT_FORK),
	LEGACY(evbuffer_reference, TT_FORK),
	LEGACY(evbuffer_iterative, TT_FORK),
	LEGACY(evbuffer_readln, TT_FORK),
	{ "evbuffer_find", test_evbuffer_find, TT_FORK, NULL, NULL },

	END_OF_TESTCASES
};
