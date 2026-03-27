/* tinytest.c -- Copyright 2009-2012 Nick Mathewson
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
#ifdef TINYTEST_LOCAL
#include "tinytest_local.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef TINYTEST_LOCAL
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif
#endif

#ifndef NO_FORKING

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#endif

#if defined(__APPLE__) && defined(__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__)
#if (__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1060 && \
    __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ < 1070)
/* Workaround for a stupid bug in OSX 10.6 */
#define FORK_BREAKS_GCOV
#include <vproc.h>
#endif
#endif

#endif /* !NO_FORKING */

#ifndef __GNUC__
#define __attribute__(x)
#endif

#include "tinytest.h"
#include "tinytest_macros.h"

#define LONGEST_TEST_NAME 16384
#define DEFAULT_TESTCASE_TIMEOUT 30U
#define MAGIC_EXITCODE 42

static int in_tinytest_main = 0; /**< true if we're in tinytest_main().*/
static int n_ok = 0; /**< Number of tests that have passed */
static int n_bad = 0; /**< Number of tests that have failed. */
static int n_skipped = 0; /**< Number of tests that have been skipped. */

static int opt_forked = 0; /**< True iff we're called from inside a win32 fork*/
static int opt_nofork = 0; /**< Suppress calls to fork() for debugging. */
static int opt_verbosity = 1; /**< -==quiet,0==terse,1==normal,2==verbose */
static unsigned int opt_timeout = DEFAULT_TESTCASE_TIMEOUT; /**< Timeout for every test (using alarm()) */
static unsigned int opt_retries = 3; /**< How much test with TT_RETRIABLE should be retried */
static unsigned int opt_retries_delay = 1; /**< How much seconds to delay before retrying */
static unsigned int opt_repeat = 0; /**< How much times to repeat the test */
static int opt_parallel = -1; /**< Parallel workers: -1=auto, 0=sequential, >0=N workers */
const char *verbosity_flag = "";

const struct testlist_alias_t *cfg_aliases=NULL;

enum outcome { SKIP=2, OK=1, FAIL=0 };
static enum outcome cur_test_outcome = 0;
const char *cur_test_prefix = NULL; /**< prefix of the current test group */
/** Name of the current test, if we haven't logged is yet. Used for --quiet */
const char *cur_test_name = NULL;

static void usage(struct testgroup_t *groups, int list_groups)
	__attribute__((noreturn));
static int process_test_option(struct testgroup_t *groups, const char *test);

#ifdef TINYTEST_LOCAL
static struct evutil_monotonic_timer mono_timer_;
static int mono_timer_initialized_ = 0;
#endif

static double
gettime_(void)
{
	struct timeval tv;
#ifdef TINYTEST_LOCAL
	if (!mono_timer_initialized_) {
		evutil_configure_monotonic_time_(&mono_timer_, 0);
		mono_timer_initialized_ = 1;
	}
	evutil_gettime_monotonic_(&mono_timer_, &tv);
#elif defined(_WIN32)
	ULONGLONG ms = GetTickCount64();
	tv.tv_sec = (long)(ms / 1000);
	tv.tv_usec = (long)((ms % 1000) * 1000);
#else
	gettimeofday(&tv, NULL);
#endif
	return tv.tv_sec + tv.tv_usec / 1000000.0;
}

#ifdef _WIN32
/* Copy of argv[0] for win32. */
static char commandname[MAX_PATH+1];

struct timeout_thread_args {
	const testcase_fn *fn;
	void *env;
};

static DWORD WINAPI
timeout_thread_proc_(LPVOID arg)
{
	struct timeout_thread_args *args = arg;
	(*(args->fn))(args->env);
	ExitThread(cur_test_outcome == FAIL ? 1 : 0);
}

static enum outcome
testcase_run_in_thread_(const struct testcase_t *testcase, void *env)
{
	/* We will never run testcase in a new thread when the
	timeout is set to zero */
	assert(opt_timeout);
	DWORD ret, tid;
	HANDLE handle;
	struct timeout_thread_args args = {
		&(testcase->fn),
		env
	};

	handle =CreateThread(NULL, 0, timeout_thread_proc_,
		(LPVOID)&args, 0, &tid);
	ret = WaitForSingleObject(handle, opt_timeout * 1000U);
	if (ret == WAIT_OBJECT_0) {
		ret = 0;
		if (!GetExitCodeThread(handle, &ret)) {
			printf("GetExitCodeThread failed\n");
			ret = 1;
		}
	} else if (ret == WAIT_TIMEOUT)	{
		printf("timeout\n");
	} else {
		printf("Wait failed\n");
	}
	CloseHandle(handle);
	if (ret == 0)
		return OK;
	else if (ret == MAGIC_EXITCODE)
		return SKIP;
	else
		return FAIL;
}
#else
static unsigned int testcase_set_timeout_(void)
{
	return alarm(opt_timeout);
}

static unsigned int testcase_reset_timeout_(void)
{
	return alarm(0);
}
#endif

static enum outcome
testcase_run_bare_(const struct testcase_t *testcase)
{
	void *env = NULL;
	int outcome;
	if (testcase->setup) {
		env = testcase->setup->setup_fn(testcase);
		if (!env)
			return FAIL;
		else if (env == (void*)TT_SKIP)
			return SKIP;
	}

	cur_test_outcome = OK;
	{
		if (opt_timeout) {
#ifdef _WIN32
			cur_test_outcome = testcase_run_in_thread_(testcase, env);
#else
			testcase_set_timeout_();
			testcase->fn(env);
			testcase_reset_timeout_();
#endif
		} else {
			testcase->fn(env);
		}
	}
	outcome = cur_test_outcome;

	if (testcase->setup) {
		if (testcase->setup->cleanup_fn(testcase, env) == 0)
			outcome = FAIL;
	}

	return outcome;
}


#ifndef NO_FORKING

static enum outcome
testcase_run_forked_(const struct testgroup_t *group,
		     const struct testcase_t *testcase)
{
#ifdef _WIN32
	/* Fork? On Win32?  How primitive!  We'll do what the smart kids do:
	   we'll invoke our own exe (whose name we recall from the command
	   line) with a command line that tells it to run just the test we
	   want, and this time without forking.

	   (No, threads aren't an option.  The whole point of forking is to
	   share no state between tests.)
	 */
	int ok;
	char buffer[LONGEST_TEST_NAME+256];
	STARTUPINFOA si;
	PROCESS_INFORMATION info;
	DWORD ret;

	if (!in_tinytest_main) {
		printf("\nERROR.  On Windows, testcase_run_forked_ must be"
		       " called from within tinytest_main.\n");
		abort();
	}
	if (opt_verbosity>0)
		printf("[forking] ");

	snprintf(buffer, sizeof(buffer), "%s --RUNNING-FORKED %s --timeout 0 %s%s",
		 commandname, verbosity_flag, group->prefix, testcase->name);

	memset(&si, 0, sizeof(si));
	memset(&info, 0, sizeof(info));
	si.cb = sizeof(si);

	ok = CreateProcessA(commandname, buffer, NULL, NULL, 0,
			   0, NULL, NULL, &si, &info);
	if (!ok) {
		printf("CreateProcess failed!\n");
		return FAIL;
	}
	ret = WaitForSingleObject(info.hProcess,
		(opt_timeout ? opt_timeout * 1000U : INFINITE));

	if (ret == WAIT_OBJECT_0) {
		GetExitCodeProcess(info.hProcess, &ret);
	} else if (ret == WAIT_TIMEOUT) {
		printf("timeout\n");
	} else {
		printf("Wait failed\n");
	}
	CloseHandle(info.hProcess);
	CloseHandle(info.hThread);
	if (ret == 0)
		return OK;
	else if (ret == MAGIC_EXITCODE)
		return SKIP;
	else
		return FAIL;
#else
	int outcome_pipe[2];
	pid_t pid;
	(void)group;

	if (pipe(outcome_pipe))
		perror("opening pipe");

	if (opt_verbosity>0)
		printf("[forking] ");
	pid = fork();
#ifdef FORK_BREAKS_GCOV
	vproc_transaction_begin(0);
#endif
	if (!pid) {
		/* child. */
		int test_r, write_r;
		char b[1];
		close(outcome_pipe[0]);
		test_r = testcase_run_bare_(testcase);
		assert(0<=(int)test_r && (int)test_r<=2);
		b[0] = "NYS"[test_r];
		write_r = (int)write(outcome_pipe[1], b, 1);
		if (write_r != 1) {
			perror("write outcome to pipe");
			exit(1);
		}
		exit(0);
		return FAIL; /* unreachable */
	} else {
		/* parent */
		int status, r, exitcode;
		char b[1];
		/* Close this now, so that if the other side closes it,
		 * our read fails. */
		close(outcome_pipe[1]);
		r = (int)read(outcome_pipe[0], b, 1);
		waitpid(pid, &status, 0);
		exitcode = WEXITSTATUS(status);
		close(outcome_pipe[0]);
		if (r == 0) {
			if (WIFSIGNALED(status))
				printf("[Lost connection: signal %i] ", WTERMSIG(status));
			else
				printf("[Lost connection: exit %i] ", exitcode);
			return FAIL;
		} else if (r != 1) {
			if (WIFSIGNALED(status))
				printf("[read outcome from pipe: signal %i] ", WTERMSIG(status));
			else
				printf("[read outcome from pipe: exit %i] ", exitcode);
		}
		if (opt_verbosity>1)
			printf("%s%s: exited with %i (%i)\n", group->prefix, testcase->name, exitcode, status);
		return b[0]=='Y' ? OK : (b[0]=='S' ? SKIP : FAIL);
	}
#endif
}

#endif /* !NO_FORKING */

int
testcase_run_one(const struct testgroup_t *group,
		 const struct testcase_t *testcase,
		 const int test_attempts)
{
	enum outcome outcome;

	if (testcase->flags & (TT_SKIP|TT_OFF_BY_DEFAULT)) {
		if (opt_verbosity>0)
			printf("%s%s: %s\n",
			   group->prefix, testcase->name,
			   (testcase->flags & TT_SKIP) ? "SKIPPED" : "DISABLED");
		++n_skipped;
		return SKIP;
	}

	if (opt_verbosity>0 && !opt_forked) {
		printf("%s%s: ", group->prefix, testcase->name);
	} else {
		if (opt_verbosity==0) printf(".");
		cur_test_prefix = group->prefix;
		cur_test_name = testcase->name;
	}

	{
	double t_start = gettime_();

#ifndef NO_FORKING
	if ((testcase->flags & TT_FORK) && !(opt_forked||opt_nofork)) {
		outcome = testcase_run_forked_(group, testcase);
	} else {
#else
	{
#endif
		outcome = testcase_run_bare_(testcase);
	}

	if (outcome == OK) {
		if (opt_verbosity>0 && !opt_forked)
			printf("OK (%.3fs)\n", gettime_() - t_start);
	} else if (outcome == SKIP) {
		if (opt_verbosity>0 && !opt_forked)
			puts("SKIPPED");
	} else {
		if (!opt_forked && (testcase->flags & TT_RETRIABLE) && !test_attempts)
			printf("FAIL (%.3fs)\n  [%s FAILED]\n",
				gettime_() - t_start, testcase->name);
	}
	}

	if (opt_forked) {
		exit(outcome==OK ? 0 : (outcome==SKIP?MAGIC_EXITCODE : 1));
		return 1; /* unreachable */
	} else {
		return (int)outcome;
	}
}

int
tinytest_set_flag_(struct testgroup_t *groups, const char *arg, int set, unsigned long flag)
{
	int i, j;
	size_t length = LONGEST_TEST_NAME;
	char fullname[LONGEST_TEST_NAME];
	int found=0;
	if (strstr(arg, ".."))
		length = strstr(arg,"..")-arg;
	for (i=0; groups[i].prefix; ++i) {
		for (j=0; groups[i].cases[j].name; ++j) {
			struct testcase_t *testcase = &groups[i].cases[j];
			snprintf(fullname, sizeof(fullname), "%s%s",
				 groups[i].prefix, testcase->name);
			if (!flag) { /* Hack! */
				printf("    %s", fullname);
				if (testcase->flags & TT_OFF_BY_DEFAULT)
					puts("   (Off by default)");
				else if (testcase->flags & TT_SKIP)
					puts("  (DISABLED)");
				else
					puts("");
			}
			if (!strncmp(fullname, arg, length)) {
				if (set)
					testcase->flags |= flag;
				else
					testcase->flags &= ~flag;
				++found;
			}
		}
	}
	return found;
}

static void
usage(struct testgroup_t *groups, int list_groups)
{
	puts("Options are:");
	puts("  -v, --verbose");
	puts("  --quiet");
	puts("  --terse");
	puts("  --no-fork");
	puts("  --timeout <sec>");
	puts("  --retries <n>");
	puts("  --retries-delay <n>");
	puts("  --repeat <n>");
	puts("  -j, --parallel <n>  (default: min(4*nproc, 64); 0=sequential)");
	puts("");
	puts("  Specify tests by name, or using a prefix ending with '..'");
	puts("  To skip a test, prefix its name with a colon.");
	puts("  To enable a disabled test, prefix its name with a plus.");
	puts("  Use --list-tests for a list of tests.");
	if (list_groups) {
		puts("Known tests are:");
		tinytest_set_flag_(groups, "..", 1, 0);
	}
	exit(0);
}

static int
process_test_alias(struct testgroup_t *groups, const char *test)
{
	int i, j, n, r;
	for (i=0; cfg_aliases && cfg_aliases[i].name; ++i) {
		if (!strcmp(cfg_aliases[i].name, test)) {
			n = 0;
			for (j = 0; cfg_aliases[i].tests[j]; ++j) {
				r = process_test_option(groups, cfg_aliases[i].tests[j]);
				if (r<0)
					return -1;
				n += r;
			}
			return n;
		}
	}
	printf("No such test alias as @%s!",test);
	return -1;
}

static int
process_test_option(struct testgroup_t *groups, const char *test)
{
	int flag = TT_ENABLED_;
	int n = 0;
	if (test[0] == '@') {
		return process_test_alias(groups, test + 1);
	} else if (test[0] == ':') {
		++test;
		flag = TT_SKIP;
	} else if (test[0] == '+') {
		++test;
		++n;
		if (!tinytest_set_flag_(groups, test, 0, TT_OFF_BY_DEFAULT)) {
			printf("No such test as %s!\n", test);
			return -1;
		}
	} else {
		++n;
	}
	if (!tinytest_set_flag_(groups, test, 1, flag)) {
		printf("No such test as %s!\n", test);
		return -1;
	}
	return n;
}

void
tinytest_set_aliases(const struct testlist_alias_t *aliases)
{
	cfg_aliases = aliases;
}

/* ====== Parallel test runner ====== */
#ifndef NO_FORKING

struct parallel_slot {
	char testname[LONGEST_TEST_NAME];
	char *output;
	size_t output_len;
	size_t output_cap;
	double start_time;
#ifdef _WIN32
	HANDLE process;
	HANDLE pipe_rd;
#else
	pid_t pid;
	int pipe_fd;
#endif
};

static void
par_buf_append_(struct parallel_slot *s, const char *data, size_t len)
{
	if (!len)
		return;
	if (s->output_len + len >= s->output_cap) {
		size_t newcap = s->output_cap ? s->output_cap * 2 : 4096;
		char *p;
		while (newcap < s->output_len + len + 1)
			newcap *= 2;
		p = realloc(s->output, newcap);
		if (!p)
			return;
		s->output = p;
		s->output_cap = newcap;
	}
	memcpy(s->output + s->output_len, data, len);
	s->output_len += len;
	s->output[s->output_len] = '\0';
}

static void
par_slot_free_(struct parallel_slot *s)
{
	free(s->output);
	s->output = NULL;
	s->output_len = 0;
	s->output_cap = 0;
#ifdef _WIN32
	s->process = NULL;
	s->pipe_rd = NULL;
#else
	s->pid = -1;
	s->pipe_fd = -1;
#endif
}

static int
run_tests_parallel_(const char *exe, struct testgroup_t *groups)
{
	int i, j, slot, njobs;
	int ntests = 0, next = 0, running = 0;
	int p_ok = 0, p_bad = 0;
	struct parallel_slot *slots = NULL;
	char **tests = NULL;
	int rc = 1;
#ifndef _WIN32
	struct pollfd *pfds = NULL;
#endif

	/* Count enabled tests */
	for (i = 0; groups[i].prefix; ++i)
		for (j = 0; groups[i].cases[j].name; ++j)
			if ((groups[i].cases[j].flags & TT_ENABLED_) &&
			    !(groups[i].cases[j].flags & (TT_SKIP|TT_OFF_BY_DEFAULT)))
				ntests++;

	if (ntests == 0) {
		if (opt_verbosity >= 1)
			printf("No tests to run.\n");
		return 0;
	}

	/* Build test name array */
	tests = calloc((size_t)ntests, sizeof(char *));
	if (!tests)
		goto out;
	{
		int idx = 0;
		for (i = 0; groups[i].prefix; ++i)
			for (j = 0; groups[i].cases[j].name; ++j)
				if ((groups[i].cases[j].flags & TT_ENABLED_) &&
				    !(groups[i].cases[j].flags & (TT_SKIP|TT_OFF_BY_DEFAULT))) {
					size_t len = strlen(groups[i].prefix) +
						strlen(groups[i].cases[j].name) + 1;
					tests[idx] = malloc(len);
					if (!tests[idx])
						goto out;
					snprintf(tests[idx], len, "%s%s",
						groups[i].prefix,
						groups[i].cases[j].name);
					idx++;
				}
	}

	njobs = opt_parallel;
	if (njobs > ntests)
		njobs = ntests;
#ifdef _WIN32
	if (njobs > MAXIMUM_WAIT_OBJECTS) {
		fprintf(stderr, "Warning: capping parallelism at %d on Windows\n",
			(int)MAXIMUM_WAIT_OBJECTS);
		njobs = MAXIMUM_WAIT_OBJECTS;
	}
#endif

	slots = calloc((size_t)njobs, sizeof(*slots));
	if (!slots)
		goto out;
	for (i = 0; i < njobs; i++)
		par_slot_free_(&slots[i]);
#ifndef _WIN32
	pfds = calloc((size_t)njobs, sizeof(*pfds));
	if (!pfds)
		goto out;
#endif

	if (opt_verbosity >= 1)
		printf("Running %d tests with %d workers\n", ntests, njobs);

	while (next < ntests || running > 0) {
		/* Launch new workers */
		while (running < njobs && next < ntests) {
			int test_idx;

			for (slot = 0; slot < njobs; slot++) {
#ifdef _WIN32
				if (slots[slot].process == NULL)
#else
				if (slots[slot].pid <= 0)
#endif
					break;
			}

			test_idx = next++;
			snprintf(slots[slot].testname,
				sizeof(slots[slot].testname),
				"%s", tests[test_idx]);
			slots[slot].output = NULL;
			slots[slot].output_len = 0;
			slots[slot].output_cap = 0;

#ifdef _WIN32
			{
				SECURITY_ATTRIBUTES sa;
				HANDLE pipe_wr;
				STARTUPINFOEXA siex;
				PROCESS_INFORMATION pi;
				char cmdline[LONGEST_TEST_NAME + 512];
				int pos;
				SIZE_T attr_size = 0;
				LPPROC_THREAD_ATTRIBUTE_LIST attr_list = NULL;

				sa.nLength = sizeof(sa);
				sa.bInheritHandle = TRUE;
				sa.lpSecurityDescriptor = NULL;

				if (!CreatePipe(&slots[slot].pipe_rd,
					&pipe_wr, &sa, 0)) {
					printf("[FAILED %s] (CreatePipe)\n",
						slots[slot].testname);
					p_bad++;
					continue;
				}
				SetHandleInformation(slots[slot].pipe_rd,
					HANDLE_FLAG_INHERIT, 0);

				pos = snprintf(cmdline, sizeof(cmdline),
					"%s -j 0 --quiet", commandname);
				if (opt_nofork)
					pos += snprintf(cmdline + pos,
						sizeof(cmdline) - pos,
						" --no-fork");
				pos += snprintf(cmdline + pos,
					sizeof(cmdline) - pos,
					" --timeout %u", opt_timeout);
				if (opt_retries != 3)
					pos += snprintf(cmdline + pos,
						sizeof(cmdline) - pos,
						" --retries %u", opt_retries);
				if (opt_retries_delay != 1)
					pos += snprintf(cmdline + pos,
						sizeof(cmdline) - pos,
						" --retries-delay %u",
						opt_retries_delay);
				if (opt_repeat)
					pos += snprintf(cmdline + pos,
						sizeof(cmdline) - pos,
						" --repeat %u", opt_repeat);
				snprintf(cmdline + pos,
					sizeof(cmdline) - pos,
					" %s", tests[test_idx]);

				memset(&siex, 0, sizeof(siex));
				siex.StartupInfo.cb = sizeof(siex);
				siex.StartupInfo.dwFlags =
					STARTF_USESTDHANDLES;
				siex.StartupInfo.hStdOutput = pipe_wr;
				siex.StartupInfo.hStdError = pipe_wr;
				siex.StartupInfo.hStdInput =
					GetStdHandle(STD_INPUT_HANDLE);

				InitializeProcThreadAttributeList(
					NULL, 1, 0, &attr_size);
				attr_list = malloc(attr_size);
				if (attr_list &&
				    InitializeProcThreadAttributeList(
					attr_list, 1, 0, &attr_size)) {
					UpdateProcThreadAttribute(
						attr_list, 0,
						PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
						&pipe_wr, sizeof(HANDLE),
						NULL, NULL);
					siex.lpAttributeList = attr_list;
				}

				if (!CreateProcessA(commandname, cmdline,
					NULL, NULL, TRUE,
					EXTENDED_STARTUPINFO_PRESENT,
					NULL, NULL,
					&siex.StartupInfo, &pi)) {
					printf("[FAILED %s] (CreateProcess)\n",
						slots[slot].testname);
					if (attr_list) {
						DeleteProcThreadAttributeList(
							attr_list);
						free(attr_list);
					}
					CloseHandle(pipe_wr);
					CloseHandle(slots[slot].pipe_rd);
					slots[slot].pipe_rd = NULL;
					p_bad++;
					continue;
				}
				if (attr_list) {
					DeleteProcThreadAttributeList(
						attr_list);
					free(attr_list);
				}
				CloseHandle(pipe_wr);
				CloseHandle(pi.hThread);
				slots[slot].process = pi.hProcess;
			}
#else
			{
				int pipefd[2];
				pid_t pid;

				if (pipe(pipefd) < 0) {
					perror("pipe");
					p_bad++;
					continue;
				}

				pid = fork();
				if (pid < 0) {
					perror("fork");
					close(pipefd[0]);
					close(pipefd[1]);
					p_bad++;
					continue;
				}

				if (pid == 0) {
					const char *child_argv[16];
					int ac = 0;
					char timeout_s[32], retries_s[32];
					char delay_s[32], repeat_s[32];

					close(pipefd[0]);
					dup2(pipefd[1], STDOUT_FILENO);
					dup2(pipefd[1], STDERR_FILENO);
					if (pipefd[1] != STDOUT_FILENO &&
					    pipefd[1] != STDERR_FILENO)
						close(pipefd[1]);

					child_argv[ac++] = exe;
					child_argv[ac++] = "-j";
					child_argv[ac++] = "0";
					child_argv[ac++] = "--quiet";
					if (opt_nofork)
						child_argv[ac++] = "--no-fork";
					snprintf(timeout_s, sizeof(timeout_s),
						"%u", opt_timeout);
					child_argv[ac++] = "--timeout";
					child_argv[ac++] = timeout_s;
					if (opt_retries != 3) {
						snprintf(retries_s,
							sizeof(retries_s),
							"%u", opt_retries);
						child_argv[ac++] = "--retries";
						child_argv[ac++] = retries_s;
					}
					if (opt_retries_delay != 1) {
						snprintf(delay_s,
							sizeof(delay_s), "%u",
							opt_retries_delay);
						child_argv[ac++] =
							"--retries-delay";
						child_argv[ac++] = delay_s;
					}
					if (opt_repeat) {
						snprintf(repeat_s,
							sizeof(repeat_s),
							"%u", opt_repeat);
						child_argv[ac++] = "--repeat";
						child_argv[ac++] = repeat_s;
					}
					child_argv[ac++] =
						slots[slot].testname;
					child_argv[ac] = NULL;

					execvp(exe,
						(char *const *)child_argv);
					_exit(127);
				}

				close(pipefd[1]);
				slots[slot].pid = pid;
				slots[slot].pipe_fd = pipefd[0];
			}
#endif
			slots[slot].start_time = gettime_();
			running++;
		}

		if (running == 0)
			break;

		/* Drain pipes and reap finished children */
#ifdef _WIN32
		{
			HANDLE handles[MAXIMUM_WAIT_OBJECTS];
			int handle_map[MAXIMUM_WAIT_OBJECTS];
			DWORD nh = 0, ret;

			for (i = 0; i < njobs; i++) {
				if (slots[i].process == NULL)
					continue;
				/* Drain available data */
				for (;;) {
					char buf[4096];
					DWORD avail = 0, nread = 0;
					if (!PeekNamedPipe(slots[i].pipe_rd,
						NULL, 0, NULL, &avail, NULL)
						|| avail == 0)
						break;
					if (!ReadFile(slots[i].pipe_rd, buf,
						sizeof(buf), &nread, NULL)
						|| nread == 0)
						break;
					par_buf_append_(&slots[i],
						buf, nread);
				}
				handles[nh] = slots[i].process;
				handle_map[nh] = i;
				nh++;
			}

			if (nh == 0)
				continue;

			ret = WaitForMultipleObjects(nh, handles, FALSE, 50);

			if (ret >= WAIT_OBJECT_0 &&
			    ret < WAIT_OBJECT_0 + nh) {
				DWORD exitcode;

				slot = handle_map[ret - WAIT_OBJECT_0];

				for (;;) {
					char buf[4096];
					DWORD avail = 0, nread = 0;
					if (!PeekNamedPipe(
						slots[slot].pipe_rd,
						NULL, 0, NULL,
						&avail, NULL)
						|| avail == 0)
						break;
					if (!ReadFile(
						slots[slot].pipe_rd,
						buf, sizeof(buf),
						&nread, NULL)
						|| nread == 0)
						break;
					par_buf_append_(&slots[slot],
						buf, nread);
				}

				GetExitCodeProcess(slots[slot].process,
					&exitcode);
				CloseHandle(slots[slot].process);
				CloseHandle(slots[slot].pipe_rd);

				{
				double elapsed = gettime_() -
					slots[slot].start_time;
				if (exitcode == 0) {
					p_ok++;
					if (opt_verbosity >= 1)
						printf("%s: OK (%.3fs)\n",
							slots[slot].testname,
							elapsed);
					else if (opt_verbosity == 0)
						printf(".");
				} else {
					p_bad++;
					printf("[FAILED %s] (%.3fs)\n",
						slots[slot].testname,
						elapsed);
					if (opt_verbosity >= 1 &&
					    slots[slot].output_len > 0)
						fwrite(slots[slot].output, 1,
							slots[slot].output_len,
							stdout);
				}
				}
				fflush(stdout);
				par_slot_free_(&slots[slot]);
				running--;
			}
		}
#else
		{
			/* Build pollfd array */
			for (i = 0; i < njobs; i++) {
				pfds[i].fd = (slots[i].pid > 0) ?
					slots[i].pipe_fd : -1;
				pfds[i].events = POLLIN;
				pfds[i].revents = 0;
			}

			if (poll(pfds, (nfds_t)njobs, 100) < 0 &&
			    errno != EINTR)
				break;

			/* Read available data from all pipes */
			for (i = 0; i < njobs; i++) {
				if (pfds[i].revents & (POLLIN | POLLHUP)) {
					char buf[4096];
					ssize_t n = read(slots[i].pipe_fd,
						buf, sizeof(buf));
					if (n > 0)
						par_buf_append_(&slots[i],
							buf, (size_t)n);
				}
			}

			/* Reap any exited children */
			for (;;) {
				int status;
				pid_t pid = waitpid(-1, &status, WNOHANG);
				if (pid <= 0)
					break;

				for (slot = 0; slot < njobs; slot++)
					if (slots[slot].pid == pid)
						break;
				if (slot >= njobs)
					continue;

				/* Drain remaining pipe data */
				for (;;) {
					char buf[4096];
					ssize_t n = read(
						slots[slot].pipe_fd,
						buf, sizeof(buf));
					if (n <= 0)
						break;
					par_buf_append_(&slots[slot],
						buf, (size_t)n);
				}
				close(slots[slot].pipe_fd);

				{
				double elapsed = gettime_() -
					slots[slot].start_time;
				if (WIFEXITED(status) &&
				    WEXITSTATUS(status) == 0) {
					p_ok++;
					if (opt_verbosity >= 1)
						printf("%s: OK (%.3fs)\n",
							slots[slot].testname,
							elapsed);
					else if (opt_verbosity == 0)
						printf(".");
				} else {
					p_bad++;
					printf("[FAILED %s] (%.3fs)\n",
						slots[slot].testname,
						elapsed);
					if (opt_verbosity >= 1 &&
					    slots[slot].output_len > 0)
						fwrite(slots[slot].output, 1,
							slots[slot].output_len,
							stdout);
				}
				}
				fflush(stdout);
				par_slot_free_(&slots[slot]);
				running--;
			}
		}
#endif
	}

	if (opt_verbosity == 0)
		puts("");

	if (p_bad)
		printf("%d/%d TESTS FAILED.\n", p_bad, p_bad + p_ok);
	else if (opt_verbosity >= 1)
		printf("%d tests ok.\n", p_ok);

	rc = (p_bad == 0) ? 0 : 1;

out:
	if (slots) {
		for (i = 0; i < njobs; i++) {
#ifdef _WIN32
			if (slots[i].process != NULL) {
				TerminateProcess(slots[i].process, 1);
				WaitForSingleObject(slots[i].process,
					INFINITE);
				CloseHandle(slots[i].process);
				CloseHandle(slots[i].pipe_rd);
			}
#else
			if (slots[i].pid > 0) {
				kill(slots[i].pid, SIGTERM);
				waitpid(slots[i].pid, NULL, 0);
				close(slots[i].pipe_fd);
			}
#endif
			free(slots[i].output);
		}
		free(slots);
	}
	if (tests) {
		for (i = 0; i < ntests; i++)
			free(tests[i]);
		free(tests);
	}
#ifndef _WIN32
	free(pfds);
#endif
	return rc;
}

#endif /* !NO_FORKING */

int
tinytest_main(int c, const char **v, struct testgroup_t *groups)
{
	int i, j, n=0;

#ifdef _WIN32
	const char *sp = strrchr(v[0], '.');
	const char *extension = "";
	if (!sp || stricmp(sp, ".exe"))
		extension = ".exe"; /* Add an exe so CreateProcess will work */
	snprintf(commandname, sizeof(commandname), "%s%s", v[0], extension);
	commandname[MAX_PATH]='\0';
#endif
	for (i=1; i<c; ++i) {
		if (v[i][0] == '-') {
			if (!strcmp(v[i], "--RUNNING-FORKED")) {
				opt_forked = 1;
			} else if (!strcmp(v[i], "--no-fork")) {
				opt_nofork = 1;
			} else if (!strcmp(v[i], "--quiet")) {
				opt_verbosity = -1;
				verbosity_flag = "--quiet";
			} else if (!strcmp(v[i], "-v") || !strcmp(v[i], "--verbose")) {
				opt_verbosity = 2;
				verbosity_flag = "--verbose";
			} else if (!strcmp(v[i], "--terse")) {
				opt_verbosity = 0;
				verbosity_flag = "--terse";
			} else if (!strcmp(v[i], "--help")) {
				usage(groups, 0);
			} else if (!strcmp(v[i], "--list-tests")) {
				usage(groups, 1);
			} else if (!strcmp(v[i], "--timeout")) {
				++i;
				if (i >= c) {
					fprintf(stderr, "--timeout requires argument\n");
					return -1;
				}
				opt_timeout = (unsigned)atoi(v[i]);
			} else if (!strcmp(v[i], "--retries")) {
				++i;
				if (i >= c) {
					fprintf(stderr, "--retries requires argument\n");
					return -1;
				}
				opt_retries = (unsigned)atoi(v[i]);
			} else if (!strcmp(v[i], "--retries-delay")) {
				++i;
				if (i >= c) {
					fprintf(stderr, "--retries-delay requires argument\n");
					return -1;
				}
				opt_retries_delay = (unsigned)atoi(v[i]);
			} else if (!strcmp(v[i], "--repeat")) {
				++i;
				if (i >= c) {
					fprintf(stderr, "--repeat requires argument\n");
					return -1;
				}
				opt_repeat = (unsigned)atoi(v[i]);
			} else if (!strcmp(v[i], "-j") || !strcmp(v[i], "--parallel")) {
				++i;
				if (i >= c) {
					fprintf(stderr, "--parallel requires argument\n");
					return -1;
				}
				opt_parallel = atoi(v[i]);
				if (opt_parallel < 0) {
					fprintf(stderr, "--parallel requires a non-negative number\n");
					return -1;
				}
			} else if (!strncmp(v[i], "-j", 2) && v[i][2] != '\0') {
				opt_parallel = atoi(v[i] + 2);
				if (opt_parallel < 0) {
					fprintf(stderr, "-j requires a non-negative number\n");
					return -1;
				}
			} else {
				fprintf(stderr, "Unknown option %s. Try --help\n", v[i]);
				return -1;
			}
		} else {
			int r = process_test_option(groups, v[i]);
			if (r<0)
				return -1;
			n += r;
		}
	}
	if (!n)
		tinytest_set_flag_(groups, "..", 1, TT_ENABLED_);

#ifdef _IONBF
	setvbuf(stdout, NULL, _IONBF, 0);
#endif

#ifndef NO_FORKING
	/* FIXME: debug win32 issues and enable on CI */
#if 0
	if (opt_parallel < 0) {
		long nproc = 0;
#ifdef _WIN32
		SYSTEM_INFO sysinfo;
		GetSystemInfo(&sysinfo);
		nproc = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_ONLN)
		nproc = sysconf(_SC_NPROCESSORS_ONLN);
#endif
		if (nproc < 1)
			nproc = 1;
		opt_parallel = (int)(nproc * 4);
		if (opt_parallel > 64)
			opt_parallel = 64;
	}
#endif
	if (opt_parallel > 0)
		return run_tests_parallel_(v[0], groups);
#endif

	++in_tinytest_main;
	for (i = 0; groups[i].prefix; ++i) {
		struct testgroup_t *group = &groups[i];
		for (j = 0; group->cases[j].name; ++j) {
			struct testcase_t *testcase = &group->cases[j];
			int retriable = testcase->flags & TT_RETRIABLE;
			int attempts = retriable ? opt_retries : 0;
			int test_ret_err = FAIL;

			if (!(testcase->flags & TT_ENABLED_))
				continue;

			for (unsigned k = 0; k < opt_repeat + 1; ++k) {
				for (;;) {
					test_ret_err = testcase_run_one(group, testcase, attempts);

					if (test_ret_err == OK || test_ret_err == SKIP)
						break;
					if (!attempts--)
						break;
					printf("\n  [RETRYING %s%s (attempts left %i, delay %i sec)]\n", group->prefix, testcase->name, attempts, opt_retries_delay);
#ifdef _WIN32
					Sleep(opt_retries_delay * 1000);
#else
					sleep(opt_retries_delay);
#endif
				}
			}

			switch (test_ret_err) {
				case OK:   ++n_ok;      break;
				case SKIP: ++n_skipped; break;
				default:
					printf("\n  [FAILED %s%s (%i retries)]\n",
						group->prefix, testcase->name, retriable ? opt_retries : 0);
					++n_bad;
					break;
			}
		}
	}

	--in_tinytest_main;

	if (opt_verbosity==0)
		puts("");

	if (n_bad)
		printf("%d/%d TESTS FAILED. (%d skipped)\n", n_bad,
		       n_bad+n_ok,n_skipped);
	else if (opt_verbosity >= 1)
		printf("%d tests ok.  (%d skipped)\n", n_ok, n_skipped);

	return (n_bad == 0) ? 0 : 1;
}

int
tinytest_get_verbosity_(void)
{
	return opt_verbosity;
}

void
tinytest_set_test_failed_(void)
{
	if (opt_verbosity <= 0 && cur_test_name) {
		if (opt_verbosity==0) puts("");
		printf("%s%s: ", cur_test_prefix, cur_test_name);
		cur_test_name = NULL;
	}
	cur_test_outcome = FAIL;
}

void
tinytest_set_test_skipped_(void)
{
	if (cur_test_outcome==OK)
		cur_test_outcome = SKIP;
}

char *
tinytest_format_hex_(const void *val_, unsigned long len)
{
	const unsigned char *val = val_;
	char *result, *cp;
	size_t i;

	if (!val)
		return strdup("null");
	if (!(result = malloc(len*2+1)))
		return strdup("<allocation failure>");
	cp = result;
	for (i=0;i<len;++i) {
		*cp++ = "0123456789ABCDEF"[val[i] >> 4];
		*cp++ = "0123456789ABCDEF"[val[i] & 0x0f];
	}
	*cp = 0;
	return result;
}
