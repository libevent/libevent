#include <stdlib.h>
#include <stdio.h>

#include <string.h>

#include <locale.h>

#include <unistd.h>

#include <dlfcn.h>

#include <err.h>

#include "timeout.h"
#include "bench.h"

#ifndef countof
#define countof(a) (sizeof (a) / sizeof *(a))
#endif


struct {
	const char *path;
	void *solib;
	size_t count;
	timeout_t maximum;
	int verbose;

	struct timeout *timeout;
	struct vops vops;
	timeout_t curtime;
} MAIN = {
	.path = "bench-wheel.so",
	.count = 32678,
	.maximum = 60000, // 60 seconds in milliseconds
};


static int split(char **argv, int max, char *src) {
	char **ap = argv, **pe = argv + max;

	while (ap < pe && (*ap = strsep(&src, " \t\n"))) {
		if (**ap)
			++ap;
	}

	return ap - argv;
} /* split() */


struct op *parseop(struct op *op, char *ln) {
	char *arg[8];
	int argc;

	if (!(argc = split(arg, countof(arg), ln)))
		return NULL;

	switch (**arg) {
	case 'q': /* quit */
		op->type = OP_QUIT;

		break;
	case 'h': /* help */
		op->type = OP_HELP;

		break;
	case 'a': /* add */
		if (argc != 3)
			goto badargc;

		op->type = OP_ADD;
		op->add.id = strtoul(arg[1], NULL, 0) % MAIN.count;
		op->add.timeout = strtoul(arg[2], NULL, 0);

		break;
	case 'd': /* del */
		if (argc != 2)
			goto badargc;

		op->type = OP_DEL;
		op->del.id = strtoul(arg[1], NULL, 0) % MAIN.count;

		break;
	case 'g': /* get */
		op->type = OP_GET;
		op->get.verbose = (argc > 1)? strtol(arg[1], NULL, 0) : 0;

		break;
	case 's': /* step */
		if (argc != 2)
			goto badargc;

		op->type = OP_STEP;
		op->step.time = strtoul(arg[1], NULL, 0);

		break;
	case 'u': /* update */
		if (argc != 2)
			goto badargc;

		op->type = OP_UPDATE;
		op->update.time = strtoul(arg[1], NULL, 0);

		break;
	case 'c': /* check */
		op->type = OP_CHECK;

		break;
	case 'f': /* fill */
		op->type = OP_FILL;

		break;
	case '#':
		/* FALL THROUGH */
	case 'n':
		op->type = OP_NONE;

		break;
	default:
		op->type = OP_OOPS;
		snprintf(op->oops.why, sizeof op->oops.why, "%.8s: illegal op", *arg);

		break;
	} /* switch() */

	return op;
badargc:
	op->type = OP_OOPS;
	snprintf(op->oops.why, sizeof op->oops.why, "wrong number of arguments");

	return op;
} /* parseop() */


#define SHORT_OPTS "n:t:vh"
static void usage(FILE *fp) {
	fprintf(fp,
		"bench [-%s] LIBRARY\n" \
		"  -n MAX  maximum number of timeouts\n" \
		"  -t MAX  maximum timeout\n" \
		"  -v      increase log level\n" \
		"  -h      print usage message\n" \
		"\n" \
		"[commands]\n" \
		"  help    print usage message\n" \
		"  quit    exit program\n" \
		"\n" \
		"Report bugs to <william@25thandClement.com>\n",
	SHORT_OPTS);
} /* usage() */


int main(int argc, char **argv) {
	extern char *optarg;
	extern int optind;
	int optc;
	struct vops *vops;
	char cmd[256];
	struct op op;

	setlocale(LC_ALL, "C");

	while (-1 != (optc = getopt(argc, argv, SHORT_OPTS))) {
		switch (optc) {
		case 'n':
			MAIN.count = strtoul(optarg, NULL, 0);

			break;
		case 't':
			MAIN.maximum = (strtod(optarg, NULL) * TIMEOUT_mHZ);

			break;
		case 'v':
			MAIN.verbose++;

			break;
		case 'h':
			usage(stdout);

			return 0;
		default:
			usage(stderr);

			return 1;
		} /* switch() */
	} /* while() */

	argv += optind;
	argc -= optind;

	if (argc > 0) {
		MAIN.path = *argv++;
		--argc;
	}

	if (!(MAIN.timeout = calloc(MAIN.count, sizeof *MAIN.timeout)))
		err(1, "calloc");

	if (!(MAIN.solib = dlopen(MAIN.path, RTLD_NOW|RTLD_LOCAL)))
		errx(1, "%s: %s", MAIN.path, dlerror());

	if (!(vops = dlsym(MAIN.solib, "VOPS")))
		errx(1, "%s: %s", MAIN.path, dlerror());

	MAIN.vops = *vops;
	MAIN.vops.init(MAIN.timeout, MAIN.count, MAIN.verbose);

	while (fgets(cmd, sizeof cmd, stdin) && parseop(&op, cmd)) {
		struct timeout *to;
		unsigned n;

		switch (op.type) {
		case OP_QUIT:
			goto quit;
		case OP_HELP:
			usage(stdout);

			break;
		case OP_ADD:
			to = &MAIN.timeout[op.add.id];
			MAIN.vops.add(to, op.add.timeout);

			break;
		case OP_DEL:
			to = &MAIN.timeout[op.del.id];
			MAIN.vops.del(to);

			break;
		case OP_GET:
			n = 0;

			while ((to = MAIN.vops.get())) {
				if (op.get.verbose > 1)
					printf("#%ld expired (%llu >= %llu)\n", to - MAIN.timeout, to->expires, MAIN.curtime);
				n++;
			}

			if (op.get.verbose)
				printf("expired %u\n", n);

			break;
		case OP_STEP:
			MAIN.curtime += op.step.time;
			MAIN.vops.update(MAIN.curtime);

			break;
		case OP_UPDATE:
			MAIN.curtime = op.update.time;
			MAIN.vops.update(MAIN.curtime);

			break;
		case OP_CHECK:
			MAIN.vops.check();

			break;
		case OP_FILL:
			for (to = MAIN.timeout; to < &MAIN.timeout[MAIN.count]; to++) {
				MAIN.vops.add(to, random() % MAIN.maximum);
			}

			break;
		case OP_NONE:
			break;
		case OP_OOPS:
			errx(1, "oops: %s", op.oops.why);

			break;
		}
	} /* while() */

quit:
	return 0;
} /* main() */
