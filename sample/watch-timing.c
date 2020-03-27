#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef EVENT__HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/watch.h>

#if !defined(INFINITY)
#define INFINITY (1.0/0.0)
#endif

/**
  An approximate histogram in constant space, based on Ben-Haim & Yom-Tov, "A
  Streaming Parallel Decision Tree Algorithm" [1] and a previous implementation
  in Java by Dan Rosen [2]. The histogram is represented as an array of
  contiguous bins of non-uniform width. Each bin is centered on a certain point,
  called its "centroid," and summarizes some "count" of observations. The bins
  are ordered in the array by their centroids; an array is used rather than a
  linked structure for CPU cache friendliness.

  When the histogram is updated with a new observation, a new bin is created for
  it, and then the pair of bins with the closest centroids are merged. Since
  bins are stored in contiguous memory, this update process requires bins to be
  shifted in worst-case linear time. The novel contribution of this
  implementation is to maintain an insertion gap adjacent to the most recently
  merged bin, such that for "well behaved" input (such as a normal
  distribution), the number of shift operations required by an update should be
  much less than the total number of bins on average.

  This implementation is almost entirely untested. Don't trust it for
  production code.

  [1] http://www.jmlr.org/papers/volume11/ben-haim10a/ben-haim10a.pdf
  [2] https://github.com/mergeconflict/histogram
 */

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wfloat-equal"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfloat-equal"
#endif

/** Compare two doubles for equality without the compiler warning. This is
 * probably the wrong thing to do, but this is just sample code :) */
static inline int
eq(double a, double b)
{
	return a == b;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

struct bin {
	double centroid;
	unsigned long count;
};

struct histogram {
	struct bin *bins;
	unsigned max_bins;
	unsigned num_bins;
	unsigned gap;
	unsigned long count;
	double min;
	double max;
};

static struct histogram *
histogram_new(unsigned max_bins)
{
	struct histogram *h = malloc(sizeof(struct histogram));
	h->bins = calloc(max_bins + 1, sizeof(struct bin));
	h->max_bins = max_bins;
	h->num_bins = 0;
	h->gap = 0;
	h->count = 0;
	h->min = INFINITY;
	h->max = -INFINITY;
	return h;
}

static void
histogram_free(struct histogram *h)
{
	free(h->bins);
	free(h);
}

static void
histogram_update(struct histogram *h, double observation)
{
	unsigned bin;
	double delta;
	double min_delta = INFINITY;

	/* Update population count, min and max */
	++(h->count);
	if (observation < h->min)
		h->min = observation;
	if (observation > h->max)
		h->max = observation;

	/* Shift the insertion gap to the left or right so that the new bin
	 * containing the given observation as its centroid will be in the right
	 * order with respect to the other bins. */
	while (1) {
		/* Look at the bin to the left of the gap... */
		if (h->gap != 0) {
			/* If its centroid is greater than the observation, move
			 * the gap to the left and try again... */
			if (h->bins[h->gap - 1].centroid > observation) {
				h->bins[h->gap] = h->bins[h->gap - 1];
				--(h->gap);
				continue;
			}
			/* If its centroid is equal to the observation, just
			 * update its count in place. */
			if (eq(h->bins[h->gap - 1].centroid, observation)) {
				++(h->bins[h->gap - 1].count);
				return;
			}
		}

		/* Look at the bin to the right of the gap... */
		if (h->gap != h->num_bins) {
			/* If its centroid is less than the observation, move
			 * the gap to the right and try again... */
			if (h->bins[h->gap + 1].centroid < observation) {
				h->bins[h->gap] = h->bins[h->gap + 1];
				++(h->gap);
				continue;
			}
			/* If its centroid is equal to the observation, just
			 * update its count in place. */
			if (eq(h->bins[h->gap + 1].centroid, observation)) {
				++(h->bins[h->gap + 1].count);
				return;
			}
		}

		/* If the gap is in the right place, we're ready to insert. */
		break;
	}

	/* Insert the observation into a new bin at the gap. */
	h->bins[h->gap].centroid = observation;
	h->bins[h->gap].count = 1;

	/* If the histogram isn't full yet, don't bother merging bins, just
	 * stick the gap back at the end. */
	if (h->num_bins != h->max_bins) {
		h->gap = ++(h->num_bins);
		return;
	}

	/* Find the two adjacent bins with the closest centroids and merge them.
	 * The choice whether to leave the gap on the left or right is
	 * arbitrary (we choose the left). */
	for (bin = 0; bin < h->num_bins; ++bin) {
		delta = h->bins[bin + 1].centroid - h->bins[bin].centroid;
		if (delta < min_delta) {
			min_delta = delta;
			h->gap = bin;
		}
	}
	/* The merged centroid is the weighted average of the two, and the
	 * merged count is the sum of the two. */
	h->bins[h->gap + 1].centroid =
		(h->bins[h->gap].centroid * h->bins[h->gap].count +
		 h->bins[h->gap + 1].centroid * h->bins[h->gap + 1].count) /
		(h->bins[h->gap].count + h->bins[h->gap + 1].count);
	h->bins[h->gap + 1].count += h->bins[h->gap].count;
}

static double
histogram_query(const struct histogram *h, double quantile)
{
	unsigned lhs = 0, rhs = 0;
	struct bin lhs_bin = { 0, 0 }, rhs_bin = { 0, 0 };
	double lhs_total = 0, rhs_total = 0;
	double a = 0, b = 0, c = 0, z = 0;

	/* The "needle" is the n'th value represented by the histogram. For
	 * example, if the histogram summarizes 100 entries and we're querying
	 * for the 50th percentile, the needle is 50. */
	double needle = h->count * quantile;
	if (quantile <= 0)
		return h->min;
	if (quantile >= 1)
		return h->max;

	/* Divide the histogram into slices: the first slice starts at h->min
	 * and ends at h->bins[0].centroid, the last slice starts at
	 * h->bins[h->num_bins].centroid and ends at h->max, and the slices
	 * in the middle are between adjacent centroids (minding the gap). The
	 * "count" in each slice is the average of the count in the two bins
	 * that define it. Find the slice containing the needle by keeping a
	 * running total of the slice counts. */
	while (rhs_total < needle) {
		/* Determine the left-hand side bin of the current slice. Note
		 * that the first slice has bin 0 on its right-hand side! */
		if (rhs == 0) {
			lhs_bin.centroid = h->min;
			lhs_bin.count = 0;
		} else {
			lhs_bin = h->bins[lhs];
		}

		/* Determine the right-hand side bin of the current slice... */
		if (rhs > h->num_bins) {
			lhs_bin.centroid = h->max;
			rhs_bin.count = 0;
		} else {
			rhs_bin = h->bins[rhs];
		}

		/* Update the running totals: the lhs total is whatever the rhs
		 * total was previously, and the new rhs total includes the
		 * count for this slice. */
		lhs_total = rhs_total;
		rhs_total += 0.5 * (lhs_bin.count + rhs_bin.count);

		/* Next iteration's left-hand side is the current iteration's
		 * right-hand side, and next iteration's right-hand side is one
		 * bin further right (minding the gap). */
		lhs = rhs++;
		if (rhs == h->gap)
			rhs++;
	}

	/* Approximate the value at the requested quantile... */
	a = rhs_bin.count - lhs_bin.count;
	if (eq(a, 0)) {
		b = rhs_total - lhs_total;
		z = eq(b, 0) ? 0 : (needle - lhs_total) / b;
	} else {
		b = 2 * lhs_bin.count;
		c = 2 * (lhs_total - needle);
		z = (-b + sqrt(b * b - 4 * a * c)) / (2 * a);
	}
	return lhs_bin.centroid + (rhs_bin.centroid - lhs_bin.centroid) * z;
}

/**
  This is an example of one way in which "prepare" and "check" watchers can be
  useful. We track histograms of two timing metrics:

  The first is "duration," which is the amount of time between a "check" and the
  next "prepare" (in the next iteration of the event loop). This corresponds
  pretty closely to the amount of time spent in event handlers (such as the
  `on_timeout` handler in this example). In a real-world server, this would
  provide a way to monitor whether any of your handlers are blocking or
  otherwise performing heavy computation.

  The second is "delay," which is the difference between the actual and expected
  polling duration. The actual polling duration is the amount of time between a
  "prepare" and the next "check" (in the same iteration of the event loop), and
  the expected duration is obtained from `evwatch_prepare_get_timeout`. In a
  real-world server, this provides an indication of kernel scheduling delays.
  For example, if your server is lightly loaded, this delay should usually be
  close to your kernel's scheduling quantum (e.g. 1 millisecond).
 */

static struct event_base *base;
static struct timeval
	prepare_time = { 0, 0 },
	check_time = { 0, 0 },
	expected = { 0, 0 };
static struct histogram *durations, *delays;

static void on_prepare(struct evwatch *watcher, const struct evwatch_prepare_cb_info *info, void *arg)
{
	struct timeval duration;
	evutil_gettimeofday(&prepare_time, NULL);
	evwatch_prepare_get_timeout(info, &expected);
	if (check_time.tv_sec != 0) {
		evutil_timersub(&prepare_time, &check_time, &duration);
		histogram_update(durations, duration.tv_sec + duration.tv_usec / 1000000.0l);
	}
}

static void on_check(struct evwatch *watcher, const struct evwatch_check_cb_info *info, void *arg)
{
	struct timeval actual, delay;
	evutil_gettimeofday(&check_time, NULL);
	evutil_timersub(&check_time, &prepare_time, &actual);
	evutil_timersub(&actual, &expected, &delay);
	if (delay.tv_sec >= 0)
		histogram_update(delays, delay.tv_sec + delay.tv_usec / 1000000.0l);
}

static void
on_timeout(evutil_socket_t fd, short events, void *arg)
{
	printf("durations: [p50 = %fs, p95 = %fs], delays: [p50 = %fs, p95 = %fs]\n",
		histogram_query(durations, 0.5),
		histogram_query(durations, 0.95),
		histogram_query(delays, 0.5),
		histogram_query(delays, 0.95));
}


static void
on_sigint(evutil_socket_t sig, short events, void *arg)
{
	event_base_loopbreak(base);
}

int
main(int argc, char **argv)
{
	struct timeval one_second = { 1, 0 };
	struct event *timeout_event, *sigint_event;

	base = event_base_new();
	durations = histogram_new(100);
	delays = histogram_new(100);

	/* add prepare and check watchers; no need to hang on to their pointers,
	 * since they will be freed for us in event_base_free. */
	evwatch_prepare_new(base, &on_prepare, NULL);
	evwatch_check_new(base, &on_check, NULL);

	/* set a persistent one second timeout */
	timeout_event = event_new(base, -1, EV_PERSIST, &on_timeout, NULL);
	if (!timeout_event)
		return EXIT_FAILURE;
	event_add(timeout_event, &one_second);

	/* set a handler for interrupt, so we can quit cleanly */
	sigint_event = evsignal_new(base, SIGINT, &on_sigint, NULL);
	if (!sigint_event)
		return EXIT_FAILURE;
	event_add(sigint_event, NULL);

	/* run the event loop until interrupted */
	event_base_dispatch(base);

	/* clean up */
	event_free(timeout_event);
	event_free(sigint_event);
	event_base_free(base);
	histogram_free(durations);
	histogram_free(delays);

	return EXIT_SUCCESS;
}
