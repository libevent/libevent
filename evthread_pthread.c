#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
struct event_base;
#include <event2/thread.h>

#include "mm-internal.h"

static void *
evthread_posix_lock_create(void)
{
	pthread_mutex_t *lock = mm_malloc(sizeof(pthread_mutex_t));
	if (!lock)
		return NULL;
	pthread_mutex_init(lock, NULL);
	return lock;
}

static void
evthread_posix_lock_free(void *_lock)
{
	pthread_mutex_t *lock = _lock;
	pthread_mutex_destroy(lock);
	mm_free(lock);
}

static void
evthread_posix_lock(int mode, void *_lock)
{
	pthread_mutex_t *lock = _lock;
	if (0 != (mode & EVTHREAD_LOCK))
		pthread_mutex_lock(lock);
	else
		pthread_mutex_unlock(lock);
}

static unsigned long
evthread_posix_get_id(void)
{
	union {
		pthread_t thr;
		unsigned long id;
	} r;
	r.thr = pthread_self();
	return r.id;
}

int
evthread_use_pthreads(struct event_base *base)
{
	evthread_set_lock_create_callbacks(base,
									   evthread_posix_lock_create,
									   evthread_posix_lock_free);
	evthread_set_locking_callback(base, evthread_posix_lock);
	evthread_set_id_callback(base, evthread_posix_get_id);
	return -1;
}
