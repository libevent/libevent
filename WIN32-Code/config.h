/* config.h.in.  Generated automatically from configure.in by autoheader.  */
/* Define if kqueue works correctly with pipes */
#undef HAVE_WORKING_KQUEUE

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
#undef u_int64_t

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
#undef u_int32_t

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
#undef u_int16_t

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
#undef u_int8_t

/* Define if timeradd is defined in <sys/time.h> */
#undef HAVE_TIMERADD
#ifndef HAVE_TIMERADD
#undef timersub
#define timeradd(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
		if ((vvp)->tv_usec >= 1000000) {			\
			(vvp)->tv_sec++;				\
			(vvp)->tv_usec -= 1000000;			\
		}							\
	} while (0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* !HAVE_TIMERADD */

#undef HAVE_TIMERCLEAR
#ifndef HAVE_TIMERCLEAR
#define	timerclear(tvp)		(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

#define HAVE_TIMERCMP
#ifndef HAVE_TIMERCMP
#undef timercmp
#define	timercmp(tvp, uvp, cmp)						\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	    ((tvp)->tv_usec cmp (uvp)->tv_usec) :			\
	    ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#undef HAVE_TIMERISSET
#ifndef HAVE_TIMERISSET
#undef timerisset
#define	timerisset(tvp)		((tvp)->tv_sec || (tvp)->tv_usec)
#endif

/* Define if TAILQ_FOREACH is defined in <sys/queue.h> */
#define HAVE_TAILQFOREACH
#ifndef HAVE_TAILQFOREACH
#define	TAILQ_FIRST(head)		((head)->tqh_first)
#define	TAILQ_END(head)			NULL
#define	TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define TAILQ_FOREACH(var, head, field)					\
	for((var) = TAILQ_FIRST(head);					\
	    (var) != TAILQ_END(head);					\
	    (var) = TAILQ_NEXT(var, field))
#define	TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (0)
#endif /* TAILQ_FOREACH */

/* Define if /dev/poll is available */
#undef HAVE_DEVPOLL

/* Define if your system supports the epoll system calls */
#undef HAVE_EPOLL

/* Define if you have the `epoll_ctl' function. */
#undef HAVE_EPOLL_CTL

/* Define if you have the `err' function. */
#undef HAVE_ERR

/* Define if you have the `fcntl' function. */
#undef HAVE_FCNTL

/* Define if you have the <fcntl.h> header file. */
#undef HAVE_FCNTL_H

/* Define if you have the `gettimeofday' function. */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define if you have the `kqueue' function. */
#undef HAVE_KQUEUE

/* Define if you have the `socket' library (-lsocket). */
#undef HAVE_LIBSOCKET

/* Define if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define if you have the `poll' function. */
#undef HAVE_POLL

/* Define if you have the <poll.h> header file. */
#undef HAVE_POLL_H

/* Define if your system supports POSIX realtime signals */
#undef HAVE_RTSIG

/* Define if you have the `select' function. */
#undef HAVE_SELECT

/* Define if F_SETFD is defined in <fcntl.h> */
#undef HAVE_SETFD

/* Define if you have the <signal.h> header file. */
#undef HAVE_SIGNAL_H

/* Define if you have the `sigtimedwait' function. */
#undef HAVE_SIGTIMEDWAIT

/* Define if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define if you have the <stdint.h> header file. */
#undef HAVE_STDINT_H

/* Define if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define if you have the <strings.h> header file. */
#undef HAVE_STRINGS_H

/* Define if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have the <sys/devpoll.h> header file. */
#undef HAVE_SYS_DEVPOLL_H

/* Define if you have the <sys/epoll.h> header file. */
#undef HAVE_SYS_EPOLL_H

/* Define if you have the <sys/event.h> header file. */
#undef HAVE_SYS_EVENT_H

/* Define if you have the <sys/ioctl.h> header file. */
#undef HAVE_SYS_IOCTL_H

/* Define if you have the <sys/queue.h> header file. */
#undef HAVE_SYS_QUEUE_H

/* Define if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file. */
#undef HAVE_SYS_TIME_H

/* Define if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define if TAILQ_FOREACH is defined in <sys/queue.h> */
#undef HAVE_TAILQFOREACH

/* Define if timeradd is defined in <sys/time.h> */
#undef HAVE_TIMERADD

/* Define if you have the <unistd.h> header file. */
#undef HAVE_UNISTD_H

/* Define if you have the `vasprintf' function. */
#undef HAVE_VASPRINTF

/* Define if kqueue works correctly with pipes */
#undef HAVE_WORKING_KQUEUE

/* Define if realtime signals work on pipes */
#undef HAVE_WORKING_RTSIG

/* Name of package */
#define PACKAGE "libevent"

/* Define if you have the ANSI C header files. */
#undef STDC_HEADERS

/* Define if you can safely include both <sys/time.h> and <time.h>. */
#undef TIME_WITH_SYS_TIME

/* Version number of package */
#define VERSION "1.0b"

/* Define to empty if `const' does not conform to ANSI C. */
#undef const

/* Define as `__inline' if that's what the C compiler calls it, or to nothing
   if it is not supported. */
#define inline __inline

/* Define to `int' if <sys/types.h> does not define. */
#undef pid_t

/* Define to `unsigned' if <sys/types.h> does not define. */
#undef size_t

/* Define to unsigned int if you dont have it */
#undef socklen_t

/* Define to `unsigned short' if <sys/types.h> does not define. */
#undef u_int16_t

/* Define to `unsigned int' if <sys/types.h> does not define. */
#undef u_int32_t

/* Define to `unsigned long long' if <sys/types.h> does not define. */
/* #undef u_int64_t */

/* Define to `unsigned char' if <sys/types.h> does not define. */
/* #undef u_int8_t */

/* Define to __FUNCTION__ or __file__ if your compiler doesn't have __func__ */
#define __func__ __FUNCTION__
