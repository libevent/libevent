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
#define	timerclear(tvp)	(tvp)->tv_sec = (tvp)->tv_usec = 0
#endif

#undef HAVE_TIMERCMP
#ifndef HAVE_TIMERCMP
#undef timercmp
#define	timercmp(tvp, uvp, cmp)						\
	(((tvp)->tv_sec == (uvp)->tv_sec) ?				\
	 ((tvp)->tv_usec cmp (uvp)->tv_usec) :				\
	 ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif

#undef HAVE_TIMERISSET
#ifndef HAVE_TIMERISSET
#undef timerisset
#define	timerisset(tvp)	((tvp)->tv_sec || (tvp)->tv_usec)
#endif

/* Define if TAILQ_FOREACH is defined in <sys/queue.h> */
#undef HAVE_TAILQFOREACH
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

/* Define to __FUNCTION__ or __file__ if your compiler doesn't have __func__ */
#undef __func__
