dnl Copyright 2000-2007 Niels Provos
dnl Copyright 2007-2012 Niels Provos and Nick Mathewson
dnl
dnl See LICENSE for copying information.
dnl
dnl Original version Dug Song <dugsong@monkey.org>

AC_PREREQ([2.67])
AC_INIT(libevent,2.2.1-alpha-dev)
AC_CONFIG_SRCDIR(event.c)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

dnl Automake setup
dnl 'foreign' means that GNU package rules are not strictly enforced.
AM_INIT_AUTOMAKE([1.13 foreign subdir-objects])

dnl make compilation quiet unless V=1 is used
AM_SILENT_RULES([yes])

AC_CONFIG_HEADERS(config.h  evconfig-private.h:evconfig-private.h.in)
AC_DEFINE(NUMERIC_VERSION, 0x02020100, [Numeric representation of the version])

dnl Try and get a full POSIX environment on obscure systems
AC_USE_SYSTEM_EXTENSIONS

dnl the 'build' machine is where we run configure and compile
dnl the 'host' machine is where the resulting stuff runs.
AC_CANONICAL_BUILD
AC_CANONICAL_HOST

dnl Checks for programs.
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_SED

AC_ARG_ENABLE([gcc-warnings],
     AS_HELP_STRING([--disable-gcc-warnings, disable verbose warnings with GCC]))

AC_ARG_ENABLE([gcc-hardening],
     AS_HELP_STRING([--enable-gcc-hardening, enable compiler security checks]),
[if test "$enableval" = "yes"; then
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=3 -fstack-protector-all"
    CFLAGS="$CFLAGS -fwrapv -fPIE -Wstack-protector"
    CFLAGS="$CFLAGS --param ssp-buffer-size=1"
fi])

AC_ARG_ENABLE([thread-support],
    AS_HELP_STRING([--disable-thread-support, disable support for threading]),
	[], [enable_thread_support=yes])
AC_ARG_ENABLE([malloc-replacement],
    AS_HELP_STRING([--disable-malloc-replacement, disable support for replacing the memory mgt functions]),
    [], [enable_malloc_replacement=yes])
AC_ARG_ENABLE([openssl],
     AS_HELP_STRING([--disable-openssl, disable support for openssl encryption]),
    [], [enable_openssl=yes])
AC_ARG_ENABLE([mbedtls],
     AS_HELP_STRING([--disable-mbedtls, disable support for mbedtls encryption]),
    [], [enable_mbedtls=yes])
AC_ARG_ENABLE([debug-mode],
     AS_HELP_STRING([--disable-debug-mode, disable support for running in debug mode]),
    [], [enable_debug_mode=yes])
AC_ARG_ENABLE([libevent-install],
     AS_HELP_STRING([--disable-libevent-install, disable installation of libevent]),
	[], [enable_libevent_install=yes])
AC_ARG_ENABLE([libevent-regress],
     AS_HELP_STRING([--disable-libevent-regress, skip regress in make check]),
	[], [enable_libevent_regress=yes])
AC_ARG_ENABLE([samples],
     AS_HELP_STRING([--disable-samples, skip building of sample programs]),
	[], [enable_samples=yes])
AC_ARG_ENABLE([function-sections],
     AS_HELP_STRING([--enable-function-sections, make static library allow smaller binaries with --gc-sections]),
	[], [enable_function_sections=no])
AC_ARG_ENABLE([verbose-debug],
		AS_HELP_STRING([--enable-verbose-debug, verbose debug logging]),
	[], [enable_verbose_debug=no])
AC_ARG_ENABLE([clock-gettime],
     AS_HELP_STRING([--disable-clock-gettime, do not use clock_gettime even if it is available]),
  [], [enable_clock_gettime=yes])


LT_PREREQ([2.4.2])
LT_INIT

AC_SUBST(LIBTOOL_DEPS)

AM_CONDITIONAL([BUILD_SAMPLES], [test "$enable_samples" = "yes"])
AM_CONDITIONAL([BUILD_REGRESS], [test "$enable_libevent_regress" = "yes"])

dnl Checks for libraries.
AC_SEARCH_LIBS([inet_ntoa], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([inet_aton], [resolv])
if test "$enable_clock_gettime" = "yes"; then
  AC_SEARCH_LIBS([clock_gettime], [rt])
  AC_CHECK_FUNCS([clock_gettime])
fi
AC_SEARCH_LIBS([sendfile], [sendfile])

dnl - check if the macro _WIN32 is defined on this compiler.
dnl - (this is how we check for a windows compiler)
AC_MSG_CHECKING(for WIN32)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([],
    [
#ifndef _WIN32
die horribly
#endif
    ]
  )],
	[bwin32=true; AC_MSG_RESULT(yes)],
	[bwin32=false; AC_MSG_RESULT(no)]
)

dnl - check if the macro __midipix__ is defined on this compiler.
dnl - (this is how we check for a midipix version of GCC)
AC_MSG_CHECKING(for MIDIPIX)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([],
    [
#ifndef __midipix__
die horribly
#endif
    ]
  )],
	[midipix=true; AC_MSG_RESULT(yes)],
	[midipix=false; AC_MSG_RESULT(no)]
)

dnl - check if the macro __CYGWIN__ is defined on this compiler.
dnl - (this is how we check for a cygwin version of GCC)
AC_MSG_CHECKING(for CYGWIN)
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([],
    [
#ifndef __CYGWIN__
die horribly
#endif
    ]
  )],
	[cygwin=true; AC_MSG_RESULT(yes)],
	[cygwin=false; AC_MSG_RESULT(no)]
)

AC_CHECK_HEADERS([zlib.h])

if test "$ac_cv_header_zlib_h" = "yes"; then
dnl Determine if we have zlib for regression tests
dnl Don't put this one in LIBS
save_LIBS="$LIBS"
LIBS=""
ZLIB_LIBS=""
have_zlib=no
AC_SEARCH_LIBS([inflateEnd], [z],
	[have_zlib=yes
	ZLIB_LIBS="$LIBS"
	AC_DEFINE(HAVE_LIBZ, 1, [Define if the system has zlib])])
LIBS="$save_LIBS"
AC_SUBST(ZLIB_LIBS)
fi
AM_CONDITIONAL(ZLIB_REGRESS, [test "$have_zlib" = "yes"])

dnl See if we have openssl.  This doesn't go in LIBS either.
if test "$bwin32" = "true"; then
  EV_LIB_WS32=-lws2_32
  EV_LIB_GDI=-lgdi32
else
  EV_LIB_WS32=
  EV_LIB_GDI=
fi
AC_SUBST(EV_LIB_WS32)
AC_SUBST(EV_LIB_GDI)
AC_SUBST(OPENSSL_LIBADD)

AC_SYS_LARGEFILE

LIBEVENT_OPENSSL
LIBEVENT_MBEDTLS

dnl Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h ifaddrs.h mach/mach_time.h mach/mach.h netdb.h netinet/in.h netinet/in6.h netinet/tcp.h sys/un.h poll.h port.h stdarg.h stddef.h sys/devpoll.h sys/epoll.h sys/event.h sys/eventfd.h sys/ioctl.h sys/mman.h sys/param.h sys/queue.h sys/resource.h sys/select.h sys/sendfile.h sys/socket.h sys/stat.h sys/time.h sys/timerfd.h sys/signalfd.h sys/uio.h sys/wait.h sys/random.h errno.h afunix.h])

case "${host_os}" in
    linux*) ;;
    *)
        AC_CHECK_HEADERS(sys/sysctl.h, [], [], [
        #ifdef HAVE_SYS_PARAM_H
        #include <sys/param.h>
        #endif
        ])
esac

if test "$ac_cv_header_sys_queue_h" = "yes"; then
	AC_MSG_CHECKING(for TAILQ_FOREACH in sys/queue.h)
	AC_EGREP_CPP(yes,
[
#include <sys/queue.h>
#ifdef TAILQ_FOREACH
 yes
#endif
],	[AC_MSG_RESULT(yes)
	 AC_DEFINE(HAVE_TAILQFOREACH, 1,
		[Define if TAILQ_FOREACH is defined in <sys/queue.h>])],
	AC_MSG_RESULT(no)
	)
fi

dnl if we have sys/time.h, check for timer* macros
if test "$ac_cv_header_sys_time_h" = "yes"; then

AC_MSG_CHECKING(for timeradd in sys/time.h)
AC_EGREP_CPP(yes, [
    #include <sys/time.h>
    #ifdef timeradd
     yes
    #endif],
    [AC_MSG_RESULT(yes); AC_DEFINE(HAVE_TIMERADD, 1, [Define if timeradd is defined in <sys/time.h>])],
    [AC_MSG_RESULT(no)]
)

AC_MSG_CHECKING(for timercmp in sys/time.h)
AC_EGREP_CPP(yes, [
    #include <sys/time.h>
    #ifdef timercmp
     yes
    #endif],
    [AC_MSG_RESULT(yes); AC_DEFINE(HAVE_TIMERCMP, 1,[Define if timercmp is defined in <sys/time.h>])],
    [AC_MSG_RESULT(no)]
)

AC_MSG_CHECKING(for timerclear in sys/time.h)
AC_EGREP_CPP(yes, [
    #include <sys/time.h>
    #ifdef timerclear
     yes
    #endif],
    [AC_MSG_RESULT(yes); AC_DEFINE(HAVE_TIMERCLEAR, 1, [Define if timerclear is defined in <sys/time.h>])],
    [AC_MSG_RESULT(no)]
)

AC_MSG_CHECKING(for timerisset in sys/time.h)
AC_EGREP_CPP(yes, [
    #include <sys/time.h>
    #ifdef timerisset
     yes
    #endif],
    [AC_MSG_RESULT(yes); AC_DEFINE(HAVE_TIMERISSET, 1, [Define if timerisset is defined in <sys/time.h>])],
    [AC_MSG_RESULT(no)]
)
fi

if test "$ac_cv_header_sys_sysctl_h" = "yes"; then
	AC_CHECK_DECLS([CTL_KERN, KERN_ARND], [], [],
	   [[#include <sys/types.h>
	     #include <sys/sysctl.h>]]
	)
fi

AM_CONDITIONAL(BUILD_WIN32, test "$bwin32" = "true")
AM_CONDITIONAL(BUILD_CYGWIN, test "$cygwin" = "true")
AM_CONDITIONAL(BUILD_MIDIPIX, test "$midipix" = "true")
AM_CONDITIONAL(BUILD_WITH_NO_UNDEFINED, test x$bwin32 = xtrue || test x$cygwin = xtrue || test x$midipix = xtrue)

if test "$bwin32" = "true"; then
  AC_CHECK_LIB([ws2_32], [main])
fi

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

dnl Checks for library functions.
AC_CHECK_FUNCS([accept4 arc4random arc4random_buf arc4random_addrandom eventfd epoll_create1 epoll_pwait2 fcntl getegid geteuid getifaddrs gettimeofday issetugid mach_absolute_time mmap nanosleep pipe pipe2 pread putenv sendfile setenv setrlimit sigaction signal strsignal strlcpy strsep strtok_r strtoll sysctl timerfd_create umask unsetenv usleep getrandom mmap64])

AS_IF([test "$bwin32" = "true"],
  AC_CHECK_FUNCS(_gmtime64_s, , [AC_CHECK_FUNCS(_gmtime64)])
)

AM_CONDITIONAL(STRLCPY_IMPL, [test "$ac_cv_func_strlcpy" = "no"])

m4_define([funcstochk], [getnameinfo getprotobynumber getservbyname inet_ntop inet_pton])

AS_IF([test "$bwin32" = "true"],
  [AX_CHECK_DECLS_EX([funcstochk getaddrinfo],
    [#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #endif])],
  [AC_CHECK_FUNCS(m4_normalize(funcstochk))]
)

m4_undefine([funcstochk])

dnl check getaddrinfo and gethostbyname_r for non-windows
AS_IF([test x$bwin32 = xfalse], [
AC_CACHE_CHECK(
    [for getaddrinfo],
    [libevent_cv_getaddrinfo],
    [AC_LINK_IFELSE(
	[AC_LANG_PROGRAM(
	    [[
		#ifdef HAVE_NETDB_H
		#include <netdb.h>
		#endif
	    ]],
	    [[
		getaddrinfo;
	    ]]
	)],
	[libevent_cv_getaddrinfo=yes],
	[libevent_cv_getaddrinfo=no]
    )]
)
if test "$libevent_cv_getaddrinfo" = "yes" ; then
    AC_DEFINE([HAVE_GETADDRINFO], [1], [Do we have getaddrinfo()?])
else

dnl Check for gethostbyname_r in all its glorious incompatible versions.
dnl   (This is cut-and-pasted from Tor, which based its logic on
dnl   Python's configure.in.)
AH_TEMPLATE(HAVE_GETHOSTBYNAME_R,
  [Define this if you have any gethostbyname_r()])

AC_CHECK_FUNC(gethostbyname_r, [
  AC_MSG_CHECKING([how many arguments gethostbyname_r() wants])
  OLD_CFLAGS=$CFLAGS
  CFLAGS="$CFLAGS $MY_CPPFLAGS $MY_THREAD_CPPFLAGS $MY_CFLAGS"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <netdb.h>
  ], [[
    char *cp1, *cp2;
    struct hostent *h1, *h2;
    int i1, i2;
    (void)gethostbyname_r(cp1,h1,cp2,i1,&h2,&i2);
  ]])],[
    AC_DEFINE(HAVE_GETHOSTBYNAME_R)
    AC_DEFINE(HAVE_GETHOSTBYNAME_R_6_ARG, 1,
     [Define this if gethostbyname_r takes 6 arguments])
    AC_MSG_RESULT(6)
  ], [
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <netdb.h>
    ], [
      char *cp1, *cp2;
      struct hostent *h1;
      int i1, i2;
      (void)gethostbyname_r(cp1,h1,cp2,i1,&i2);
    ])], [
      AC_DEFINE(HAVE_GETHOSTBYNAME_R)
      AC_DEFINE(HAVE_GETHOSTBYNAME_R_5_ARG, 1,
        [Define this if gethostbyname_r takes 5 arguments])
      AC_MSG_RESULT(5)
    ], [
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([
#include <netdb.h>
     ], [
       char *cp1;
       struct hostent *h1;
       struct hostent_data hd;
       (void) gethostbyname_r(cp1,h1,&hd);
     ])], [
       AC_DEFINE(HAVE_GETHOSTBYNAME_R)
       AC_DEFINE(HAVE_GETHOSTBYNAME_R_3_ARG, 1,
         [Define this if gethostbyname_r takes 3 arguments])
       AC_MSG_RESULT(3)
     ], [
       AC_MSG_RESULT(0)
     ])
  ])
 ])
 CFLAGS=$OLD_CFLAGS
])

fi
]) dnl end of checking getaddrinfo and gethostbyname_r

AC_MSG_CHECKING(for F_SETFD in fcntl.h)
AC_EGREP_CPP(yes,
[
#define _GNU_SOURCE 1
#include <fcntl.h>
#ifdef F_SETFD
yes
#endif
],	[ AC_DEFINE(HAVE_SETFD, 1,
	      [Define if F_SETFD is defined in <fcntl.h>])
	  AC_MSG_RESULT(yes) ], AC_MSG_RESULT(no))

needsignal=no
haveselect=no
if test "$bwin32" != "true"; then
    AC_CHECK_FUNCS(select, [haveselect=yes], )
    if test "$haveselect" = "yes" ; then
 	needsignal=yes
    fi
fi
AM_CONDITIONAL(SELECT_BACKEND, [test "$haveselect" = "yes"])

havepoll=no
AC_CHECK_FUNCS(poll, [havepoll=yes], )
if test "$havepoll" = "yes" ; then
	needsignal=yes
fi
AM_CONDITIONAL(POLL_BACKEND, [test "$havepoll" = "yes"])

havedevpoll=no
if test "$ac_cv_header_sys_devpoll_h" = "yes"; then
	AC_DEFINE(HAVE_DEVPOLL, 1,
		    [Define if /dev/poll is available])
fi
AM_CONDITIONAL(DEVPOLL_BACKEND, [test "$ac_cv_header_sys_devpoll_h" = "yes"])

havekqueue=no
if test "$ac_cv_header_sys_event_h" = "yes"; then
	AC_CHECK_FUNCS(kqueue, [havekqueue=yes], )
	if test "$havekqueue" = "yes" ; then
		AC_MSG_CHECKING(for working kqueue)
		AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
        ], [[
	int kq;
	int n;
	int fd[2];
	struct kevent ev;
	struct timespec ts;
	char buf[80000];

	if (pipe(fd) == -1)
  		return 1;
	if (fcntl(fd[1], F_SETFL, O_NONBLOCK) == -1)
		return 1;

	while ((n = write(fd[1], buf, sizeof(buf))) == sizeof(buf))
		;

	if ((kq = kqueue()) == -1)
		return 1;

	memset(&ev, 0, sizeof(ev));
	ev.ident = fd[1];
	ev.filter = EVFILT_WRITE;
	ev.flags = EV_ADD | EV_ENABLE;
	n = kevent(kq, &ev, 1, NULL, 0, NULL);
	if (n == -1)
		return 1;

	read(fd[0], buf, sizeof(buf));

	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	n = kevent(kq, NULL, 0, &ev, 1, &ts);
	if (n == -1 || n == 0)
		return 1;

	return 0;
        ]]
      )],
      [AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_WORKING_KQUEUE, 1,
        [Define if kqueue works correctly with pipes])
      havekqueue=yes
      ], [AC_MSG_RESULT(no)], [AC_MSG_RESULT(no)]
    )
	fi
fi
AM_CONDITIONAL(KQUEUE_BACKEND, [test "$havekqueue" = "yes"])

haveepollsyscall=no
haveepoll=no
AC_CHECK_FUNCS(epoll_ctl, [haveepoll=yes], )
if test "$haveepoll" = "yes" ; then
	AC_DEFINE(HAVE_EPOLL, 1,
		[Define if your system supports the epoll system calls])
	needsignal=yes
fi
if test "$ac_cv_header_sys_epoll_h" = "yes"; then
	if test "$haveepoll" = "no" ; then
		AC_MSG_CHECKING(for epoll system call)
		AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([[
#include <stdint.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <unistd.h>

int
epoll_create(int size)
{
	return (syscall(__NR_epoll_create, size));
}
        ]],[[
	int epfd;

	epfd = epoll_create(256);
	return (epfd == -1 ? 1 : 0);
        ]]
      )], 
      [AC_MSG_RESULT(yes)
      AC_DEFINE(HAVE_EPOLL, 1,
	      [Define if your system supports the epoll system calls])
      needsignal=yes
      have_epoll=yes
      AC_LIBOBJ(epoll_sub)
      ], [AC_MSG_RESULT(no)], [AC_MSG_RESULT(no)]
    )
	fi
fi
AM_CONDITIONAL(EPOLL_BACKEND, [test "$haveepoll" = "yes"])

haveeventports=no
AC_CHECK_FUNCS(port_create, [haveeventports=yes], )
if test "$haveeventports" = "yes" ; then
	AC_DEFINE(HAVE_EVENT_PORTS, 1,
		[Define if your system supports event ports])
	needsignal=yes
fi
AM_CONDITIONAL(EVPORT_BACKEND, [test "$haveeventports" = "yes"])

havewepoll=no
if test "$bwin32" = "true"; then
	needsignal=yes
  if test "$cygwin" = "false"; then
    havewepoll=yes
    AC_DEFINE(HAVE_WEPOLL, 1,
      [Define if your system supports the wepoll module])
  fi
fi
AM_CONDITIONAL(WEPOLL_BACKEND, [test "$havewepoll" = "yes"])
AM_CONDITIONAL(SIGNAL_SUPPORT, [test "$needsignal" = "yes"])
AM_CONDITIONAL(SIGNALFD_SUPPORT, [test "$ac_cv_header_sys_signalfd_h" = "yes"])

AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

AC_CHECK_TYPES([uint64_t, uint32_t, uint16_t, uint8_t, uintptr_t], , ,
[#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined(HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif])

AC_CHECK_TYPES([fd_mask], , ,
[#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif])

AC_CHECK_SIZEOF(long long)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(void *)
AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(time_t)

AC_CHECK_TYPES([struct in6_addr, struct sockaddr_in6, struct sockaddr_un, sa_family_t, struct addrinfo, struct sockaddr_storage], , ,
[#define _GNU_SOURCE 1
#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef _WIN32
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#if defined(_MSC_VER) && (_MSC_VER < 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif
])
AC_CHECK_MEMBERS([struct in6_addr.s6_addr32, struct in6_addr.s6_addr16, struct sockaddr_in.sin_len, struct sockaddr_in6.sin6_len, struct sockaddr_storage.ss_family, struct sockaddr_storage.__ss_family], , ,
[#include <sys/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef _WIN32
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#if defined(_MSC_VER) && (_MSC_VER < 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif
])

AC_CHECK_TYPES([struct linger],,,
[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif
])

AC_MSG_CHECKING([for socklen_t])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([
 #include <sys/types.h>
 #ifdef _WIN32
 #include <ws2tcpip.h>
 #else
 #include <sys/socket.h>
 #endif
    ],[socklen_t x;]
  )],
	[AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
  AC_DEFINE(socklen_t, unsigned int,
	  [Define to unsigned int if you dont have it])]
)

dnl __func__/__FUNCTION__ is not a macros in general
AC_MSG_CHECKING([whether our compiler supports __func__])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([],
    [ const char *cp = __func__; ]
  )],
	[ AC_DEFINE(HAVE___func__, 1, [Define to 1 if compiler have __func__])
    AC_MSG_RESULT([yes])
  ],
  [AC_MSG_RESULT([no])]
)
AC_MSG_CHECKING([whether our compiler supports __FUNCTION__])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM([],
    [ const char *cp = __FUNCTION__; ]
  )],
	[ AC_DEFINE(HAVE___FUNCTION__, 1, [Define to 1 if compiler have __FUNCTION__])
    AC_MSG_RESULT([yes])
  ],
  [AC_MSG_RESULT([no])]
)

dnl check if we can compile with pthreads
have_pthreads=no
if test "$bwin32" != "true" && test "$enable_thread_support" != "no"; then
  AX_PTHREAD([
    AC_DEFINE([HAVE_PTHREADS], [1], [Define if we have pthreads on this system])
    have_pthreads=yes
  ])
  CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
  AC_CHECK_SIZEOF([pthread_t], [], [AC_INCLUDES_DEFAULT() #include <pthread.h> ])
  AC_CHECK_FUNCS([pthread_mutexattr_setprotocol])
fi
AM_CONDITIONAL(THREADS, [test "$enable_thread_support" != "no"])
AM_CONDITIONAL(PTHREADS, [test "$have_pthreads" != "no" && test "$enable_thread_support" != "no"])

dnl check if we should compile locking into the library
if test "$enable_thread_support" = "no"; then
   AC_DEFINE(DISABLE_THREAD_SUPPORT, 1,
	[Define if libevent should not be compiled with thread support])
fi

dnl check if we should hard-code the mm functions.
if test "$enable_malloc_replacement" = "no"; then
  AC_DEFINE(DISABLE_MM_REPLACEMENT, 1,
        [Define if libevent should not allow replacing the mm functions])
fi

dnl check if we should hard-code debugging out
if test "$enable_debug_mode" = "no"; then
  AC_DEFINE(DISABLE_DEBUG_MODE, 1,
        [Define if libevent should build without support for a debug mode])
fi

dnl check if we should enable verbose debugging
if test "$enable_verbose_debug" = "yes"; then
	CFLAGS="$CFLAGS -DUSE_DEBUG"
fi

dnl check if we have and should use OpenSSL
AM_CONDITIONAL(OPENSSL, [test "$enable_openssl" != "no" && test "$have_openssl" = "yes"])

# check if we have and should use mbedtls
AM_CONDITIONAL(MBEDTLS, [test "$enable_mbedtls" != "no" && test "$have_mbedtls" = "yes"])

dnl enable some warnings by default
AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"],[],[-Werror])

dnl Disable the strict-aliasing optimization, since it breaks
dnl our sockaddr-handling code in strange ways.
dnl See 52eb4951302554dd696d6a0120ad5d3f6cffb7bb.
AX_CHECK_COMPILE_FLAG([-fno-strict-aliasing], [CFLAGS="$CFLAGS -fno-strict-aliasing"],[],[-Werror])

dnl Add warnings which we use in development but not for releases.
if test "$enable_gcc_warnings" != "no" && test "$GCC" = "yes"; then

  dnl -W is the same as -Wextra
  AX_CHECK_COMPILE_FLAG([-W], [CFLAGS="$CFLAGS -W"],[],[-Werror])

  dnl The AX_CHECK_COMPILE_FLAG macro ignores warnings, so -Werror is used
  dnl to convert warnings into errors and prevent the addition of unknown flags.
  AX_CHECK_COMPILE_FLAG([-Waddress],[CFLAGS="$CFLAGS -Waddress"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wbad-function-cast],[CFLAGS="$CFLAGS -Wbad-function-cast"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wdeclaration-after-statement],[CFLAGS="$CFLAGS -Wdeclaration-after-statement"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wfloat-equal],[CFLAGS="$CFLAGS -Wfloat-equal"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Winit-self],[CFLAGS="$CFLAGS -Winit-self"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wlogical-op],[CFLAGS="$CFLAGS -Wlogical-op"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wmissing-declarations],[CFLAGS="$CFLAGS -Wmissing-declarations"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wmissing-field-initializers],[CFLAGS="$CFLAGS -Wmissing-field-initializers"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wmissing-prototypes],[CFLAGS="$CFLAGS -Wmissing-prototypes"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wnested-externs],[CFLAGS="$CFLAGS -Wnested-externs"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wnormalized=id],[CFLAGS="$CFLAGS -Wnormalized=id"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Woverride-init],[CFLAGS="$CFLAGS -Woverride-init"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wpointer-arith],[CFLAGS="$CFLAGS -Wpointer-arith"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wredundant-decls],[CFLAGS="$CFLAGS -Wredundant-decls"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wstrict-prototypes],[CFLAGS="$CFLAGS -Wstrict-prototypes"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wundef],[CFLAGS="$CFLAGS -Wundef"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wwrite-strings],[CFLAGS="$CFLAGS -Wwrite-strings"],[],[-Werror])

  dnl Convert warnings into errors
  if test "$enable_gcc_warnings" = "yes"; then
    AX_CHECK_COMPILE_FLAG([-Werror], [CFLAGS="$CFLAGS -Werror"])
  fi

  dnl Disable warnings for unused parameters
  AX_CHECK_COMPILE_FLAG([-Wunused-parameter], [CFLAGS="$CFLAGS -Wno-unused-parameter"],[],[-Werror])
  AX_CHECK_COMPILE_FLAG([-Wvoid-pointer-to-enum-cast], [CFLAGS="$CFLAGS -Wno-void-pointer-to-enum-cast"],[],[-Werror])

  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [
  #if !defined(__clang__)
  #error
  #endif])], have_clang=yes, have_clang=no)

   dnl Disable unused-function warnings. These trigger for minheap-internal.h.
   AX_CHECK_COMPILE_FLAG([-Wno-unused-function], [CFLAGS="$CFLAGS -Wno-unused-function"],[],[-Werror])

   dnl Disable unknown pragmas warnings.
   AX_CHECK_COMPILE_FLAG([-Wno-pragmas], [CFLAGS="$CFLAGS -Wno-pragmas"],[],[-Werror])

   dnl Disable Variable Lenght Array
   AX_CHECK_COMPILE_FLAG([-Wvla], [CFLAGS="$CFLAGS -Wvla"],[],[-Werror])

  if test "$have_clang" = "yes"; then
    case "$host_os" in
      darwin*)
        dnl Clang on macOS emits warnings for each directory specified which
        dnl isn't "used", generating a lot of build noise.
        AX_CHECK_COMPILE_FLAG([-Qunused-arguments], [CFLAGS="$CFLAGS -Qunused-arguments"],[],[-Werror])
    esac
  fi
fi

LIBEVENT_GC_SECTIONS=
if test "$GCC" = yes && test "$enable_function_sections" = yes ; then
    AC_CACHE_CHECK(
	[if linker supports omitting unused code and data],
	[libevent_cv_gc_sections_runs],
	[
	    dnl  NetBSD will link but likely not run with --gc-sections
	    dnl  http://bugs.ntp.org/1844
	    dnl  http://gnats.netbsd.org/40401
	    dnl  --gc-sections causes attempt to load as linux elf, with
	    dnl  wrong syscalls in place.  Test a little gauntlet of
	    dnl  simple stdio read code checking for errors, expecting
	    dnl  enough syscall differences that the NetBSD code will
	    dnl  fail even with Linux emulation working as designed.
	    dnl  A shorter test could be refined by someone with access
	    dnl  to a NetBSD host with Linux emulation working.
	    origCFLAGS="$CFLAGS"
	    CFLAGS="$CFLAGS -Wl,--gc-sections"
	    AC_LINK_IFELSE(
		[AC_LANG_PROGRAM(
		    [[
			#include <stdlib.h>
			#include <stdio.h>
		    ]],
		    [[
			FILE *	fpC;
			char	buf[32];
			size_t	cch;
			int	read_success_once;

			fpC = fopen("conftest.c", "r");
			if (NULL == fpC)
				exit(1);
			do {
				cch = fread(buf, sizeof(buf), 1, fpC);
				read_success_once |= (0 != cch);
			} while (0 != cch);
			if (!read_success_once)
				exit(2);
			if (!feof(fpC))
				exit(3);
			if (0 != fclose(fpC))
				exit(4);

			exit(EXIT_SUCCESS);
		    ]]
		)],
		[
                    dnl We have to do this invocation manually so that we can
                    dnl get the output of conftest.err to make sure it doesn't
                    dnl mention gc-sections.
		    if test "$cross_compiling" = "yes" || grep gc-sections conftest.err ; then
			libevent_cv_gc_sections_runs=no
		    else
			libevent_cv_gc_sections_runs=no
			./conftest >/dev/null 2>&1 && libevent_cv_gc_sections_runs=yes
		    fi
		],
		[libevent_cv_gc_sections_runs=no]
	    )
	    CFLAGS="$origCFLAGS"
	    AS_UNSET([origCFLAGS])
	]
    )
    case "$libevent_cv_gc_sections_runs" in
     yes)
	CFLAGS="-ffunction-sections -fdata-sections $CFLAGS"
	LIBEVENT_GC_SECTIONS="-Wl,--gc-sections"
	;;
    esac
fi
AC_SUBST([LIBEVENT_GC_SECTIONS])

AM_CONDITIONAL([INSTALL_LIBEVENT], [test "$enable_libevent_install" = "yes"])

AC_C_BIGENDIAN([CFLAGS="$CFLAGS -DBIG_ENDIAN"], [CFLAGS="$CFLAGS -DLITTLE_ENDIAN"])

dnl Doxygen support
DX_HTML_FEATURE(ON)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_INIT_DOXYGEN([libevent], [${top_srcdir}/Doxyfile], [doxygen])

AM_CONDITIONAL([ENABLE_DOXYGEN], [test "$DX_FLAG_doc" = "1"])
AM_CONDITIONAL([ENABLE_DOXYGEN_MAN], [test "$DX_FLAG_man" = "1"])

AC_CONFIG_FILES([Makefile libevent.pc libevent_mbedtls.pc libevent_openssl.pc libevent_pthreads.pc libevent_core.pc libevent_extra.pc] )
AC_OUTPUT
