dnl ######################################################################
dnl liburing support
dnl
dnl Detect liburing via pkg-config. 2.4 is the first release that has the
dnl multishot recv APIs (io_uring_setup_buf_ring,
dnl io_uring_prep_recv_multishot, io_uring_prep_cancel_fd, plus the
dnl IORING_ASYNC_CANCEL_ANY constant) the io_uring fast path relies on.
dnl Older liburing on the host is silently ignored unless --enable-liburing
dnl was passed explicitly.
AC_DEFUN([LIBEVENT_LIBURING], [

case "$enable_liburing" in
 auto|yes)
    PKG_CHECK_MODULES([LIBURING], [liburing >= 2.4],
        [have_liburing=yes
         LIBURING_INCS="$LIBURING_CFLAGS"],
        [have_liburing=no])
    AC_SUBST(LIBURING_INCS)
    AC_SUBST(LIBURING_LIBS)
    if test "$have_liburing" = "yes" ; then
        AC_DEFINE(HAVE_LIBURING, 1, [Define if the system has liburing])
    elif test "$enable_liburing" = "yes" ; then
        AC_MSG_ERROR([liburing >= 2.4 could not be found.])
    fi
    ;;
esac

# check if we have and should use liburing
AM_CONDITIONAL(LIBURING, [test "$have_liburing" = "yes"])
])
