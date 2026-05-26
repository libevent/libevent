dnl ######################################################################
dnl liburing support
AC_DEFUN([LIBEVENT_LIBURING], [

case "$enable_liburing" in
 auto|yes)
    case "$have_liburing" in
     yes) ;;
     *)
	save_LIBS="$LIBS"
	LIBS=""
	LIBURING_LIBS=""
	# clear cache
	unset ac_cv_search_io_uring_queue_init
	AC_SEARCH_LIBS([io_uring_queue_init], [uring],
	               [have_liburing=yes
	                LIBURING_LIBS="$LIBS"],
	               [have_liburing=no])
	LIBS="$save_LIBS"
    esac
    CPPFLAGS_SAVE=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $LIBURING_INCS"
    AC_CHECK_HEADERS([liburing.h], [], [have_liburing=no])
    CPPFLAGS=$CPPFLAGS_SAVE
    AC_SUBST(LIBURING_INCS)
    AC_SUBST(LIBURING_LIBS)
    if test "$have_liburing" = "yes" ; then
        AC_DEFINE(HAVE_LIBURING, 1, [Define if the system has liburing])
    elif test "$enable_liburing" = "yes" ; then
        AC_MSG_ERROR([liburing could not be found. You should add the directories \
                      containing liburing.h and liburing to the appropriate \
                      compiler and linker search paths.])
    fi
    ;;
esac

# check if we have and should use liburing
AM_CONDITIONAL(LIBURING, [test "$have_liburing" = "yes"])
])
