dnl ######################################################################
dnl mbedtls support
AC_DEFUN([LIBEVENT_MBEDTLS], [
AC_REQUIRE([NTP_PKG_CONFIG])dnl

case "$enable_mbedtls" in
 yes)
    case "$have_mbedtls" in
     yes) ;;
     *)
	save_LIBS="$LIBS"
	LIBS=""
	MBEDTLS_LIBS=""
	for lib in mbedtls ; do
		# clear cache
		unset ac_cv_search_mbedtls_ssl_init
		AC_SEARCH_LIBS([mbedtls_ssl_init], [mbedtls ],
		    [have_mbedtls=yes
		    MBEDTLS_LIBS="$LIBS -l$lib -lmbedcrypto -lmbedx509 $EV_LIB_GDI $EV_LIB_WS32 $MBEDTLS_LIBADD"],
		    [have_mbedtls=no],
		    [-l$lib $EV_LIB_GDI $EV_LIB_WS32 $MBEDTLS_LIBADD])
		LIBS="$save_LIBS"
		test "$have_mbedtls" = "yes" && break
	done
	;;
    esac
    CPPFLAGS_SAVE=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $MBEDTLS_INCS"
    AC_CHECK_HEADERS([mbedtls/ssl.h], [], [have_mbedtls=no])
    CPPFLAGS=$CPPFLAGS_SAVE
    AC_SUBST(MBEDTLS_INCS)
    AC_SUBST(MBEDTLS_LIBS)
    case "$have_mbedtls" in
     yes)  AC_DEFINE(HAVE_MBEDTLS, 1, [Define if the system has mbedtls]) ;;
    esac
    ;;
esac

# check if we have and should use mbedtls
AM_CONDITIONAL(MBEDTLS, [test "$enable_mbedtls" != "no" && test "$have_mbedtls" = "yes"])
])
