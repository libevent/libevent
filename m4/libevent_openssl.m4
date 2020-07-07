dnl ######################################################################
dnl OpenSSL support
AC_DEFUN([LIBEVENT_OPENSSL], [
AC_REQUIRE([NTP_PKG_CONFIG])dnl

case "$host_os" in
    darwin*)
    dnl when compiling for Darwin, attempt to find OpenSSL using brew.
    dnl We append the location given by brew to PKG_CONFIG_PATH path
    dnl and then export it, so that it can be used in detection below.
    AC_CHECK_PROG([BREW],brew, brew)
    if test x$BREW = xbrew; then
        openssl_prefix=$($BREW --prefix openssl 2>/dev/null)
        if test xopenssl_prefix != x; then
            PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$openssl_prefix/lib/pkgconfig"
            export PKG_CONFIG_PATH
        fi
    fi
    ;;
esac

case "$enable_openssl" in
 yes)
    have_openssl=no
    case "$PKG_CONFIG" in
     '')
	;;
     *)
	OPENSSL_LIBS=`$PKG_CONFIG --libs openssl 2>/dev/null`
	case "$OPENSSL_LIBS" in
	 '') ;;
	 *) OPENSSL_LIBS="$OPENSSL_LIBS $EV_LIB_GDI $EV_LIB_WS32 $OPENSSL_LIBADD"
	    have_openssl=yes
	    ;;
	esac
	OPENSSL_INCS=`$PKG_CONFIG --cflags openssl 2>/dev/null`
	;;
    esac
    case "$have_openssl" in
     yes) ;;
     *)
	save_LIBS="$LIBS"
	LIBS=""
	OPENSSL_LIBS=""
	for lib in crypto eay32; do
		dnl clear cache
		unset ac_cv_search_SSL_new
		AC_SEARCH_LIBS([SSL_new], [ssl ssl32],
		    [have_openssl=yes
		    OPENSSL_LIBS="$LIBS -l$lib $EV_LIB_GDI $EV_LIB_WS32 $OPENSSL_LIBADD"],
		    [have_openssl=no],
		    [-l$lib $EV_LIB_GDI $EV_LIB_WS32 $OPENSSL_LIBADD])
		LIBS="$save_LIBS"
		test "$have_openssl" = "yes" && break
	done
	;;
    esac
    CPPFLAGS_SAVE=$CPPFLAGS
    CPPFLAGS="$CPPFLAGS $OPENSSL_INCS"
    AC_CHECK_HEADERS([openssl/ssl.h], [], [have_openssl=no])
    CPPFLAGS=$CPPFLAGS_SAVE
    AC_SUBST(OPENSSL_INCS)
    AC_SUBST(OPENSSL_LIBS)
    case "$have_openssl" in
     yes)  AC_DEFINE(HAVE_OPENSSL, 1, [Define if the system has openssl]) ;;
     *) AC_MSG_ERROR([OpenSSL could not be found. You should add the directory \
     containing 'openssl.pc' to the 'PKG_CONFIG_PATH' environment variable, set \
     'CFLAGS' and 'LDFLAGS' directly, or use '--disable-openssl' to disable \
     support for OpenSSL encryption])
	;;
    esac
    ;;
esac

dnl check if we have and should use OpenSSL
AM_CONDITIONAL(OPENSSL, [test "$enable_openssl" != "no" && test "$have_openssl" = "yes"])
])
