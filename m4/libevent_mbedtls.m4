dnl ######################################################################
dnl mbedTLS support
AC_DEFUN([LIBEVENT_MBEDTLS], [

case "$host_os" in
    darwin*)
    dnl when compiling for Darwin, attempt to find mbedTLS using brew.
    dnl We append the location given by brew to PKG_CONFIG_PATH path
    dnl and then export it, so that it can be used in detection below.
    AC_CHECK_PROG([BREW],brew, brew)
    if test x$BREW = xbrew; then
        mbedtls_prefix=$($BREW --prefix mbedtls 2>/dev/null)
        if ! test -d $mbedtls_prefix; then
            mbedtls_prefix=$($BREW --prefix $($BREW list | $GREP -m1 mbedtls) 2>/dev/null)
        fi
        if test x$mbedtls_prefix != x; then
            MBEDTLS_LIBS=`$PKG_CONFIG --libs mbedtls 2>/dev/null`
            case "$MBEDTLS_LIBS" in
             dnl only if mbedtls is not in PKG_CONFIG_PATH already
             '')
                if test x$PKG_CONFIG_PATH != x; then
                    PKG_CONFIG_PATH="$PKG_CONFIG_PATH:"
                fi
                MBEDTLS_PKG_CONFIG="$mbedtls_prefix/lib/pkgconfig"
                PKG_CONFIG_PATH="$PKG_CONFIG_PATH$MBEDTLS_PKG_CONFIG"
                export PKG_CONFIG_PATH
                AC_MSG_NOTICE([PKG_CONFIG_PATH has been set to $PKG_CONFIG_PATH (added mbedtls from brew)])
                ;;
            esac
        fi
    fi
    ;;
esac

case "$enable_mbedtls" in
 yes)
    case "$PKG_CONFIG" in
     '')
        ;;
     *)
        MBEDTLS_LIBS=`$PKG_CONFIG --libs mbedtls 2>/dev/null`
        case "$MBEDTLS_LIBS" in
         '') ;;
         *) MBEDTLS_LIBS="$MBEDTLS_LIBS $EV_LIB_GDI $EV_LIB_WS32 $MBEDTLS_LIBADD"
            have_mbedtls=yes
            ;;
        esac
    MBEDTLS_INCS=`$PKG_CONFIG --cflags openssl 2>/dev/null`
    ;;
    esac

    case "$have_mbedtls" in
     yes) ;;
     *)
	save_LIBS="$LIBS"
	LIBS=""
	MBEDTLS_LIBS=""
    # clear cache
    unset ac_cv_search_mbedtls_ssl_init
    AC_SEARCH_LIBS([mbedtls_ssl_init], [mbedtls],
                   [have_mbedtls=yes
                   MBEDTLS_LIBS="$LIBS -lmbedtls -lmbedcrypto -lmbedx509 $EV_LIB_GDI $EV_LIB_WS32"],
                   [have_mbedtls=no],
                   [-lmbedtls -lmbedcrypto -lmbedx509 $EV_LIB_GDI $EV_LIB_WS32])
    LIBS="$save_LIBS"
    test "$have_mbedtls" = "yes" && break
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
