#!/bin/sh

FAILED=no

if test "x$TEST_OUTPUT_FILE" = "x"
then
	TEST_OUTPUT_FILE=/dev/null
fi

# /bin/echo is a little more likely to support -n than sh's builtin echo,
# printf is even more likely
if test "`printf %s hello 2>&1`" = "hello"
then
	ECHO_N="printf %s"
else
	if test -x /bin/echo
	then
		ECHO_N="/bin/echo -n"
	else
		ECHO_N="echo -n"
	fi
fi

if test "$TEST_OUTPUT_FILE" != "/dev/null"
then
	touch "$TEST_OUTPUT_FILE" || exit 1
fi

TEST_DIR=.

T=`echo "$0" | sed -e 's/test.sh$//'`
if test -x "$T/test-init"
then
	TEST_DIR="$T"
fi

setup () {
	EVENT_NOKQUEUE=yes; export EVENT_NOKQUEUE
	EVENT_NODEVPOLL=yes; export EVENT_NODEVPOLL
	EVENT_NOPOLL=yes; export EVENT_NOPOLL
	EVENT_NOSELECT=yes; export EVENT_NOSELECT
	EVENT_NOEPOLL=yes; export EVENT_NOEPOLL
	unset EVENT_EPOLL_USE_CHANGELIST
	EVENT_NOEVPORT=yes; export EVENT_NOEVPORT
	EVENT_NOWIN32=yes; export EVENT_NOWIN32
}

announce () {
	echo "$@"
	echo "$@" >>"$TEST_OUTPUT_FILE"
}

announce_n () {
	$ECHO_N "$@"
	echo "$@" >>"$TEST_OUTPUT_FILE"
}


run_tests () {
	if $TEST_DIR/test-init 2>>"$TEST_OUTPUT_FILE" ;
	then
		true
	else
		announce Skipping test
		return
	fi

	announce_n " test-eof: "
	if $TEST_DIR/test-eof >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
	announce_n " test-weof: "
	if $TEST_DIR/test-weof >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
	announce_n " test-time: "
	if $TEST_DIR/test-time >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
	announce_n " test-changelist: "
	if $TEST_DIR/test-changelist >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
	test -x $TEST_DIR/regress || return
	announce_n " regress: "
	if test "$TEST_OUTPUT_FILE" = "/dev/null" ;
	then
		$TEST_DIR/regress --quiet
	else
		$TEST_DIR/regress >>"$TEST_OUTPUT_FILE"
	fi
	if test "$?" = "0" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
}

announce "Running tests:"

# Need to do this by hand?
setup
unset EVENT_NOEVPORT
announce "EVPORT"
run_tests

setup
unset EVENT_NOKQUEUE
announce "KQUEUE"
run_tests

setup
unset EVENT_NOEPOLL
announce "EPOLL"
run_tests

setup
unset EVENT_NOEPOLL
EVENT_EPOLL_USE_CHANGELIST=yes; export EVENT_EPOLL_USE_CHANGELIST
announce "EPOLL (changelist)"
run_tests

setup
unset EVENT_NODEVPOLL
announce "DEVPOLL"
run_tests

setup
unset EVENT_NOPOLL
announce "POLL"
run_tests

setup
unset EVENT_NOSELECT
announce "SELECT"
run_tests

setup
unset EVENT_NOWIN32
announce "WIN32"
run_tests

if test "$FAILED" = "yes"; then
	exit 1
fi
