#!/bin/sh

if test "x$TEST_OUTPUT_FILE" = "x"
then
	TEST_OUTPUT_FILE=/dev/null
fi

touch "$TEST_OUTPUT_FILE" || exit 1

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
	EVENT_NOEVPORT=yes; export EVENT_NOEVPORT
}

announce () {
	echo $@
	echo $@ >>"$TEST_OUTPUT_FILE"
}

run_tests () {
	if $TEST_DIR/test-init 2>>"$TEST_OUTPUT_FILE" ;
	then
		true
	else
		announce Skipping test
		return
	fi

	announce -n " test-eof: "
	if $TEST_DIR/test-eof >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
	fi
	announce -n " test-weof: "
	if $TEST_DIR/test-weof >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
	fi
	announce -n " test-time: "
	if $TEST_DIR/test-time >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
	fi
	announce -n " regress: "
	if $TEST_DIR/regress >>"$TEST_OUTPUT_FILE" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
	fi
}

announce "Running tests:"

# Need to do this by hand?
setup
unset EVENT_NOKQUEUE
export EVENT_NOKQUEUE
announce "KQUEUE"
run_tests

setup
unset EVENT_NODEVPOLL
export EVENT_NODEVPOLL
announce "DEVPOLL"
run_tests

setup
unset EVENT_NOPOLL
export EVENT_NOPOLL
announce "POLL"
run_tests

setup
unset EVENT_NOSELECT
export EVENT_NOSELECT
announce "SELECT"
run_tests

setup
unset EVENT_NOEPOLL
export EVENT_NOEPOLL
announce "EPOLL"
run_tests

setup
unset EVENT_NOEVPORT
export EVENT_NOEVPORT
announce "EVPORT"
run_tests
