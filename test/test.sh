#!/bin/sh

BACKENDS="EVPORT KQUEUE EPOLL DEVPOLL POLL SELECT WIN32 WEPOLL"
TESTS="test-eof test-closed test-weof test-time test-changelist test-fdleak"
KQUEUE_TESTS="test-kq-collision"
FAILED=no
TEST_OUTPUT_FILE=${TEST_OUTPUT_FILE:-/dev/null}
REGRESS_ARGS=${REGRESS_ARGS:-}

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
TEST_SRC_DIR=.

T=`echo "$0" | sed -e 's/test.sh$//'`
if test -x "$T/test-init"
then
	TEST_DIR="$T"
elif test -x "./test/test-init"
then
        TEST_DIR="./test"
fi
if test -f "$T/check-dumpevents.py"
then
	TEST_SRC_DIR="$T"
elif test -f "./test/check-dumpevents.py"
then
        TEST_SRC_DIR="./test"
fi

setup () {
	for i in $BACKENDS; do
		eval "EVENT_NO$i=yes; export EVENT_NO$i"
	done
	unset EVENT_EPOLL_USE_CHANGELIST
	unset EVENT_PRECISE_TIMER
	unset EVENT_USE_SIGNALFD
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
	backend="$1" && shift
	ALL_TESTS="$TESTS"

	if $TEST_DIR/test-init 2>>"$TEST_OUTPUT_FILE" ;
	then
		announce "Running $backend $*"
	else
		announce "Skipping test $backend $*"
		return
	fi

	if [ "$backend" = "KQUEUE" ]; then
		ALL_TESTS="$ALL_TESTS $KQUEUE_TESTS"
	fi

	for i in $ALL_TESTS; do
		announce_n " $i: "
		if $TEST_DIR/$i >>"$TEST_OUTPUT_FILE" ;
		then
			announce OKAY ;
		else
			announce FAILED ;
			FAILED=yes
		fi
	done
	announce_n " test-dumpevents: "
	if python -c 'import sys; assert(sys.version_info >= (2, 4))' 2>/dev/null && test -f $TEST_SRC_DIR/check-dumpevents.py; then
	    if $TEST_DIR/test-dumpevents | $TEST_SRC_DIR/check-dumpevents.py >> "$TEST_OUTPUT_FILE" ;
	    then
	        announce OKAY ;
	    else
	        announce FAILED ;
	    fi
	else
	    # no python
	    if $TEST_DIR/test-dumpevents >/dev/null; then
	        announce "OKAY (output not checked)" ;
	    else
	        announce "FAILED (output not checked)" ;
	    fi
	fi

	test -x $TEST_DIR/regress || return
	announce_n " regress: "
	if test "$TEST_OUTPUT_FILE" = "/dev/null" ;
	then
		$TEST_DIR/regress --quiet $REGRESS_ARGS
	else
		$TEST_DIR/regress $REGRESS_ARGS >>"$TEST_OUTPUT_FILE"
	fi
	if test "$?" = "0" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi

	announce_n " regress_debug: "
	if test "$TEST_OUTPUT_FILE" = "/dev/null" ;
	then
		EVENT_DEBUG_MODE=1 $TEST_DIR/regress --quiet $REGRESS_ARGS
	else
		EVENT_DEBUG_MODE=1 $TEST_DIR/regress $REGRESS_ARGS >>"$TEST_OUTPUT_FILE"
	fi
	if test "$?" = "0" ;
	then
		announce OKAY ;
	else
		announce FAILED ;
		FAILED=yes
	fi
}

do_test() {
	backend="$1" && shift
	if [ $# -gt 1 ]; then
		backend_conf="$2" && shift
	else
		backend_conf=""
	fi

	setup
	unset EVENT_NO$backend
	if test "$backend_conf" = "(changelist)" ; then
	    EVENT_EPOLL_USE_CHANGELIST=yes; export EVENT_EPOLL_USE_CHANGELIST
	elif test "$backend_conf" = "(timerfd)" ; then
	    EVENT_PRECISE_TIMER=1; export EVENT_PRECISE_TIMER
	elif test "$backend_conf" = "(signalfd)" ; then
	    EVENT_USE_SIGNALFD=1; export EVENT_USE_SIGNALFD
	elif test "$backend_conf" = "(timerfd+changelist)" ; then
	    EVENT_EPOLL_USE_CHANGELIST=yes; export EVENT_EPOLL_USE_CHANGELIST
	    EVENT_PRECISE_TIMER=1; export EVENT_PRECISE_TIMER
	fi

	run_tests "$backend" "$backend_conf"
}

usage()
{
	cat <<EOL
  -b   - specify backends
  -t   - run timerfd test
  -c   - run changelist test
  -T   - run timerfd+changelist test
  -S   - run signalfd test
EOL
}
main()
{
	backends=$BACKENDS
	timerfd=0
	changelist=0
	timerfd_changelist=0
	signalfd=0

	while getopts "b:tcTS" c; do
		case "$c" in
			b) backends="$OPTARG";;
			t) timerfd=1;;
			c) changelist=1;;
			T) timerfd_changelist=1;;
			S) signalfd=1;;
			?*) usage && exit 1;;
		esac
	done

	set -e

	announce "Running tests:"

	[ $timerfd -eq 0 ] || do_test EPOLL "(timerfd)"
	[ $changelist -eq 0 ] || do_test EPOLL "(changelist)"
	[ $timerfd_changelist -eq 0 ] || do_test EPOLL "(timerfd+changelist)"
	for i in $backends; do
		do_test $i
		[ $signalfd -eq 0 ] || do_test $i "(signalfd)"
	done

	if test "$FAILED" = "yes"; then
		exit 1
	fi
}
main "$@"
