#!/bin/sh

setup () {
	 export EVENT_NOKQUEUE=yes
	 export EVENT_NOPOLL=yes
	 export EVENT_NOSELECT=yes
	 export EVENT_NOEPOLL=yes
	 export EVENT_NORTSIG=yes
}

test () {
	if ! ./test-init 2>/dev/null ;
	then
		echo Skipping test
		return
	fi	

echo -n " test-eof: "
if ./test-eof >/dev/null ; 
then 
	echo OKAY ; 
else 
	echo FAILED ; 
fi
echo -n " test-weof: "
if ./test-weof >/dev/null ; 
then 
	echo OKAY ; 
else 
	echo FAILED ; 
fi
echo -n " test-time: "
if ./test-time >/dev/null ; 
then 
	echo OKAY ; 
else 
	echo FAILED ; 
fi
echo -n " regress: "
if ./regress >/dev/null ; 
then 
	echo OKAY ; 
else 
	echo FAILED ; 
fi
}

echo "Running tests:"

# Need to do this by hand?
setup
unset EVENT_NOKQUEUE
echo "KQUEUE"
test

setup
unset EVENT_NOPOLL
echo "POLL"
test

setup
unset EVENT_NOSELECT
echo "SELECT"
test

setup
unset EVENT_NORTSIG
echo "RTSIG"
test

setup
unset EVENT_NOEPOLL
echo "EPOLL"
test



