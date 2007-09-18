#!/bin/sh
LIBTOOLIZE=libtoolize
if [ "$(uname)" == "Darwin" ] ; then
  LIBTOOLIZE=glibtoolize
fi
aclocal && \
	autoheader && \
	$LIBTOOLIZE && \
	autoconf && \
	automake --add-missing --copy
