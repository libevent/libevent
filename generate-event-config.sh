#!/bin/sh

: ${srcdir=$(dirname "$0")}

: ${AWK=awk}
: ${CP=cp}
: ${MV=mv}
: ${SED=sed}

set -eu

private_header="$srcdir/evconfig-private.h.in"
input_file="$srcdir/config.h"
output_file="$1"

tempfile=$(mktemp config.h.XXXXXXXX)
trap 'rm -f $output_file $tempfile' EXIT INT TERM

private_constants=$($SED -E -ne 's/#[[:space:]]*undef[[:space:]]+//p' < "$private_header")

$CP "$input_file" "$tempfile"
for private_constant in $private_constants; do
	$SED -E -i "" \
	     -e 's,^#[[:space:]]*(define|undef)[[:space:]]+('$private_constant')([[:space:]]+.+)*$,/\* #undef \2 \*\/,' \
	     "$tempfile"
done
$SED -f "$srcdir/make-event-config.sed" < "$tempfile" > "$output_file"
rm -f "$tempfile"
trap - EXIT INT TERM
