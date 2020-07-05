#!/usr/bin/env bash

# Requirements:
# - wdiff
# - rfcdiff
# - universal-ctags
# - abi-tracker
# - abi-monitor
# - git
#
# All of this are included in:
#   docker.pkg.github.com/azat/docker-images/lvc-debian:latest
#
# TODO:
# - move image into libevent namespace

# verify backward compatibility of API/ABI changes

set -e

LIMIT=${1:-2}
EVENT_SOURCE_DIR=${EVENT_SOURCE_DIR:-"$(cd "$(dirname "$0")"/../.. && pwd)"}
ABI_CHECK_ROOT=${ABI_CHECK_ROOT:-$EVENT_SOURCE_DIR/.abi-check}
ABI_CHECK_WORKSPACE=${ABI_CHECK_WORKSPACE:-"work/abi-check"}

mkdir -p "$ABI_CHECK_ROOT/$ABI_CHECK_WORKSPACE"
cd "$ABI_CHECK_ROOT/$ABI_CHECK_WORKSPACE"

# copy current source code and profile into workspace
mkdir -p src/libevent/current
mkdir -p installed/libevent/current
( # to avoid cd back
  cd "$EVENT_SOURCE_DIR"
  # XXX: not `git archive` since it will not copy changes that are not in index,
  # and maybe some issues on CI (since it does not contain full clone)
  find . -maxdepth 1 -mindepth 1 | {
    git check-ignore --no-index --verbose --non-matching --stdin
  } | fgrep :: | cut -f2 | grep -v /.git/ | tee /dev/stderr | {
    xargs cp -r -t "$ABI_CHECK_ROOT/$ABI_CHECK_WORKSPACE/src/libevent/current/"
  }
  cp extra/abi-check/libevent.json "$ABI_CHECK_ROOT/$ABI_CHECK_WORKSPACE/"
)

# run LVC tools
abi-monitor -get -limit "$LIMIT" libevent.json
# XXX: abi-monitor 1.12 supports "-make -j8", but 1.10 does not
# (we can detect which version we have, and add this options)
abi-monitor -v current -build libevent.json
abi-monitor -build libevent.json
abi-tracker -build libevent.json

# remove useless files
rm -rf src installed build_logs libevent.json
