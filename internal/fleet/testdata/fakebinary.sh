#!/bin/sh
# Stands in for the copied stackward binary. It records its arguments and
# the mode of its directory, then acts per host:
#   broken*  fails like an audit that could not run (exit 2)
#   killed*  kills the remote script with SIGKILL, so its trap cannot run
#   evil*    sends a report with terminal escape sequences
#   anything else prints the report in $FAKE_REPORT
dir=$(dirname "$0")
echo "$FAKE_HOST $*" >> "$FAKE_BIN_LOG"
ls -ld "$dir" | cut -c1-10 >> "$FAKE_BIN_LOG"
case "$FAKE_HOST" in
broken*)
	echo "stackward audit: something broke" >&2
	exit 2
	;;
killed*)
	kill -9 "$PPID"
	sleep 1
	exit 0
	;;
evil*)
	cat "$FAKE_EVIL_REPORT"
	exit 0
	;;
esac
cat "$FAKE_REPORT"
