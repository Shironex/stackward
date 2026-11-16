#!/bin/sh
# A stand in for ssh in the fleet tests. It logs its arguments, then plays
# the remote host on this machine: "uname -m" prints an architecture, any
# other command runs through sh -c the way a login shell would run it, with
# TMPDIR pointing at the test's remote temporary directory.
#
#   FAKE_SSH_LOG   directory that gets one file per call, one argument per line
#   FAKE_SSH_TMP   the remote TMPDIR
#   FAKE_SSH_DOWN  hosts that refuse the connection (space separated)
#   FAKE_SSH_ARM   hosts that are aarch64 (the rest are x86_64)
for a in "$@"; do printf '%s\n' "$a"; done > "$FAKE_SSH_LOG/call.$$"
while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
[ $# -eq 3 ] || { echo "fake ssh: want -- HOST COMMAND, got: $*" >&2; exit 255; }
host=$2
cmd=$3
case " $FAKE_SSH_DOWN " in
*" $host "*)
	echo "ssh: connect to host $host port 22: Connection refused" >&2
	exit 255
	;;
esac
if [ "$cmd" = "uname -m" ]; then
	case " $FAKE_SSH_ARM " in
	*" $host "*) echo aarch64 ;;
	*) echo x86_64 ;;
	esac
	exit 0
fi
TMPDIR=$FAKE_SSH_TMP
FAKE_HOST=$host
export TMPDIR FAKE_HOST
exec sh -c "$cmd"
