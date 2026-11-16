#!/usr/bin/env bash
# run.sh: set up one live host scenario, audit it with the real binary and
# check the report, then undo the setup.
#
#   STACKWARD=./stackward test/scenarios/run.sh SCENARIO
#   test/scenarios/run.sh list
#
# Scenarios change the machine they run on (containers, UFW, sshd, iptables,
# users). Run them on a GitHub runner or a throwaway VM, never on a server
# you care about. See docs/testing.md.
#
# Reports, traces and the assertion log go to $OUT (default ./scenario-out).
# Exit status: 0 when every assertion held, 1 when one failed, 2 when the
# scenario could not run.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test/scenarios/lib.sh
. "$here/lib.sh"

SCENARIOS="bad-docker hardened-docker socket-proxy ufw ufw-docker ssh read-only non-root apply transaction updates firewall paas-env"

if [ $# -ne 1 ] || [ "$1" = -h ] || [ "$1" = --help ]; then
	sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
fi
if [ "$1" = list ]; then
	# shellcheck disable=SC2086 # a list of names
	printf '%s\n' $SCENARIOS
	exit 0
fi
name="$1"
case " $SCENARIOS " in
*" $name "*) ;;
*) die "unknown scenario $name (one of: $SCENARIOS)" ;;
esac

require_linux_root_tools
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export ASSERT_LOG="$OUT/$name.assertions.tsv"
: >"$ASSERT_LOG"

# shellcheck source=/dev/null
. "$here/$name.sh"

cleanup() {
	local code=$?
	log "cleanup"
	scenario_cleanup || true
	exit "$code"
}
trap cleanup EXIT

log "setup $name"
scenario_setup
apt_caches
log "verify $name"
scenario_verify
summary "$name"
[ "$FAILED" -eq 0 ] || exit 1
