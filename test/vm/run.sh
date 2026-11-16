#!/usr/bin/env bash
# run.sh: run one VM scenario against the VM test/vm/vm.sh booted. Every
# step reaches the VM over a new SSH session from this host, the way an
# owner works on a server: apply in one session, confirm from another,
# and a fresh login proves what still works.
#
#   test/vm/run.sh SCENARIO
#   test/vm/run.sh list
#
# The scenarios let stackward change sshd, UFW and accounts inside the VM.
# Run them only against a VM vm.sh booted, never against a real server.
# See docs/testing.md.
#
# Results go to $OUT (default ./vm-scenario-out). Exit status: 0 when every
# assertion held, 1 when one failed, 2 when the scenario could not run.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
VM_DIR="${VM_DIR:-$PWD/vm-out}"
OUT="${OUT:-$PWD/vm-scenario-out}"
# shellcheck source=test/scenarios/lib.sh
. "$here/../scenarios/lib.sh"
[ -f "$VM_DIR/vm.env" ] || die "no VM: boot one with test/vm/vm.sh boot DISTRO SEED"
# shellcheck source=test/vm/lib.sh
. "$here/lib.sh"

# Each scenario and the cloud-init seed it boots with.
SCENARIOS="rollback:users confirm:users guard:users accounts:accounts"

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
*" $name:$VM_SEED "*) ;;
*" $name:"*) die "scenario $name needs a VM booted with another seed (see run.sh list)" ;;
*) die "unknown scenario $name (run.sh list)" ;;
esac
command -v jq >/dev/null || die "jq is required"
command -v curl >/dev/null || die "curl is required"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export ASSERT_LOG="$OUT/$name.assertions.tsv"
: >"$ASSERT_LOG"

# shellcheck source=/dev/null
. "$here/$name.sh"

trap 'collect_vm' EXIT
log "scenario $name on $VM_DISTRO ($VM_ACCEL)"
prepare_vm
scenario_verify
summary "$name ($VM_DISTRO)"
[ "$FAILED" -eq 0 ] || exit 1
