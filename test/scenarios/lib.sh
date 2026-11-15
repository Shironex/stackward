# shellcheck shell=bash
# shellcheck disable=SC2034 # constants and FAILED are read by the scenario scripts
# Shared helpers for the scenario scripts. Sourced by run.sh, never run.
#
# Environment:
#   STACKWARD  path to the stackward binary (default: stackward on PATH)
#   OUT        directory for reports, traces and logs (default: ./scenario-out)

SCENARIOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACKWARD="${STACKWARD:-$(command -v stackward || true)}"
OUT="${OUT:-$PWD/scenario-out}"
ASSERT="$SCENARIOS_DIR/assert.sh"

# Images are pinned by tag so a scenario means the same thing on every run.
REDIS_IMAGE="redis:7.4-alpine"
ALPINE_IMAGE="alpine:3.21"
SOCKET_PROXY_IMAGE="tecnativa/docker-socket-proxy:0.3.0"

# Every container and network a scenario creates starts with sw-, and every
# compose project with sw, so cleanup never touches anything else.
SW_CONTAINERS="sw-redis sw-socket sw-priv sw-app sw-web sw-panel sw-socket-proxy"

log() { printf '==> %s\n' "$*"; }

die() {
	printf 'error: %s\n' "$*" >&2
	exit 2
}

# expect runs one assertion and remembers a failure in FAILED; run.sh fails
# the scenario at the end, after every assertion has had its say.
FAILED=0
expect() {
	"$ASSERT" "$@" || FAILED=1
}

# note OK WHAT EXPECTED ACTUAL [DETAIL]: record a result a scenario judged
# itself (exit codes, traces, snapshots) in the same log as assert.sh.
note() {
	local ok="$1" what="$2" expected="$3" actual="$4" detail="${5:-}"
	printf '%s\t%s\t%s\t%s\t%s\n' "$ok" "$what" "$expected" "$actual" "$detail" >>"$ASSERT_LOG"
	if [ "$ok" = yes ]; then
		printf 'PASS %s: %s\n' "$what" "$actual"
	else
		printf 'FAIL %s: expected %s, got %s\n' "$what" "$expected" "$actual"
		FAILED=1
	fi
}

# check_exit NAME CODE: stackward exits 0 or 1 (findings); 2 means the
# tool itself failed.
check_exit() {
	if [ "$2" -gt 1 ]; then
		note no "stackward audit ($1) exit code" "0|1" "$2" "the tool itself failed"
	fi
}

require_linux_root_tools() {
	[ "$(uname -s)" = Linux ] || die "scenarios run on Linux only (a throwaway VM, never a production host)"
	[ -x "$STACKWARD" ] || die "STACKWARD=$STACKWARD is not an executable stackward binary"
	command -v jq >/dev/null || die "jq is required"
	sudo -n true 2>/dev/null || die "passwordless sudo is required"
}

require_docker() {
	command -v docker >/dev/null || die "docker is required for this scenario"
	sudo docker info >/dev/null || die "the Docker daemon is not running"
}

# apt_caches builds apt's binary caches once. Runner images delete them; a
# real server keeps them (apt update rebuilds them). Without them the
# simulated upgrade in the updates collector reparses the lists and needs a
# temporary file the sandbox refuses (see docs/safety.md).
apt_caches() {
	sudo apt-cache gencaches >/dev/null
}

# audit NAME [ARGS...]: run the audit as root with the sandbox on, report to
# $OUT/NAME.json. Exit 1 (findings) is expected; 2 means stackward failed.
audit() {
	local name="$1"
	shift
	local report="$OUT/$name.json" code=0
	log "sudo stackward audit --json $* > $report"
	# The report is written by this shell, as the caller, so jq can read it.
	# shellcheck disable=SC2024
	sudo "$STACKWARD" audit --json "$@" >"$report" || code=$?
	check_exit "$name" "$code"
	REPORT="$report"
	# Every scenario runs under the sandbox as released: a command that needs
	# writes must show up here, not be hidden by --no-sandbox.
	case " $* " in
	*" --no-sandbox "*) ;;
	*) expect sandbox "$REPORT" landlock ;;
	esac
}

docker_rm() {
	local c
	for c in "$@"; do
		sudo docker rm -f "$c" >/dev/null 2>&1 || true
	done
}

# compose runs docker compose with the pinned images in its environment
# (sudo drops the caller's environment).
compose() {
	sudo env ALPINE_IMAGE="$ALPINE_IMAGE" REDIS_IMAGE="$REDIS_IMAGE" docker compose "$@"
}

# compose_up PROJECT FILE: start one compose project from compose/FILE.
compose_up() {
	compose -p "$1" -f "$SCENARIOS_DIR/compose/$2" up -d --quiet-pull
}

# wait_running NAME...: fail early when a container exits instead of
# leaving the audit to judge a stopped container.
wait_running() {
	local c state _
	for c in "$@"; do
		for _ in 1 2 3 4 5 6 7 8 9 10; do
			state="$(sudo docker inspect -f '{{.State.Status}}' "$c" 2>/dev/null || echo missing)"
			[ "$state" = running ] && break
			sleep 1
		done
		if [ "$state" != running ]; then
			sudo docker logs "$c" 2>&1 | tail -20 >&2 || true
			die "container $c is $state, not running"
		fi
	done
}

docker_cleanup() {
	# shellcheck disable=SC2086 # a list of names
	docker_rm $SW_CONTAINERS
	local p
	for p in swa swb; do
		compose -p "$p" down --remove-orphans >/dev/null 2>&1 || true
	done
	sudo docker network rm sw-shared >/dev/null 2>&1 || true
	# DOCKER-USER rules a scenario inserted carry this comment.
	while sudo iptables -S DOCKER-USER 2>/dev/null | grep -q 'stackward-scenario'; do
		local rule
		rule="$(sudo iptables -S DOCKER-USER | grep 'stackward-scenario' | head -1 | sed 's/^-A /-D /')"
		# shellcheck disable=SC2086 # the rule is split into iptables words
		sudo iptables $rule
	done
}

# needs_root_ids prints the ids of checks the catalog marks needs_root.
needs_root_ids() {
	jq -r '.checks[] | select(.needs_root == true) | .id' "$SCENARIOS_DIR"/../../internal/catalog/data/*.json
}
