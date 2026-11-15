# shellcheck shell=bash
# non-root: the same binary run without root, on a host with real state
# (the bad-docker containers).
#
# - As the runner user, who is in the docker group: no collector may
#   crash, the tool must not fail, and the report must say it ran without
#   root. The docker group reaches the Docker socket, so the DKR checks are
#   still judged (and correctly so: the group is root equivalent).
# - As a fresh system user with no groups: every check the catalog marks
#   needs_root must never pass.

# shellcheck source=test/scenarios/bad-docker.sh
. "$SCENARIOS_DIR/bad-docker.sh"

NONROOT_USER=sw-nonroot

scenario_setup() {
	require_docker
	bad_docker_up
	id "$NONROOT_USER" >/dev/null 2>&1 ||
		sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$NONROOT_USER"
	# A copy the plain user can execute, whatever the checkout's modes.
	NONROOT_BIN_DIR="$(mktemp -d)"
	chmod 755 "$NONROOT_BIN_DIR"
	install -m 755 "$STACKWARD" "$NONROOT_BIN_DIR/stackward"
}

# user_audit NAME CMD...: run an audit without root, report to $OUT/NAME.json.
user_audit() {
	local name="$1"
	shift
	local report="$OUT/$name.json" code=0
	log "$* audit --json > $report"
	(cd / && "$@" audit --json) >"$report" || code=$?
	check_exit "$name" "$code"
	REPORT="$report"
	expect field "$REPORT" .coverage.root false
	expect field "$REPORT" '[.coverage.collectors[] | select((.error // "") | test("panic"))] | map(.name) | join(",")' ""
	expect sandbox "$REPORT" landlock
}

scenario_verify() {
	local ids
	mapfile -t ids < <(needs_root_ids)

	user_audit non-root-runner "$NONROOT_BIN_DIR/stackward"
	expect collector "$REPORT" docker ok
	expect check "$REPORT" DKR-021 container:sw-priv fail

	user_audit non-root-plain sudo -u "$NONROOT_USER" "$NONROOT_BIN_DIR/stackward"
	# USR-003 needs root to judge a default cloud account that exists, but
	# "no such account exists" comes from /etc/passwd, which every user
	# reads, so its pass is real.
	local strict=() id
	for id in "${ids[@]}"; do
		[ "$id" = USR-003 ] || strict+=("$id")
	done
	expect none "$REPORT" pass "${strict[@]}"
	expect check "$REPORT" DKR-021 '.*' unknown
	expect check "$REPORT" NET-001 host unknown
	expect check "$REPORT" SSH-001 host 'unknown|skip'
}

scenario_cleanup() {
	docker_cleanup
	if [ -n "${NONROOT_BIN_DIR:-}" ]; then rm -rf "$NONROOT_BIN_DIR"; fi
}
