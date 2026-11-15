# shellcheck shell=bash
# non-root: the same binary run without root, on a host with real state
# (the bad-docker containers).
#
# - As the runner user, who is in the docker group: no collector may
#   crash, the tool must not fail, and the report must say it ran without
#   root. The docker group reaches the Docker socket, so the DKR checks are
#   still judged (and correctly so: the group is root equivalent).
# - As a fresh system user with no groups: no check the catalog marks
#   needs_root may pass blind. needs_root means "may be unknown without
#   root", not "never passes": on some images every sshd file is world
#   readable, so a pass from the files is legitimate. The rule compares
#   with a root audit of the same host: a pass without root is a false pass
#   only when root judges it fail or warn, or it says "not inspected".

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
	local plain="$REPORT"
	audit non-root-as-root
	expect nofalsepass "$plain" "$REPORT" "${ids[@]}"
	REPORT="$plain"
	expect check "$REPORT" DKR-021 '.*' unknown
	expect check "$REPORT" NET-001 host unknown
}

scenario_cleanup() {
	docker_cleanup
	if [ -n "${NONROOT_BIN_DIR:-}" ]; then rm -rf "$NONROOT_BIN_DIR"; fi
}
