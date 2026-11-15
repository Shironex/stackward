# shellcheck shell=bash
# shellcheck disable=SC2024 # outputs are written by this shell, as the caller, so they stay readable
# transaction: the access-critical transaction on a real host, with a real
# systemd timer and the machine's own sshd. It needs the scenario binary
# (go build -tags stackward_scenario), the only build that carries the
# test-only access-critical steps: txn-test-sshd writes an sshd drop-in
# with LoginGraceTime 60, txn-test-sshd-bad one that sshd -t refuses.
# Released binaries do not contain them.
#
# The runner has no SSH session, which is what a dropped connection looks
# like to the timer.
#
# 1. plan holds both test steps.
# 2. Validation failure: apply --step txn-test-sshd-bad exits 1, the bad
#    drop-in is gone at once, no timer is left, sshd -t passes and the
#    state is rolled-back (validation) and does not block.
# 3. Rollback by the timer: apply --step txn-test-sshd --confirm-within 30s
#    arms stackward-rollback-ID.timer, writes the drop-in and sshd -T shows
#    logingracetime 60. A second transaction is refused while it is open.
#    confirm without --console is refused (no SSH session). Nobody
#    confirms: the timer fires, the drop-in is gone, sshd -t passes, sshd
#    listens and runs, the state is rolled-back (timer) and access steps
#    are refused until confirm --ack-rollback.
# 4. Confirm: a new transaction, confirm --console ID; the timer is gone and
#    after the deadline the drop-in is still there.

SSHD_DIR=/etc/ssh/sshd_config.d
GOOD=$SSHD_DIR/01-stackward-txn-test.conf
BAD=$SSHD_DIR/01-stackward-txn-test-bad.conf
STATE=/var/lib/stackward/transaction.json
WITHIN=30s

scenario_setup() {
	if ! command -v sshd >/dev/null && [ ! -x /usr/sbin/sshd ]; then
		sudo apt-get install -y -qq openssh-server >/dev/null
	fi
	sudo mkdir -p "$SSHD_DIR"
	grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/' /etc/ssh/sshd_config ||
		die "/etc/ssh/sshd_config does not include sshd_config.d; this scenario needs a stock Ubuntu or Debian sshd"
	# sshd -t needs /run/sshd, which ssh.service creates; with socket
	# activation it may not have run yet.
	sudo systemctl start ssh.service
	sudo "$STACKWARD" version | grep -q . || die "cannot run $STACKWARD"
}

state() { sudo jq -r ".$1 // empty" "$STATE" 2>/dev/null; }

yn() {
	if "$@"; then echo yes; else echo no; fi
}

timer_state() { sudo systemctl is-active "stackward-rollback-$1.timer" 2>/dev/null || true; }

sshd_ok() { sudo /usr/sbin/sshd -t; }

listening22() { sudo ss -Htln | awk '{print $4}' | grep -Eq ':22$'; }

# run_apply NAME ARGS...: apply the plan, output to $OUT/NAME.txt; sets CODE.
run_apply() {
	local name="$1"
	shift
	CODE=0
	log "sudo stackward apply $*"
	sudo "$STACKWARD" apply "$@" "$OUT/plan.json" >"$OUT/$name.txt" 2>&1 || CODE=$?
	cat "$OUT/$name.txt"
}

scenario_verify() {
	local id steps out code
	log "sudo stackward plan --out $OUT/plan.json"
	sudo "$STACKWARD" plan --out "$OUT/plan.json" >"$OUT/plan.txt"
	sudo chmod 0644 "$OUT/plan.json"
	steps="$(jq -r '[.steps[].id] | join(",")' "$OUT/plan.json")"
	note "$(yn grep -q 'txn-test-sshd-bad' <<<"$steps")" "plan holds txn-test-sshd-bad" yes "$steps"
	note "$(yn grep -Eq '(^|,)txn-test-sshd(,|$)' <<<"$steps")" "plan holds txn-test-sshd" yes "$steps"

	# 2. Validation failure rolls back at once.
	run_apply txn-bad --step txn-test-sshd-bad --confirm-within 60s --yes
	id="$(state id)"
	note "$(yn [ "$CODE" -eq 1 ])" "validation failure exit code" 1 "$CODE"
	note "$(yn grep -q 'validation failed' "$OUT/txn-bad.txt")" "says the validation failed" "validation failed" "$(grep -m1 'validation' "$OUT/txn-bad.txt")"
	note "$(yn sudo test ! -e "$BAD")" "the bad drop-in is gone at once" gone "$(sudo test -e "$BAD" && echo present || echo gone)"
	note "$(yn [ "$(state status)/$(state cause)" = rolled-back/validation ])" "state after the validation failure" rolled-back/validation "$(state status)/$(state cause)"
	note "$(yn [ -n "$(state acked_at)" ])" "a validation rollback does not block" acked "$(state acked_at)"
	note "$(yn [ "$(timer_state "$id")" != active ])" "no timer left after the validation failure" inactive "$(timer_state "$id")"
	note "$(yn sshd_ok)" "sshd -t passes after the validation rollback" pass "$(sudo /usr/sbin/sshd -t 2>&1 | head -1)"

	# 3. Nobody confirms: the timer rolls back.
	run_apply txn-timer --step txn-test-sshd --confirm-within "$WITHIN" --yes
	id="$(state id)"
	note "$(yn [ "$CODE" -eq 0 ])" "transaction apply exit code" 0 "$CODE"
	note "$(yn grep -q 'provider console' "$OUT/txn-timer.txt")" "the provider console reminder is printed" printed ""
	note "$(yn [ "$(state status)" = open ])" "state is open" open "$(state status)"
	note "$(yn [ "$(timer_state "$id")" = active ])" "the rollback timer is armed" active "$(timer_state "$id")"
	sudo systemctl list-timers --all "stackward-rollback-*" >"$OUT/timers.txt" 2>&1 || true
	note "$(yn sudo test -f "$GOOD")" "the drop-in is written" present ""
	note "$(yn sh -c "sudo /usr/sbin/sshd -T | grep -qx 'logingracetime 60'")" "sshd -T shows logingracetime 60" 60 "$(sudo /usr/sbin/sshd -T | grep logingracetime)"

	code=0
	out="$(sudo "$STACKWARD" apply --step txn-test-sshd-bad --yes "$OUT/plan.json" 2>&1)" || code=$?
	note "$(yn [ "$code" -eq 2 ])" "a second transaction is refused while one is open" 2 "$code" "$(grep -m1 'only one' <<<"$out")"
	code=0
	out="$(sudo "$STACKWARD" confirm "$id" 2>&1)" || code=$?
	note "$(yn [ "$code" -eq 2 ])" "confirm outside an SSH session without --console is refused" 2 "$code" "$(tail -1 <<<"$out")"
	note "$(yn [ "$(state status)" = open ])" "a refused confirm leaves it open" open "$(state status)"

	log "waiting for the rollback timer (deadline $(state deadline))"
	local waited=0
	while [ "$(state status)" = open ] && [ "$waited" -lt 120 ]; do
		sleep 2
		waited=$((waited + 2))
	done
	sudo journalctl -u "stackward-rollback-$id.service" --no-pager >"$OUT/rollback-service.log" 2>&1 || true
	cat "$OUT/rollback-service.log"
	note "$(yn [ "$(state status)/$(state cause)" = rolled-back/timer ])" "the timer rolled back with no session" rolled-back/timer "$(state status)/$(state cause)" "after ${waited}s"
	note "$(yn sudo test ! -e "$GOOD")" "the rollback removed the drop-in" gone "$(sudo test -e "$GOOD" && echo present || echo gone)"
	note "$(yn sshd_ok)" "sshd -t passes after the rollback" pass "$(sudo /usr/sbin/sshd -t 2>&1 | head -1)"
	note "$(yn listening22)" "port 22 is listened on after the rollback" listening ""
	note "$(yn sudo systemctl is-active --quiet ssh.service)" "ssh.service runs after the rollback" active "$(sudo systemctl is-active ssh.service)"
	note "$(yn [ "$(timer_state "$id")" != active ])" "the timer is gone after it fired" inactive "$(timer_state "$id")"
	note "$(yn [ "$(sudo jq -r .status "/var/backups/stackward/$id/journal.json")" = undone ])" "the journal says undone" undone "$(sudo jq -r .status "/var/backups/stackward/$id/journal.json")"

	run_apply txn-blocked --step txn-test-sshd --yes
	note "$(yn [ "$CODE" -eq 2 ])" "access steps are blocked until the rollback is acknowledged" 2 "$CODE" "$(grep -m1 'ack-rollback' "$OUT/txn-blocked.txt")"
	note "$(yn sudo test ! -e "$GOOD")" "the blocked apply changed nothing" gone ""
	code=0
	sudo "$STACKWARD" confirm --ack-rollback "$id" >"$OUT/ack.txt" 2>&1 || code=$?
	cat "$OUT/ack.txt"
	note "$(yn [ "$code" -eq 0 ])" "confirm --ack-rollback exit code" 0 "$code"

	# 4. Confirm from the console path: the change stays.
	run_apply txn-confirm --step txn-test-sshd --confirm-within "$WITHIN" --yes
	id="$(state id)"
	note "$(yn [ "$CODE" -eq 0 ])" "second transaction apply exit code" 0 "$CODE"
	note "$(yn [ "$(timer_state "$id")" = active ])" "the second timer is armed" active "$(timer_state "$id")"
	code=0
	sudo "$STACKWARD" confirm --console "$id" >"$OUT/confirm.txt" 2>&1 || code=$?
	cat "$OUT/confirm.txt"
	note "$(yn [ "$code" -eq 0 ])" "confirm --console exit code" 0 "$code"
	note "$(yn [ "$(state status)/$(state confirmed_via)" = confirmed/console ])" "state after confirm" confirmed/console "$(state status)/$(state confirmed_via)"
	note "$(yn [ "$(timer_state "$id")" != active ])" "confirm stops the timer" inactive "$(timer_state "$id")"
	log "waiting past the deadline"
	sleep 40
	note "$(yn sudo test -f "$GOOD")" "the confirmed change stays after the deadline" present "$(sudo test -e "$GOOD" && echo present || echo gone)"
	note "$(yn [ "$(state status)" = confirmed ])" "still confirmed after the deadline" confirmed "$(state status)"
	note "$(yn sshd_ok)" "sshd -t passes with the confirmed change" pass ""
}

scenario_cleanup() {
	sudo systemctl stop 'stackward-rollback-*' >/dev/null 2>&1 || true
	sudo rm -f "$GOOD" "$BAD"
	sudo rm -rf /var/lib/stackward /var/backups/stackward
	sudo systemctl try-reload-or-restart ssh.service >/dev/null 2>&1 || true
}
