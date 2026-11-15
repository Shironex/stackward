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
#    The boot unit stackward-boot-rollback-ID.service is installed and
#    enabled while it is open, passes systemd-analyze verify, and the
#    timer's rollback removes it.
# 4. Confirm: a new transaction, confirm --console ID; the timer and the
#    boot unit are gone and after the deadline the drop-in is still there.
# 5. Reboot: a new transaction (deadline 5m). A boot is replayed: the
#    transient timer is stopped (a reboot drops it), sshd is stopped (at
#    boot it has not started yet), then the boot unit and ssh.service are
#    started together, as systemd does at boot; the ordering makes sshd
#    wait for the rollback. It rolls back (cause boot), removes itself,
#    sshd starts with the restored config (sshd -t passes, logingracetime
#    is back to 120), and access steps are refused until
#    confirm --ack-rollback.
# 6. A boot unit left over without an open transaction makes apply refuse
#    access steps, with the fix printed.

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

boot_unit() { echo "/etc/systemd/system/stackward-boot-rollback-$1.service"; }

boot_enabled() { sudo systemctl is-enabled "stackward-boot-rollback-$1.service" 2>/dev/null || true; }

# boot_unit_installed ID WHEN: the boot unit is there, enabled and valid.
boot_unit_installed() {
	local id="$1" when="$2" code=0
	note "$(yn sudo test -f "$(boot_unit "$id")")" "the boot unit is written $when" present ""
	note "$(yn [ "$(boot_enabled "$id")" = enabled ])" "the boot unit is enabled $when" enabled "$(boot_enabled "$id")"
	sudo systemd-analyze verify "$(boot_unit "$id")" >"$OUT/verify-$id.txt" 2>&1 || code=$?
	cat "$OUT/verify-$id.txt"
	note "$(yn [ "$code" -eq 0 ])" "systemd-analyze verify passes on the boot unit" 0 "$code" "$(head -3 "$OUT/verify-$id.txt")"
}

# boot_unit_gone ID WHEN: the boot unit and its link are removed.
boot_unit_gone() {
	local id="$1" when="$2"
	note "$(yn sudo test ! -e "$(boot_unit "$id")")" "the boot unit is removed $when" gone "$(sudo test -e "$(boot_unit "$id")" && echo present || echo gone)"
	note "$(yn [ "$(boot_enabled "$id")" != enabled ])" "the boot unit is not enabled $when" "not enabled" "$(boot_enabled "$id")"
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
	boot_unit_installed "$id" "while open"

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
	boot_unit_gone "$id" "by the timer's rollback"
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
	boot_unit_gone "$id" "by confirm"
	log "waiting past the deadline"
	sleep 40
	note "$(yn sudo test -f "$GOOD")" "the confirmed change stays after the deadline" present "$(sudo test -e "$GOOD" && echo present || echo gone)"
	note "$(yn [ "$(state status)" = confirmed ])" "still confirmed after the deadline" confirmed "$(state status)"
	note "$(yn sshd_ok)" "sshd -t passes with the confirmed change" pass ""

	verify_boot_rollback
	verify_stale_boot_unit
}

# 5. The host reboots while a transaction is open.
verify_boot_rollback() {
	local id code
	# The confirmed drop-in from step 4 would make the step a no-op.
	sudo rm -f "$GOOD"
	sudo systemctl try-reload-or-restart ssh.service
	run_apply txn-boot --step txn-test-sshd --confirm-within 5m --yes
	id="$(state id)"
	note "$(yn [ "$CODE" -eq 0 ] && [ "$(state status)" = open ])" "the boot transaction is open" 0/open "$CODE/$(state status)"
	boot_unit_installed "$id" "for the boot transaction"
	replay_boot "$id"
	note "$(yn [ "$(state status)/$(state cause)" = rolled-back/boot ])" "the boot unit rolled back" rolled-back/boot "$(state status)/$(state cause)"
	note "$(yn sudo test ! -e "$GOOD")" "the boot rollback removed the drop-in" gone "$(sudo test -e "$GOOD" && echo present || echo gone)"
	boot_unit_gone "$id" "by itself after the boot rollback"
	note "$(yn sshd_ok)" "sshd -t passes after the boot rollback" pass "$(sudo /usr/sbin/sshd -t 2>&1 | head -1)"
	note "$(yn listening22)" "port 22 is listened on after the boot rollback" listening ""
	note "$(yn sudo systemctl is-active --quiet ssh.service)" "ssh.service runs after the boot rollback" active "$(sudo systemctl is-active ssh.service)"
	note "$(yn sh -c "sudo /usr/sbin/sshd -T | grep -qx 'logingracetime 120'")" "sshd runs with the restored setting" 120 "$(sudo /usr/sbin/sshd -T | grep logingracetime)"
	note "$(yn [ -z "$(state acked_at)" ])" "a boot rollback needs an acknowledgement" unacked "$(state acked_at)"
	run_apply txn-boot-blocked --step txn-test-sshd --yes
	note "$(yn [ "$CODE" -eq 2 ])" "access steps are blocked after the boot rollback" 2 "$CODE" "$(grep -m1 'ack-rollback' "$OUT/txn-boot-blocked.txt")"
	code=0
	sudo "$STACKWARD" confirm --ack-rollback "$id" >"$OUT/ack-boot.txt" 2>&1 || code=$?
	cat "$OUT/ack-boot.txt"
	note "$(yn [ "$code" -eq 0 ])" "confirm --ack-rollback after the boot rollback" 0 "$code"
}

# replay_boot ID: what a reboot does to an open transaction. The transient
# timer is gone and sshd has not started; the boot unit and ssh.service
# start in one go, and the boot unit's ordering makes ssh.service wait.
replay_boot() {
	local id="$1" socket=no code=0 status_at_ssh
	log "replaying a boot: the transient timer goes, sshd is down, the boot unit and sshd start together"
	sudo systemctl stop "stackward-rollback-$id.timer"
	note "$(yn [ "$(timer_state "$id")" != active ])" "the transient timer is gone, as after a reboot" inactive "$(timer_state "$id")"
	if sudo systemctl is-active --quiet ssh.socket; then
		socket=yes
		sudo systemctl stop ssh.socket
	fi
	sudo systemctl stop ssh.service
	sudo systemctl start --no-block "stackward-boot-rollback-$id.service"
	sudo timeout 300 systemctl start ssh.service || code=$?
	status_at_ssh="$(state status)"
	if [ "$socket" = yes ]; then
		sudo systemctl start ssh.socket
	fi
	sudo journalctl -u "stackward-boot-rollback-$id.service" --no-pager >"$OUT/boot-rollback.log" 2>&1 || true
	cat "$OUT/boot-rollback.log"
	note "$(yn [ "$code" -eq 0 ])" "ssh.service starts after the boot unit" 0 "$code"
	note "$(yn [ "$status_at_ssh" = rolled-back ])" "the rollback is done when ssh.service has started" rolled-back "$status_at_ssh"
	note "$(yn grep -q 'stackward-boot-rollback-.*Deactivated successfully' "$OUT/boot-rollback.log")" "the boot unit ran to the end" finished "$(tail -1 "$OUT/boot-rollback.log")"
}

# 6. A boot unit left over without an open transaction.
verify_stale_boot_unit() {
	local stale
	stale="$(boot_unit 20260301T120000Z-abcdef)"
	printf '[Unit]\nDescription=left over by a test\n' | sudo tee "$stale" >/dev/null
	run_apply txn-stale --step txn-test-sshd --yes
	note "$(yn [ "$CODE" -eq 2 ])" "a left over boot unit blocks access steps" 2 "$CODE" "$(grep -m1 'left over' "$OUT/txn-stale.txt")"
	note "$(yn grep -q 'sudo rm -f' "$OUT/txn-stale.txt")" "the fix is printed" printed ""
	note "$(yn sudo test ! -e "$GOOD")" "the refused apply changed nothing" gone ""
	sudo rm -f "$stale"
}

scenario_cleanup() {
	sudo systemctl stop 'stackward-rollback-*' >/dev/null 2>&1 || true
	sudo rm -f /etc/systemd/system/stackward-boot-rollback-*.service /etc/systemd/system/sysinit.target.wants/stackward-boot-rollback-*.service
	sudo systemctl daemon-reload || true
	sudo rm -f "$GOOD" "$BAD"
	sudo rm -rf /var/lib/stackward /var/backups/stackward
	sudo systemctl try-reload-or-restart ssh.service >/dev/null 2>&1 || true
}
