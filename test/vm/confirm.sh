# shellcheck shell=bash
# confirm: confirm from a second SSH session, and the change stays, past
# the timer's deadline and across a reboot.
#
# 1. sshd-hardening applied over SSH. A confirm in the same SSH session as
#    the apply is refused (it proves nothing about a fresh login); a
#    confirm from a new session keeps it (confirmed, new-ssh-session), and
#    stops the timer and removes the boot unit.
# 2. Past the deadline: the drop-in is there, sshd -T shows the planned
#    settings, a new password login as swpw is refused and a new key login
#    works.
# 3. ufw-policy from a new plan, confirmed from a new session. Past the
#    deadline: UFW is active with a default deny, 8090 is closed from
#    outside, a new SSH login works.
# 4. The VM reboots. Both changes are still in effect: sshd -T, the
#    password login refused, the key login working, UFW active, 8090
#    closed. The state still says confirmed and no rollback unit exists.

scenario_verify() {
	plan_as "$VM_USER" plan --profile tunnel
	note "$(planned plan sshd-hardening)" "plan holds sshd-hardening" yes "$(jq -r '[.steps[].id] | join(",")' "$OUT/plan.json")"
	expect_password_login yes "before apply, $PW_USER logs in with its password"

	confirm_sshd
	confirm_ufw
	after_reboot
}

confirm_sshd() {
	local id
	# Apply and confirm in one SSH session: the confirm must be refused.
	log "[$VM_USER] apply sshd-hardening and confirm from the same session"
	vm "sudo stackward apply --step sshd-hardening --confirm-within $WITHIN --yes $WORK/plan.json; echo \"apply exit \$?\"
		id=\$(sudo python3 -c 'import json; print(json.load(open(\"$STATE\"))[\"id\"])')
		sudo stackward confirm \"\$id\"; echo \"same-session confirm exit \$?\"" >"$OUT/apply-sshd.txt" 2>&1 || true
	cat "$OUT/apply-sshd.txt"
	id="$(txn id)"
	note "$(yn grep -qx 'apply exit 0' "$OUT/apply-sshd.txt")" "sshd-hardening transaction exit code" "apply exit 0" "$(grep -m1 '^apply exit' "$OUT/apply-sshd.txt")"
	note "$(yn grep -qx 'same-session confirm exit 2' "$OUT/apply-sshd.txt")" "a confirm from the session that applied is refused" "exit 2" "$(grep -m1 'same-session' "$OUT/apply-sshd.txt")" "$(grep -m1 'session that applied' "$OUT/apply-sshd.txt")"
	note "$(yn [ "$(txn status)" = open ])" "after the refused confirm the transaction is still open" open "$(txn status)"

	confirm_as "$VM_USER" confirm-sshd "$id"
	note "$(yn [ "$CODE" -eq 0 ])" "confirm from a new SSH session exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)/$(txn confirmed_via)" = confirmed/new-ssh-session ])" "the transaction is confirmed from a new SSH session" confirmed/new-ssh-session "$(txn status)/$(txn confirmed_via)"
	note "$(yn [ "$(timer_state "$id")" != active ])" "confirm stops the rollback timer" inactive "$(timer_state "$id")"
	note "$(yn [ "$(boot_units)" = 0 ])" "confirm removes the boot rollback unit" 0 "$(boot_units)"

	wait_past_deadline
	note "$(yn [ "$(vm "test -e $HARDENING && echo present || echo gone")" = present ])" "past the deadline, the drop-in stays" present "$(vm "test -e $HARDENING && echo present || echo gone")"
	note "$(yn [ "$(txn status)" = confirmed ])" "past the deadline, the state says confirmed" confirmed "$(txn status)"
	expect_planned_sshd plan "past the deadline"
	expect_password_login no "past the deadline, a new password login as $PW_USER is refused"
	expect_key_login "$VM_USER" yes "past the deadline, a new key login works"
}

confirm_ufw() {
	local id
	plan_as "$VM_USER" plan-ufw --profile tunnel
	note "$(planned plan-ufw ufw-policy)" "a new plan holds ufw-policy" yes "$(skipped plan-ufw ufw-policy)"
	apply_as "$VM_USER" apply-ufw --step ufw-policy --confirm-within "$WITHIN" --yes "$WORK/plan-ufw.json"
	id="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "ufw-policy transaction exit code" 0 "$CODE"
	confirm_as "$VM_USER" confirm-ufw "$id"
	note "$(yn [ "$CODE" -eq 0 ])" "confirm ufw-policy from a new SSH session exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)/$(txn confirmed_via)" = confirmed/new-ssh-session ])" "ufw-policy is confirmed from a new SSH session" confirmed/new-ssh-session "$(txn status)/$(txn confirmed_via)"
	wait_past_deadline
	expect_ufw_on "past the deadline"
}

expect_ufw_on() {
	note "$(yn grep -q 'Status: active' <<<"$(ufw_line '^Status:')")" "$1, UFW is active" "Status: active" "$(ufw_line '^Status:')"
	note "$(yn grep -q 'deny (incoming)' <<<"$(ufw_line '^Default:')")" "$1, UFW denies incoming by default" "deny (incoming)" "$(ufw_line '^Default:')"
	expect_http closed "$1, 8090 is closed from outside"
	expect_key_login "$VM_USER" yes "$1, a new SSH login works"
}

after_reboot() {
	reboot_vm
	note "$(yn [ "$(vm "systemctl is-active sw-http.service")" = active ])" "after the reboot, the web server on 8090 runs" active "$(vm "systemctl is-active sw-http.service" || true)"
	note "$(yn [ "$(vm "test -e $HARDENING && echo present || echo gone")" = present ])" "after the reboot, the drop-in stays" present "$(vm "test -e $HARDENING && echo present || echo gone")"
	expect_planned_sshd plan "after the reboot"
	expect_password_login no "after the reboot, a new password login as $PW_USER is refused"
	expect_ufw_on "after the reboot"
	note "$(yn [ "$(txn status)" = confirmed ])" "after the reboot, the state says confirmed" confirmed "$(txn status)"
	note "$(yn [ "$(boot_units)" = 0 ])" "after the reboot, no boot rollback unit exists" 0 "$(boot_units)"
}
