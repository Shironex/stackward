# shellcheck shell=bash
# rollback: nobody confirms, the timer fires, and access comes back.
#
# 1. plan --profile tunnel as swtest holds sshd-hardening and ufw-policy.
#    Before anything changes, swpw logs in with its password, swtest with
#    its key, and the web server on 8090 answers from outside.
# 2. sshd-hardening, applied over SSH with --confirm-within 60s (240s on an
#    emulated VM), then the session ends, as a dropped connection does.
#    While it is open: sshd -T shows every setting of the planned drop-in
#    (password login off among them), and a new
#    password login as swpw is refused, so the change really took away a
#    way in. A new key login still works.
# 3. Nobody confirms. The timer fires: the state says rolled-back (timer),
#    the drop-in is gone, sshd -T shows password login on again, and a new
#    password login as swpw works again: the rollback restored the access
#    the change took away. A new key login works. Access steps wait for
#    confirm --ack-rollback.
# 4. ufw-policy the same way: while open, UFW is active with a default
#    deny, 8090 is closed from outside and a new SSH login works. After the
#    timer: UFW is inactive, 8090 answers again, a new SSH login works.

scenario_verify() {
	plan_as "$VM_USER" plan --profile tunnel
	note "$(planned plan sshd-hardening)" "plan holds sshd-hardening" yes "$(jq -r '[.steps[].id] | join(",")' "$OUT/plan.json")"
	note "$(planned plan ufw-policy)" "plan holds ufw-policy" yes "$(skipped plan ufw-policy)"
	expect_password_login yes "before apply, $PW_USER logs in with its password"
	expect_key_login "$VM_USER" yes "before apply, $VM_USER logs in with its key"
	expect_http open "before apply, 8090 answers from outside"

	rollback_sshd
	rollback_ufw
}

rollback_sshd() {
	local id
	apply_as "$VM_USER" apply-sshd --step sshd-hardening --confirm-within "$WITHIN" --yes "$WORK/plan.json"
	id="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "sshd-hardening transaction exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)" = open ])" "the sshd-hardening transaction is open" open "$(txn status)"
	note "$(yn [ "$(timer_state "$id")" = active ])" "its rollback timer is armed" active "$(timer_state "$id")"
	expect_planned_sshd plan "while open"
	expect_password_login no "while open, a new password login as $PW_USER is refused"
	expect_key_login "$VM_USER" yes "while open, a new key login works"

	wait_txn_closed "$id"
	note "$(yn [ "$(txn status)/$(txn cause)" = rolled-back/timer ])" "nobody confirmed: the timer rolled sshd-hardening back" rolled-back/timer "$(txn status)/$(txn cause)" "after ${WAITED}s"
	note "$(yn [ "$(vm "test -e $HARDENING && echo present || echo gone")" = gone ])" "the rollback removed the hardening drop-in" gone "$(vm "test -e $HARDENING && echo present || echo gone")"
	note "$(yn [ "$(timer_state "$id")" != active ])" "the timer is gone after it fired" inactive "$(timer_state "$id")"
	note "$(yn [ "$(boot_units)" = 0 ])" "no boot rollback unit is left" 0 "$(boot_units)"
	expect_sshd passwordauthentication yes "after the rollback, sshd -T has password login on again"
	expect_password_login yes "after the rollback, a new password login as $PW_USER works again"
	expect_key_login "$VM_USER" yes "after the rollback, a new key login works"

	apply_as "$VM_USER" apply-blocked --step ufw-policy --yes "$WORK/plan.json"
	note "$(yn [ "$CODE" -eq 2 ])" "access steps wait for confirm --ack-rollback" 2 "$CODE" "$(grep -m1 'ack-rollback' "$OUT/apply-blocked.txt")"
	confirm_as "$VM_USER" ack-sshd "--ack-rollback $id"
	note "$(yn [ "$CODE" -eq 0 ])" "confirm --ack-rollback exit code" 0 "$CODE"
}

rollback_ufw() {
	local id
	# A new plan: the earlier one was made before sshd-hardening ran.
	plan_as "$VM_USER" plan-ufw --profile tunnel
	apply_as "$VM_USER" apply-ufw --step ufw-policy --confirm-within "$WITHIN" --yes "$WORK/plan-ufw.json"
	id="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "ufw-policy transaction exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)" = open ])" "the ufw-policy transaction is open" open "$(txn status)"
	note "$(yn grep -q 'Status: active' <<<"$(ufw_line '^Status:')")" "while open, UFW is active" "Status: active" "$(ufw_line '^Status:')"
	note "$(yn grep -q 'deny (incoming)' <<<"$(ufw_line '^Default:')")" "while open, UFW denies incoming by default" "deny (incoming)" "$(ufw_line '^Default:')"
	expect_http closed "while open, 8090 is closed from outside"
	expect_key_login "$VM_USER" yes "while open, a new SSH login still works"

	wait_txn_closed "$id"
	note "$(yn [ "$(txn status)/$(txn cause)" = rolled-back/timer ])" "nobody confirmed: the timer rolled ufw-policy back" rolled-back/timer "$(txn status)/$(txn cause)" "after ${WAITED}s"
	note "$(yn grep -q 'Status: inactive' <<<"$(ufw_line '^Status:')")" "after the rollback, UFW is inactive" "Status: inactive" "$(ufw_line '^Status:')"
	expect_http open "after the rollback, 8090 answers from outside again"
	expect_key_login "$VM_USER" yes "after the rollback, a new SSH login works"
	expect_password_login yes "after the rollback, a new password login works"
	confirm_as "$VM_USER" ack-ufw "--ack-rollback $id"
	note "$(yn [ "$CODE" -eq 0 ])" "confirm --ack-rollback exit code" 0 "$CODE"
}
