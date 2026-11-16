# shellcheck shell=bash
# guard: apply refuses a change that would lock the session out, and
# refuses to run in CI without the throwaway VM flag. Nothing changes.
#
# 1. plan as swtest (a key and sudo) holds sshd-hardening: swtest is the
#    second way in that survives password login going off.
# 2. The CI gate: GITHUB_ACTIONS=true on the command line of sudo (which
#    drops it from apply's own environment) makes apply refuse, exit 2,
#    with nothing changed. With STACKWARD_CI_APPLY=throwaway-vm as well,
#    apply goes past the gate (and stops at a plan file that does not
#    exist).
# 3. swpw (password only, no key) gets sudo, and from its password session
#    swtest's sudo rule is removed. Now the only account that can run
#    sudo logs in with a password, which sshd-hardening turns off.
# 4. plan from that state lists sshd-hardening as refused by the lockout
#    guard.
# 5. apply of the plan from step 1 (made while swtest could sudo), from
#    swpw's password session: the guard proves again from the live host,
#    finds no non-root sudo account with a key, and refuses, exit 2. Nothing
#    changed: no drop-in, sshd -T has password login on, no transaction,
#    no timer, no boot unit, and a new password login as swpw works.

scenario_verify() {
	plan_as "$VM_USER" plan --profile tunnel
	note "$(planned plan sshd-hardening)" "plan as $VM_USER holds sshd-hardening" yes "$(skipped plan sshd-hardening)"

	ci_gate
	lone_password_admin
}

nothing_changed() {
	local when="$1"
	note "$(yn [ "$(root_cmd "test -e $HARDENING && echo present || echo gone")" = gone ])" "$when, no hardening drop-in" gone "$(root_cmd "test -e $HARDENING && echo present || echo gone")"
	note "$(yn [ -z "$(txn status)" ])" "$when, no transaction" none "$(txn status)"
	note "$(yn [ -z "$(root_cmd "systemctl list-units --all --plain --no-legend 'stackward-rollback-*'")" ])" "$when, no rollback timer" none "$(root_cmd "systemctl list-units --all --plain --no-legend 'stackward-rollback-*'" | head -1)"
	note "$(yn [ "$(boot_units)" = 0 ])" "$when, no boot rollback unit" 0 "$(boot_units)"
	expect_sshd passwordauthentication yes "$when, sshd -T has password login on"
}

ci_gate() {
	CODE=0
	log "[$VM_USER] GITHUB_ACTIONS=true sudo stackward apply --step sshd-hardening"
	vm "GITHUB_ACTIONS=true sudo stackward apply --step sshd-hardening --confirm-within $WITHIN --yes $WORK/plan.json" >"$OUT/apply-ci.txt" 2>&1 || CODE=$?
	cat "$OUT/apply-ci.txt"
	note "$(yn [ "$CODE" -eq 2 ])" "apply in a CI job without the flag exit code" 2 "$CODE"
	note "$(yn grep -q 'GITHUB_ACTIONS is set in pid' "$OUT/apply-ci.txt")" "apply finds GITHUB_ACTIONS that sudo dropped" "found in an ancestor" "$(grep -m1 -o 'GITHUB_ACTIONS is set in [^,]*' "$OUT/apply-ci.txt")"
	nothing_changed "after the CI refusal"

	CODE=0
	vm "GITHUB_ACTIONS=true STACKWARD_CI_APPLY=throwaway-vm sudo stackward apply --step sshd-hardening --yes $WORK/no-such-plan.json" >"$OUT/apply-ci-flag.txt" 2>&1 || CODE=$?
	cat "$OUT/apply-ci-flag.txt"
	note "$(yn [ "$CODE" -eq 2 ] && ! grep -q 'CI job' "$OUT/apply-ci-flag.txt" && grep -q 'no-such-plan' "$OUT/apply-ci-flag.txt")" \
		"with STACKWARD_CI_APPLY=throwaway-vm apply goes past the CI gate" "stops at the plan file" "$(head -1 "$OUT/apply-ci-flag.txt")"
}

lone_password_admin() {
	vm "printf '%s ALL=(ALL) NOPASSWD:ALL\n' $PW_USER | sudo tee /etc/sudoers.d/90-vmtest-$PW_USER >/dev/null && sudo chmod 0440 /etc/sudoers.d/90-vmtest-$PW_USER"
	# cloud-init wrote swtest's rule into this file, and nothing else.
	pw "sudo -n grep -l '^swtest ' /etc/sudoers.d/90-cloud-init-users && sudo -n rm /etc/sudoers.d/90-cloud-init-users" >/dev/null
	# shellcheck disable=SC2034 # read by root_cmd in lib.sh
	ROOT_SESSION="pw"
	note "$(yn [ "$(yn vm "sudo -n true" 2>/dev/null)" = no ])" "$VM_USER can no longer sudo" "no sudo" "$(vm "sudo -n true" >/dev/null 2>&1 && echo sudo || echo "no sudo")"
	note "$(yn pw "sudo -n true")" "$PW_USER logs in with its password and can sudo" sudo ""

	log "[$PW_USER] sudo stackward plan --profile tunnel"
	pw "sudo stackward plan --profile tunnel --out $WORK/plan-pw.json" >"$OUT/plan-pw.txt" 2>&1 || true
	pw "sudo cat $WORK/plan-pw.json" >"$OUT/plan-pw.json" 2>/dev/null || true
	note "$(yn grep -q '^refused: lockout guard' <<<"$(skipped plan-pw sshd-hardening)")" "plan with a password only admin refuses sshd-hardening" "refused: lockout guard" "$(skipped plan-pw sshd-hardening)"

	CODE=0
	log "[$PW_USER] sudo stackward apply --step sshd-hardening (the plan made while $VM_USER could sudo)"
	pw "sudo stackward apply --step sshd-hardening --confirm-within $WITHIN --yes $WORK/plan.json" >"$OUT/apply-guard.txt" 2>&1 || CODE=$?
	cat "$OUT/apply-guard.txt"
	note "$(yn [ "$CODE" -eq 2 ])" "apply that would lock the session out exit code" 2 "$CODE"
	note "$(yn grep -q 'lockout guard' "$OUT/apply-guard.txt")" "apply names the lockout guard" "lockout guard" "$(grep -m1 'lockout guard' "$OUT/apply-guard.txt" | cut -c1-200)"
	nothing_changed "after the guard refusal"
	expect_password_login yes "after the guard refusal, a new password login as $PW_USER works"
}
