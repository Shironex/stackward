# shellcheck shell=bash
# shellcheck disable=SC2034 # ROOT_SESSION is read by root_cmd in lib.sh
# accounts: create an admin, prove it by logging in as it, harden sshd and
# lock the image's default account from that session, then undo it all.
# The VM is booted with the accounts seed: the image's own default account
# (ubuntu or debian) holds the key, as a provider sets it up.
#
# 1. As the default account: plan --admin-user swadmin --admin-keys-from
#    the default account holds admin-user. apply --step admin-user opens a
#    transaction; swadmin exists, logs in over SSH with the copied key and
#    can sudo. The confirm runs from that new session as swadmin.
# 2. As swadmin: a new plan holds sshd-hardening and lock-default-user
#    (not refused: swadmin is a proven sudo account with a key).
#    sshd-hardening is applied and confirmed from a new swadmin session;
#    sshd -T shows the planned settings.
# 3. As swadmin: lock-default-user from a new plan, confirmed from a new
#    swadmin session. The default account no longer logs in with its key,
#    its shell is nologin and its keys file is set aside; swadmin still
#    logs in.
# 4. Undo, newest first: lock-default-user and sshd-hardening from a
#    swadmin session (the default account logs in again, password login is
#    back), then admin-user from the default account (swadmin, its home and
#    its sudoers drop-in are gone). passwd, group, shadow, gshadow, subuid,
#    subgid and the default account's authorized_keys are byte for byte
#    what they were before step 1.

ADMIN=swadmin

admin() { ssh_as "$ADMIN" "$@"; }

# account_files: sha256 of the account files, one per line (absent files
# say so), read in a session of an account that may sudo.
account_files() {
	root_cmd "for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid /home/$VM_DEFAULT_USER/.ssh/authorized_keys; do
		if sudo test -e \"\$f\"; then sudo sha256sum \"\$f\"; else echo \"absent  \$f\"; fi
	done"
}

# txn_step NAME STEP PLAN USER CONFIRMER: apply STEP of PLAN as USER, then
# confirm it from a new session as CONFIRMER, the account that stays; sets
# RUN.
txn_step() {
	local name="$1" step="$2" plan="$3" user="$4" confirmer="$5"
	apply_as "$user" "apply-$name" --step "$step" --confirm-within "$WITHIN" --yes "$WORK/$plan.json"
	RUN="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "$step transaction exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)" = open ])" "the $step transaction is open" open "$(txn status)"
	if [ "$step" = admin-user ]; then
		expect_admin_works "while the transaction is open"
	fi
	confirm_as "$confirmer" "confirm-$name" "$RUN"
	note "$(yn [ "$(txn status)/$(txn confirmed_via)" = confirmed/new-ssh-session ])" "$step is confirmed from a new SSH session as $confirmer" confirmed/new-ssh-session "$(txn status)/$(txn confirmed_via)"
}

expect_admin_works() {
	expect_key_login "$ADMIN" yes "$1, $ADMIN logs in with the copied key"
	note "$(yn quiet admin "sudo -n true")" "$1, $ADMIN can sudo without a password" sudo ""
}

scenario_verify() {
	local admin_run sshd_run lock_run shell
	account_files >"$OUT/accounts.before"
	cat "$OUT/accounts.before"
	vm "cat /etc/passwd /etc/group" >"$OUT/passwd-group.before" 2>&1 || true

	plan_as "$VM_DEFAULT_USER" plan-admin --profile tunnel --admin-user "$ADMIN" --admin-keys-from "$VM_DEFAULT_USER"
	note "$(planned plan-admin admin-user)" "plan holds admin-user" yes "$(skipped plan-admin admin-user)"
	txn_step admin admin-user plan-admin "$VM_DEFAULT_USER" "$ADMIN"
	admin_run="$RUN"
	ROOT_SESSION="admin"

	plan_as "$ADMIN" plan-sshd --profile tunnel
	note "$(planned plan-sshd sshd-hardening)" "a plan from the $ADMIN session holds sshd-hardening" yes "$(skipped plan-sshd sshd-hardening)"
	note "$(planned plan-sshd lock-default-user)" "a plan from the $ADMIN session holds lock-default-user" yes "$(skipped plan-sshd lock-default-user)"
	txn_step sshd sshd-hardening plan-sshd "$ADMIN" "$ADMIN"
	sshd_run="$RUN"
	expect_planned_sshd plan-sshd "after the confirm"

	plan_as "$ADMIN" plan-lock --profile tunnel
	note "$(planned plan-lock lock-default-user)" "a new plan holds lock-default-user" yes "$(skipped plan-lock lock-default-user)"
	txn_step lock lock-default-user plan-lock "$ADMIN" "$ADMIN"
	lock_run="$RUN"
	expect_key_login "$VM_DEFAULT_USER" no "after the lock, $VM_DEFAULT_USER no longer logs in with its key"
	shell="$(admin "getent passwd $VM_DEFAULT_USER" | cut -d: -f7)"
	note "$(yn [ "$shell" = /usr/sbin/nologin ])" "after the lock, $VM_DEFAULT_USER has the nologin shell" /usr/sbin/nologin "$shell"
	note "$(yn quiet admin "sudo test -e /home/$VM_DEFAULT_USER/.ssh/authorized_keys.stackward-locked")" "after the lock, the keys file is set aside" "authorized_keys.stackward-locked" ""
	expect_admin_works "after the lock"

	undo_as "$ADMIN" undo-lock "$lock_run"
	expect_key_login "$VM_DEFAULT_USER" yes "after undo, $VM_DEFAULT_USER logs in with its key again"
	undo_as "$ADMIN" undo-sshd "$sshd_run"
	expect_sshd passwordauthentication yes "after undo, sshd -T has password login on again"

	ROOT_SESSION="vm"
	wait_no_processes "$ADMIN"
	undo_as "$VM_DEFAULT_USER" undo-admin "$admin_run"
	note "$(yn [ -z "$(vm "getent passwd $ADMIN" || true)" ])" "after undo, $ADMIN is gone" gone "$(vm "getent passwd $ADMIN" || true)"
	note "$(yn quiet vm "test ! -e /home/$ADMIN && sudo test ! -e /etc/sudoers.d/90-stackward-$ADMIN")" "after undo, the home and the sudoers drop-in of $ADMIN are gone" gone ""
	expect_key_login "$ADMIN" no "after undo, $ADMIN no longer logs in"

	account_files >"$OUT/accounts.after"
	local f before after
	while read -r before f; do
		after="$(awk -v f="$f" '$2 == f {print $1}' "$OUT/accounts.after")"
		note "$(yn [ "$before" = "$after" ])" "after undo, $f is byte for byte as before" "${before:0:12}" "${after:0:12}"
	done <"$OUT/accounts.before"
	vm "cat /etc/passwd /etc/group" >"$OUT/passwd-group.after" 2>&1 || true
}

# undo_as USER NAME RUN: stackward undo --run RUN in a new session as USER.
undo_as() {
	CODE=0
	log "[$1] sudo stackward undo --run $3 --yes"
	ssh_as "$1" "sudo stackward undo --run $3 --yes" >"$OUT/$2.txt" 2>&1 || CODE=$?
	cat "$OUT/$2.txt"
	note "$(yn [ "$CODE" -eq 0 ])" "$2 exit code" 0 "$CODE"
}

# wait_no_processes USER: userdel refuses an account that still runs a
# process; logind ends the user's systemd instance shortly after the last
# session closes.
wait_no_processes() {
	local _
	for _ in $(seq 1 30); do
		vm "pgrep -u $1 >/dev/null" || return 0
		sleep 2
	done
	log "processes of $1 are still running:"
	vm "ps -u $1 -o pid,comm" || true
}
