# shellcheck shell=bash
# shellcheck disable=SC2034 # ROOT_SESSION is read by root_cmd in lib.sh
# rootonly: a server with no account but root, as some providers hand one
# out, and a fresh image's empty package lists. The VM is booted with the
# root seed: root logs in with the key, and no other account exists.
#
# 1. As root: plan --admin-user swadmin --admin-keys-from root holds
#    admin-user, and says the keys come from /root/.ssh/authorized_keys and
#    that sshd-hardening turns root login off once swadmin is confirmed.
#    apply --step admin-user opens a transaction; swadmin logs in with the
#    copied key and can sudo, and confirms from that new session.
# 2. Undo from a root session: swadmin, its home and sudoers drop-in are
#    gone; passwd, group, shadow, gshadow, subuid, subgid and root's
#    authorized_keys are byte for byte what they were before step 1.
# 3. The package lists emptied, as on a fresh cloud image: plan holds
#    fail2ban-sshd with apt-get update before the install, named. With the
#    apt sources moved aside, the install fails: the transaction ends
#    rolled-back (not rollback-failed), /etc/fail2ban does not exist and
#    no journal leaves a restart pending.
# 4. The sources back, still with empty lists: a new plan still offers
#    fail2ban-sshd with the update; apply installs fail2ban, the jail runs,
#    the next apply finds no pending restart, a confirm from a new session
#    keeps it; undo removes the jail and purges fail2ban.

ADMIN=swadmin
SOURCES_ASIDE=/var/tmp/stackward-vm-sources

admin() { ssh_as "$ADMIN" "$@"; }

# account_files: sha256 of the account files and of root's keys, one per
# line (absent files say so).
account_files() {
	vm "for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid /root/.ssh/authorized_keys; do
		if test -e \"\$f\"; then sha256sum \"\$f\"; else echo \"absent  \$f\"; fi
	done"
}

# before_args PLAN STEP N: the arguments of the N-th command STEP runs
# before its edits, joined by spaces.
# shellcheck disable=SC2016 # a jq program
before_args() {
	jq -r --arg s "$2" --argjson n "$3" '.steps[] | select(.id == $s) | (.before // [])[$n].args // [] | join(" ")' "$OUT/$1.json" 2>/dev/null
}

# pending_restarts: journals that still mark a step restart pending.
pending_restarts() {
	vm "grep -l '\"restart_pending\": true' /var/backups/stackward/*/journal.json 2>/dev/null || true"
}

undo_as() {
	CODE=0
	log "[$1] sudo stackward undo --run $3 --yes"
	ssh_as "$1" "sudo stackward undo --run $3 --yes" >"$OUT/$2.txt" 2>&1 || CODE=$?
	cat "$OUT/$2.txt"
	note "$(yn [ "$CODE" -eq 0 ])" "$2 exit code" 0 "$CODE"
}

wait_no_processes() {
	local _
	for _ in $(seq 1 30); do
		vm "pgrep -u $1 >/dev/null" || return 0
		sleep 2
	done
	log "processes of $1 are still running:"
	vm "ps -u $1 -o pid,comm" || true
}

expect_admin_works() {
	expect_key_login "$ADMIN" yes "$1, $ADMIN logs in with the key copied from root"
	note "$(yn quiet admin "sudo -n true")" "$1, $ADMIN can sudo without a password" sudo ""
}

verify_admin_from_root() {
	local run f before after
	local others
	# Accounts people log in as, but the password only account prepare_vm
	# adds for every scenario.
	others="$(vm "awk -F: '\$3 >= 1000 && \$3 < 60000 && \$1 != \"$PW_USER\" {print \$1}' /etc/passwd" || true)"
	note "$(yn [ -z "$others" ])" "the root seed has no account but root" none "$others"
	account_files >"$OUT/accounts.before"
	cat "$OUT/accounts.before"

	plan_as root plan-admin --profile tunnel --admin-user "$ADMIN" --admin-keys-from root
	note "$(planned plan-admin admin-user)" "plan holds admin-user with the keys of root" yes "$(skipped plan-admin admin-user)"
	note "$(yn grep -q '/root/.ssh/authorized_keys' "$OUT/plan-admin.txt")" "the plan says the keys come from /root/.ssh/authorized_keys" yes ""
	note "$(yn grep -q 'PermitRootLogin no' "$OUT/plan-admin.txt")" "the plan points at sshd-hardening to turn root login off" yes ""

	apply_as root apply-admin --step admin-user --confirm-within "$WITHIN" --yes "$WORK/plan-admin.json"
	run="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "admin-user transaction exit code" 0 "$CODE"
	note "$(yn [ "$(txn status)" = open ])" "the admin-user transaction is open" open "$(txn status)"
	expect_admin_works "while the transaction is open"
	confirm_as "$ADMIN" confirm-admin "$run"
	note "$(yn [ "$(txn status)/$(txn confirmed_via)" = confirmed/new-ssh-session ])" "admin-user is confirmed from a new SSH session as $ADMIN" confirmed/new-ssh-session "$(txn status)/$(txn confirmed_via)"
	expect_key_login root yes "after the confirm, root still logs in with its key"

	wait_no_processes "$ADMIN"
	undo_as root undo-admin "$run"
	note "$(yn [ -z "$(vm "getent passwd $ADMIN" || true)" ])" "after undo, $ADMIN is gone" gone "$(vm "getent passwd $ADMIN" || true)"
	note "$(yn quiet vm "test ! -e /home/$ADMIN && test ! -e /etc/sudoers.d/90-stackward-$ADMIN")" "after undo, the home and the sudoers drop-in of $ADMIN are gone" gone ""
	expect_key_login "$ADMIN" no "after undo, $ADMIN no longer logs in"
	account_files >"$OUT/accounts.after"
	while read -r before f; do
		after="$(awk -v f="$f" '$2 == f {print $1}' "$OUT/accounts.after")"
		note "$(yn [ "$before" = "$after" ])" "after undo, $f is byte for byte as before" "${before:0:12}" "${after:0:12}"
	done <"$OUT/accounts.before"
}

verify_empty_lists() {
	local run status update install pending
	if quiet vm "dpkg-query -W -f='\${Status}' fail2ban | grep -q 'install ok installed'"; then
		note no "fail2ban is absent before the scenario" absent installed
		return
	fi
	# A fresh cloud image: no Packages index under /var/lib/apt/lists.
	vm "find /var/lib/apt/lists -maxdepth 1 -type f ! -name lock -delete"
	plan_as root plan-f2b
	note "$(planned plan-f2b fail2ban-sshd)" "with empty lists, plan holds fail2ban-sshd" yes "$(skipped plan-f2b fail2ban-sshd)"
	update="$(before_args plan-f2b fail2ban-sshd 0)"
	install="$(before_args plan-f2b fail2ban-sshd 1)"
	note "$(yn [ "$update" = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update" ])" "apt-get update is the first command, named" "apt-get update" "$update"
	note "$(yn [ "$install" = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y fail2ban" ])" "the install follows it, before the jail is written" "apt-get install -y fail2ban" "$install"
	note "$(yn grep -q 'package lists are empty' "$OUT/plan-f2b.txt")" "the plan says why it refreshes the lists" yes ""

	# Without sources the update finds nothing and the install fails, as
	# it did on the fresh image of the rc.1 test.
	vm "mkdir -p $SOURCES_ASIDE && cp -a /etc/apt/sources.list /etc/apt/sources.list.d $SOURCES_ASIDE/ 2>/dev/null; rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*"
	apply_as root apply-f2b-fail --step fail2ban-sshd --confirm-within "$WITHIN" --yes "$WORK/plan-f2b.json"
	run="$(txn id)"
	status="$(txn status)"
	note "$(yn [ "$CODE" -ne 0 ])" "the failed install fails apply" "exit != 0" "$CODE"
	note "$(yn [ "$status" = rolled-back ])" "the failed install ends rolled-back, not rollback-failed" rolled-back "$status/$(txn cause)"
	note "$(yn quiet vm "test ! -e /etc/fail2ban")" "after the rollback, /etc/fail2ban does not exist" absent "$(vm "ls -d /etc/fail2ban 2>/dev/null" || true)"
	pending="$(pending_restarts)"
	note "$(yn [ -z "$pending" ])" "after the rollback, no journal leaves a restart pending" none "$pending"
	vm "cat /var/backups/stackward/$run/journal.json" >"$OUT/journal-f2b-fail.json" 2>/dev/null || true

	vm "cp -a $SOURCES_ASIDE/. /etc/apt/ && rm -rf $SOURCES_ASIDE"
	plan_as root plan-f2b2
	note "$(planned plan-f2b2 fail2ban-sshd)" "after the rollback, plan still offers fail2ban-sshd" yes "$(skipped plan-f2b2 fail2ban-sshd)"
	update="$(before_args plan-f2b2 fail2ban-sshd 0)"
	note "$(yn grep -q 'apt-get -o DPkg::Lock::Timeout=120 update' <<<"$update")" "the lists are still empty, so the update is still planned" "apt-get update" "$update"
	apply_as root apply-f2b --step fail2ban-sshd --confirm-within "$WITHIN" --yes "$WORK/plan-f2b2.json"
	run="$(txn id)"
	note "$(yn [ "$CODE" -eq 0 ])" "fail2ban-sshd transaction exit code" 0 "$CODE"
	note "$(yn quiet vm "fail2ban-client status sshd")" "the sshd jail runs" running ""
	confirm_as root confirm-f2b "$run"
	note "$(yn [ "$(txn status)" = confirmed ])" "fail2ban-sshd is confirmed from a new session" confirmed "$(txn status)"
	apply_as root apply-f2b-again --step fail2ban-sshd --yes "$WORK/plan-f2b2.json"
	note "$(yn ! grep -q 'Pending restarts' "$OUT/apply-f2b-again.txt")" "the next apply finds no pending restart" none "$(grep -m1 'Pending restarts' "$OUT/apply-f2b-again.txt" || true)"

	undo_as root undo-f2b "$run"
	note "$(yn quiet vm "test ! -e /etc/fail2ban/jail.d/90-stackward-sshd.local")" "after undo, the jail is gone" gone ""
	note "$(yn [ "$(vm "dpkg-query -W -f='\${Status}' fail2ban 2>/dev/null" || true)" != "install ok installed" ])" "after undo, fail2ban is purged" purged "$(vm "dpkg-query -W -f='\${Status}' fail2ban 2>/dev/null" || true)"
}

scenario_verify() {
	verify_admin_from_root
	verify_empty_lists
}
