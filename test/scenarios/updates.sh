# shellcheck shell=bash
# shellcheck disable=SC2024 # outputs are written by this shell, as the caller, so they stay readable
# updates: the update and intrusion steps on a real host (the disposable
# GitHub runner VM). Like apply, it lets stackward change the machine.
#
# Setup: unattended-upgrades installed but turned off (20auto-upgrades says
# "0"), fail2ban absent, and the runner's own sshd reachable from anywhere
# (no firewall). apt-daily-upgrade.timer is enabled but stopped, so no
# unattended-upgrades run (and no reboot it might ask for) can start while
# the scenario runs; the timer commands of the step are covered by the
# unit tests. Then:
#
# 1. plan holds unattended-upgrades, the opt in reboot decision
#    unattended-upgrades-reboot and fail2ban-sshd (opt in, access-critical,
#    with the fail2ban install as a named command run before the jail is
#    written); --all-safe selects
#    only unattended-upgrades.
# 2. apply --step unattended-upgrades --step unattended-upgrades-reboot:
#    both drop-ins hold the planned content, apt-config shows the values,
#    the timer is left alone, nothing reboots. A second apply
#    says nothing to do. A new audit passes UPD-001. undo --run restores
#    every regular file under /etc.
# 3. apply --step fail2ban-sshd (no SSH session, as after a dropped
#    connection): the transaction installs fail2ban, fail2ban-client -t
#    passes, the sshd jail runs on port 22 and ignores loopback; confirm
#    --console keeps it. A second apply says nothing to do. A new audit
#    passes CS-010. undo --run removes the jail and purges fail2ban.

UPD_SAVE=""
AUTO=/etc/apt/apt.conf.d/20auto-upgrades
TIMER=apt-daily-upgrade.timer
UU_DROPIN=/etc/apt/apt.conf.d/90stackward-unattended-upgrades
REBOOT_DROPIN=/etc/apt/apt.conf.d/91stackward-automatic-reboot
JAIL=/etc/fail2ban/jail.d/90-stackward-sshd.local
TXN_STATE=/var/lib/stackward/transaction.json

dpkg_installed() { [ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" = "install ok installed" ]; }

scenario_setup() {
	command -v apt-get >/dev/null || die "this scenario needs an apt host"
	UPD_SAVE="$OUT/updates-saved"
	mkdir -p "$UPD_SAVE"
	dpkg_installed fail2ban && die "fail2ban is already installed; this scenario installs it itself"
	if sudo test -e "$AUTO"; then
		sudo cat "$AUTO" >"$UPD_SAVE/20auto-upgrades"
	fi
	sudo systemctl is-enabled "$TIMER" >"$UPD_SAVE/timer-enabled" 2>/dev/null || true
	sudo systemctl is-active "$TIMER" >"$UPD_SAVE/timer-active" 2>/dev/null || true
	sudo apt-get update -qq >/dev/null
	if ! dpkg_installed unattended-upgrades; then
		: >"$UPD_SAVE/uu-installed-by-setup"
		sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null
	fi
	printf 'APT::Periodic::Update-Package-Lists "0";\nAPT::Periodic::Unattended-Upgrade "0";\n' | sudo tee "$AUTO" >/dev/null
	sudo systemctl unmask "$TIMER" >/dev/null 2>&1 || true
	sudo systemctl stop "$TIMER" >/dev/null 2>&1 || true
	sudo systemctl enable "$TIMER" >/dev/null 2>&1 || true
	# sshd -t needs /run/sshd, which ssh.service creates.
	sudo systemctl start ssh.service
	apt_caches
}

etc_hashes() {
	sudo find /etc -xdev -type f -print0 | sudo xargs -0 -r sha256sum | LC_ALL=C sort -k2
}

planned_new() {
	sudo jq -r --arg p "$1" ".steps[].edits[] | select(.path == \$p) | .new_sha256" "$OUT/plan.json"
}

file_sha() { sudo sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

yn() {
	if "$@"; then echo yes; else echo no; fi
}

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
	local plan="$OUT/plan.json" steps
	log "sudo stackward plan --out $plan"
	sudo "$STACKWARD" plan --out "$plan" >"$OUT/plan.txt"
	sudo chmod 0644 "$plan"
	cat "$OUT/plan.txt"
	steps="$(jq -r '[.steps[].id] | join(",")' "$plan")"
	local id
	for id in unattended-upgrades unattended-upgrades-reboot fail2ban-sshd; do
		note "$(yn grep -Eq "(^|,)$id(,|$)" <<<"$steps")" "plan holds $id" yes "$steps"
	done
	# The install is the last command that runs before the jail is written
	# (after apt-get update when the lists were empty or stale).
	local install
	install="$(jq -r '.steps[] | select(.id == "fail2ban-sshd") | (.before // [])[-1].args // [] | join(" ")' "$plan")"
	note "$(yn [ "$install" = "env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y fail2ban" ])" \
		"the fail2ban install is a named command, run before the jail is written" "apt-get install -y fail2ban" "$install"
	local optin
	optin="$(jq -r '[.steps[] | select(.id | test("^(unattended-upgrades|unattended-upgrades-reboot|fail2ban-sshd)$")) | "\(.id)=\(.opt_in)"] | join(",")' "$plan")"
	note "$(yn [ "$optin" = "unattended-upgrades=false,unattended-upgrades-reboot=true,fail2ban-sshd=true" ])" \
		"only unattended-upgrades runs without being named" "unattended-upgrades=false,unattended-upgrades-reboot=true,fail2ban-sshd=true" "$optin"

	verify_updates
	verify_fail2ban
}

verify_updates() {
	local id code
	etc_hashes >"$OUT/etc.before"
	run_apply upd-1 --step unattended-upgrades --step unattended-upgrades-reboot --yes
	note "$(yn [ "$CODE" -eq 0 ])" "apply exit code" 0 "$CODE"
	id="$(sed -n 's/^run: *\([0-9TZ]*-[0-9a-f]*\) .*/\1/p' "$OUT/upd-1.txt")"
	local p
	for p in "$UU_DROPIN" "$REBOOT_DROPIN"; do
		note "$(yn [ "$(file_sha "$p")" = "$(planned_new "$p")" ])" "$p holds the planned content" "$(planned_new "$p" | cut -c1-12)" "$(file_sha "$p" | cut -c1-12)"
	done
	apt-config dump >"$OUT/apt-config.txt"
	note "$(yn grep -q '^APT::Periodic::Unattended-Upgrade "1";' "$OUT/apt-config.txt")" "apt-config: Unattended-Upgrade is on" '"1"' "$(grep '^APT::Periodic::Unattended-Upgrade ' "$OUT/apt-config.txt")"
	note "$(yn grep -q '^Unattended-Upgrade::Automatic-Reboot-Time "04:00";' "$OUT/apt-config.txt")" "apt-config: the reboot window" '"04:00"' "$(grep '^Unattended-Upgrade::Automatic-Reboot-Time' "$OUT/apt-config.txt")"
	note "$(yn [ "$(jq -r '.steps[] | select(.id == "unattended-upgrades") | .commands | length' "$OUT/plan.json")" = 0 ])" "an enabled timer gets no command" 0 "$(jq -r '.steps[] | select(.id == "unattended-upgrades") | .commands | length' "$OUT/plan.json")"
	note "$(yn [ "$(sudo systemctl is-active "$TIMER" 2>/dev/null || true)" != active ])" "the timer is left stopped" inactive "$(sudo systemctl is-active "$TIMER" 2>/dev/null || true)"

	run_apply upd-2 --step unattended-upgrades --step unattended-upgrades-reboot --yes
	note "$(yn grep -q 'nothing to do' "$OUT/upd-2.txt")" "second apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/upd-2.txt")"

	apt_caches
	audit upd-after
	expect check "$REPORT" UPD-001 host pass

	code=0
	log "sudo stackward undo --run $id --yes"
	sudo "$STACKWARD" undo --run "$id" --yes >"$OUT/upd-undo.txt" 2>&1 || code=$?
	cat "$OUT/upd-undo.txt"
	note "$(yn [ "$code" -eq 0 ])" "undo exit code" 0 "$code"
	etc_hashes >"$OUT/etc.undone"
	note "$(yn cmp -s "$OUT/etc.before" "$OUT/etc.undone")" "undo restores every file under /etc" "no diff" "$(diff "$OUT/etc.before" "$OUT/etc.undone" | head -3 | tr '\n' ' ')"
}

verify_fail2ban() {
	local id code
	run_apply f2b-1 --step fail2ban-sshd --confirm-within 5m --yes
	note "$(yn [ "$CODE" -eq 0 ])" "fail2ban-sshd transaction exit code" 0 "$CODE"
	id="$(sudo jq -r '.id // empty' "$TXN_STATE" 2>/dev/null)"
	note "$(yn [ "$(file_sha "$JAIL")" = "$(planned_new "$JAIL")" ])" "the jail holds the planned content" "$(planned_new "$JAIL" | cut -c1-12)" "$(file_sha "$JAIL" | cut -c1-12)"
	note "$(yn dpkg_installed fail2ban)" "fail2ban is installed" installed ""
	code=0
	sudo fail2ban-client -t >"$OUT/f2b-test.txt" 2>&1 || code=$?
	note "$(yn [ "$code" -eq 0 ])" "fail2ban-client -t passes" 0 "$code" "$(head -1 "$OUT/f2b-test.txt")"
	sudo fail2ban-client status sshd >"$OUT/f2b-status.txt" 2>&1 || true
	cat "$OUT/f2b-status.txt"
	note "$(yn grep -q 'Status for the jail: sshd' "$OUT/f2b-status.txt")" "the sshd jail runs" running "$(head -1 "$OUT/f2b-status.txt")"
	sudo fail2ban-client get sshd ignoreip >"$OUT/f2b-ignore.txt" 2>&1 || true
	# fail2ban prints 127.0.0.1/8 as the network it is, 127.0.0.0/8.
	note "$(yn grep -Eq '127\.0\.0\.[01]/8' "$OUT/f2b-ignore.txt")" "the jail ignores loopback" "127.0.0.0/8" "$(tr '\n' ' ' <"$OUT/f2b-ignore.txt")"

	code=0
	sudo "$STACKWARD" confirm --console "$id" >"$OUT/f2b-confirm.txt" 2>&1 || code=$?
	cat "$OUT/f2b-confirm.txt"
	note "$(yn [ "$code" -eq 0 ])" "confirm --console exit code" 0 "$code"

	run_apply f2b-2 --step fail2ban-sshd --yes
	note "$(yn grep -q 'nothing to do' "$OUT/f2b-2.txt")" "second fail2ban apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/f2b-2.txt")"

	audit f2b-after
	expect check "$REPORT" CS-010 host pass

	code=0
	log "sudo stackward undo --run $id --yes"
	sudo "$STACKWARD" undo --run "$id" --yes >"$OUT/f2b-undo.txt" 2>&1 || code=$?
	cat "$OUT/f2b-undo.txt"
	note "$(yn [ "$code" -eq 0 ])" "fail2ban undo exit code" 0 "$code"
	note "$(yn sudo test ! -e "$JAIL")" "undo removes the jail" gone "$(sudo test -e "$JAIL" && echo present || echo gone)"
	note "$(yn [ "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)" != "install ok installed" ])" "undo purges fail2ban" purged "$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null || true)"
}

scenario_cleanup() {
	[ -n "$UPD_SAVE" ] || return 0
	sudo systemctl stop 'stackward-rollback-*' >/dev/null 2>&1 || true
	sudo rm -f "$UU_DROPIN" "$REBOOT_DROPIN" "$JAIL"
	if dpkg_installed fail2ban; then
		sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq fail2ban >/dev/null || true
	fi
	if [ -f "$UPD_SAVE/20auto-upgrades" ]; then
		sudo cp "$UPD_SAVE/20auto-upgrades" "$AUTO"
	else
		sudo rm -f "$AUTO"
	fi
	if [ -f "$UPD_SAVE/uu-installed-by-setup" ]; then
		sudo env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq unattended-upgrades >/dev/null || true
	fi
	case "$(cat "$UPD_SAVE/timer-enabled" 2>/dev/null)" in
	enabled) ;;
	masked) sudo systemctl mask "$TIMER" >/dev/null 2>&1 || true ;;
	*) sudo systemctl disable "$TIMER" >/dev/null 2>&1 || true ;;
	esac
	if [ "$(cat "$UPD_SAVE/timer-active" 2>/dev/null)" = active ]; then
		sudo systemctl start "$TIMER" >/dev/null 2>&1 || true
	fi
}
