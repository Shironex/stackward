# shellcheck shell=bash
# shellcheck disable=SC2034 # constants are read by the scenario scripts
# Host side helpers for the VM scenarios. Sourced by run.sh, never run.
# Every command reaches the VM over a new SSH connection to the port
# vm.sh forwarded on 127.0.0.1, so each call is a new SSH session, as a
# second terminal would be.

# shellcheck disable=SC1091 # written by vm.sh boot
. "$VM_DIR/vm.env"

# The account that logs in with a password only (no key), and its
# password. It exists only inside the throwaway VM, which listens on
# 127.0.0.1 of the runner alone.
PW_USER=swpw
PW_PASS=stackward-vm-only
STATE=/var/lib/stackward/transaction.json
WORK=/var/tmp/stackward-vm
HARDENING=/etc/ssh/sshd_config.d/00-stackward-hardening.conf

SSH_COMMON=(-p "$VM_SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR
	-o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o ServerAliveInterval=5 -o ServerAliveCountMax=6)

yn() {
	if "$@"; then echo yes; else echo no; fi
}

# ssh_as USER COMMAND...: run COMMAND (one shell line) in a new SSH session as
# USER, logged in with the key.
ssh_as() {
	local user="$1"
	shift
	ssh "${SSH_COMMON[@]}" -i "$VM_KEY" -o IdentitiesOnly=yes -o BatchMode=yes "$user@127.0.0.1" "$@" </dev/null
}

# vm COMMAND...: as the account the VM was seeded with.
vm() { ssh_as "$VM_USER" "$@"; }

# root_cmd COMMAND...: a new session of an account that may sudo; the seeded
# account unless a scenario took its sudo away (ROOT_SESSION=pw).
ROOT_SESSION=vm
root_cmd() { "$ROOT_SESSION" "$@"; }

# pw COMMAND...: a new password session as the password only account.
pw() { as_pw "$PW_USER" "$@"; }

# as_pw USER COMMAND...: a new SSH session as USER that may only log in
# with the password (no key offered, no keyboard-interactive). The
# password reaches ssh through SSH_ASKPASS, so no sshpass is needed.
as_pw() {
	local user="$1" askpass
	shift
	askpass="$(mktemp)"
	printf '#!/bin/sh\necho %s\n' "$PW_PASS" >"$askpass"
	chmod 0700 "$askpass"
	local code=0
	SSH_ASKPASS="$askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=none \
		ssh "${SSH_COMMON[@]}" -o BatchMode=no -o PubkeyAuthentication=no -o PreferredAuthentications=password \
		-o NumberOfPasswordPrompts=1 -o IdentityAgent=none "$user@127.0.0.1" "$@" </dev/null || code=$?
	rm -f "$askpass"
	return "$code"
}

# key_login USER / password_login USER: yes when a brand new SSH login
# works, no otherwise.
quiet() { "$@" >/dev/null 2>&1; }
key_login() { yn quiet ssh_as "$1" true; }
password_login() { yn quiet as_pw "$1" true; }

expect_key_login() {
	local got
	got="$(key_login "$1")"
	note "$(yn [ "$got" = "$2" ])" "$3" "login=$2" "login=$got" "a new SSH session as $1 with the key"
}

expect_password_login() {
	local got
	got="$(password_login "$PW_USER")"
	note "$(yn [ "$got" = "$1" ])" "$2" "login=$1" "login=$got" "a new SSH session as $PW_USER with the password"
}

# sshd_value KEY: what sshd -T says for KEY in the VM.
sshd_value() { root_cmd "sudo /usr/sbin/sshd -T" | awk -v k="$1" '$1 == k {print $2; exit}'; }

expect_sshd() {
	local got
	got="$(sshd_value "$1")"
	note "$(yn [ "$got" = "$2" ])" "$3" "$1 $2" "$1 ${got:-none}" "sshd -T in the VM"
}

# planned_sshd PLAN: the settings of the sshd-hardening drop-in in PLAN, as
# sshd -T prints them ("key value", lower case).
planned_sshd() {
	jq -r '.steps[] | select(.id == "sshd-hardening") | .edits[0].new // empty' "$OUT/$1.json" |
		grep -Ev '^[[:space:]]*(#|$)' | awk '{print tolower($1), tolower($2)}'
}

# expect_planned_sshd PLAN WHEN: sshd -T shows every setting the plan's
# drop-in sets, and the drop-in turns password login off.
expect_planned_sshd() {
	local k v
	note "$(yn grep -qx 'passwordauthentication no' <<<"$(planned_sshd "$1")")" "the planned drop-in turns password login off" "passwordauthentication no" "$(planned_sshd "$1" | tr '\n' ',')"
	while read -r k v; do
		expect_sshd "$k" "$v" "$2, sshd -T has $k $v"
	done < <(planned_sshd "$1")
}

# The confirm deadline: long enough for the checks made while a
# transaction is open, which take minutes on an emulated VM.
WITHIN=60s
[ "$VM_ACCEL" = tcg ] && WITHIN=240s

# txn FIELD: a field of the transaction state in the VM ("" when unset).
txn() { root_cmd "sudo cat $STATE 2>/dev/null" | jq -r ".$1 // empty" 2>/dev/null || true; }

timer_state() { root_cmd "systemctl is-active stackward-rollback-$1.timer 2>/dev/null" || true; }

boot_units() { root_cmd "ls /etc/systemd/system/ | grep -c '^stackward-boot-rollback-' || true"; }

# http_code: the HTTP status of the VM's test web server on 8090, through
# the forwarded port; 000 when the VM drops or refuses the connection.
http_code() {
	curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://127.0.0.1:$VM_HTTP_PORT/" || true
}

expect_http() {
	local want="$1" what="$2" got
	got=closed
	[ "$(http_code)" = 200 ] && got=open
	note "$(yn [ "$got" = "$want" ])" "$what" "$want" "$got" "tcp/8090 from outside the VM"
}

# ufw_line PATTERN: the first line of ufw status verbose matching PATTERN.
ufw_line() { root_cmd "sudo ufw status verbose" | grep -m1 -E "$1" || true; }

# plan_as USER NAME [ARGS...]: stackward plan in the VM in a new session as USER,
# into $WORK/NAME.json; the plan is copied to $OUT.
plan_as() {
	local user="$1" name="$2"
	shift 2
	log "[$user] sudo stackward plan $* --out $WORK/$name.json"
	ssh_as "$user" "sudo mkdir -p $WORK && sudo stackward plan $* --out $WORK/$name.json" >"$OUT/$name.txt" 2>&1 || true
	cat "$OUT/$name.txt"
	ssh_as "$user" "sudo cat $WORK/$name.json" >"$OUT/$name.json" 2>/dev/null || true
}

# planned PLAN STEP: yes when PLAN holds STEP as a step to apply.
# shellcheck disable=SC2016 # a jq program
planned() { yn quiet jq -e --arg s "$2" 'any(.steps[]; .id == $s)' "$OUT/$1.json"; }

# skipped PLAN STEP: "kind: reason" of STEP in the skipped list.
skipped() { jq -r --arg s "$2" '.skipped[]? | select(.id == $s) | .kind + ": " + .reason' "$OUT/$1.json" 2>/dev/null; }

# apply_as USER NAME ARGS...: stackward apply in a new SSH session as USER;
# output in $OUT/NAME.txt, the exit code in CODE.
apply_as() {
	local user="$1" name="$2"
	shift 2
	CODE=0
	log "[$user] sudo stackward apply $*"
	ssh_as "$user" "sudo stackward apply $*" >"$OUT/$name.txt" 2>&1 || CODE=$?
	cat "$OUT/$name.txt"
}

# confirm_as USER NAME ID: stackward confirm ID in a new SSH session.
confirm_as() {
	CODE=0
	log "[$1] sudo stackward confirm $3"
	ssh_as "$1" "sudo stackward confirm $3" >"$OUT/$2.txt" 2>&1 || CODE=$?
	cat "$OUT/$2.txt"
}

# wait_txn_closed ID: wait until the transaction is no longer open (the
# timer fired), sized for an emulated VM.
wait_txn_closed() {
	local waited=0 limit=$((VM_TIMEOUT / 2 + 60))
	log "waiting for the rollback timer of $1 (deadline $(txn deadline), up to ${limit}s)"
	while [ "$(txn status)" = open ] && [ "$waited" -lt "$limit" ]; do
		sleep 5
		waited=$((waited + 5))
	done
	vm "sudo journalctl -u stackward-rollback-$1.service --no-pager" >"$OUT/rollback-$1.log" 2>&1 || true
	cat "$OUT/rollback-$1.log"
	WAITED=$waited
}

# wait_past_deadline: sleep until 15 seconds after the transaction's
# deadline, measured on the VM's clock.
wait_past_deadline() {
	local left
	left="$(vm "echo \$(( \$(date -d '$(txn deadline)' +%s) - \$(date +%s) ))")"
	[ "$left" -gt 0 ] 2>/dev/null || left=0
	log "waiting $((left + 15))s, past the deadline"
	sleep $((left + 15))
}

# reboot_vm: reboot the VM and wait for a new boot to answer over SSH.
reboot_vm() {
	local before now waited=0
	before="$(vm "cat /proc/sys/kernel/random/boot_id")"
	log "rebooting the VM"
	vm "sudo systemctl reboot" >/dev/null 2>&1 || true
	sleep 10
	while [ "$waited" -lt "$VM_TIMEOUT" ]; do
		now="$(vm "cat /proc/sys/kernel/random/boot_id" 2>/dev/null || true)"
		if [ -n "$now" ] && [ "$now" != "$before" ]; then
			log "back after about $((waited + 10))s"
			return 0
		fi
		sleep 5
		waited=$((waited + 5))
	done
	die "the VM did not come back from the reboot within ${VM_TIMEOUT}s"
}

# prepare_vm: what every scenario starts from. Password login on (as on a
# fresh VPS image, and so sshd-hardening has something to turn off),
# the password only account, and a web server on 8090 that UFW should
# close. All of it lives in the throwaway VM only.
prepare_vm() {
	log "preparing the VM: password login, $PW_USER, a web server on 8090"
	vm "set -e
		printf 'PasswordAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/10-vmtest-password.conf >/dev/null
		sudo systemctl reload ssh.service 2>/dev/null || sudo systemctl restart ssh.service
		id $PW_USER >/dev/null 2>&1 || sudo useradd --create-home --shell /bin/bash $PW_USER
		echo '$PW_USER:$PW_PASS' | sudo chpasswd
		sudo mkdir -p /srv/sw-http && echo ok | sudo tee /srv/sw-http/index.html >/dev/null
		printf '[Unit]\nDescription=stackward VM test web server\n[Service]\nExecStart=/usr/bin/python3 -m http.server 8090 --bind 0.0.0.0 --directory /srv/sw-http\n[Install]\nWantedBy=multi-user.target\n' | sudo tee /etc/systemd/system/sw-http.service >/dev/null
		sudo systemctl daemon-reload
		sudo systemctl enable --now sw-http.service
		sudo ufw status | grep -q 'Status: inactive'
		sudo mkdir -p $WORK"
	local _
	for _ in 1 2 3 4 5 6; do
		[ "$(http_code)" = 200 ] && break
		sleep 2
	done
}

# collect_vm: logs from the VM for the artifact.
collect_vm() {
	root_cmd "sudo journalctl -b --no-pager -u 'stackward-*' -u ssh.service -u ufw.service" >"$OUT/journal.txt" 2>&1 || true
	root_cmd "sudo cat $STATE" >"$OUT/transaction.json" 2>/dev/null || true
	root_cmd "sudo /usr/sbin/sshd -T" >"$OUT/sshd-T.txt" 2>&1 || true
	root_cmd "sudo ufw status verbose" >"$OUT/ufw.txt" 2>&1 || true
}
