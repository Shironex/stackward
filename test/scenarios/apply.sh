# shellcheck shell=bash
# shellcheck disable=SC2024 # outputs are written by this shell, as the caller, so they stay readable
# apply: stackward apply and undo on a real host, the only scenario that
# lets stackward change the machine. It runs on the disposable GitHub
# runner VM; `go test ./...` never touches a host (the unit tests write
# under t.TempDir() and start no program).
#
# Setup makes the three planned steps needed: kernel values off baseline
# (kptr_restrict, accept_redirects), a persistent journal without a size
# cap, and a daemon.json without log rotation. Then:
#
# 1. plan writes plan.json; it must hold sysctl-hardening and
#    docker-log-rotation (journald-cap when the runner's journal allows).
# 2. apply without root is refused and changes nothing.
# 3. apply --all-safe --step docker-log-rotation applies them: the files
#    hold the planned content, daemon.json keeps its mode, FILE.orig and
#    the run backup hold the old content, the journal says ok, the running
#    values changed and Docker is up with json-file rotation. Under /etc
#    nothing changed but the planned files and daemon.json.orig.
# 4. A second apply says nothing to do, writes no new run, changes no file
#    under /etc and does not restart Docker.
# 5. A new audit passes the fixed checks.
# 6. undo --run restores /etc to what it was before apply (FILE.orig
#    stays), the running values and the journal status.

APPLY_SAVE=""
SYSCTL_KEYS="kernel.kptr_restrict net.ipv4.conf.all.accept_redirects"
DAEMON=/etc/docker/daemon.json

scenario_setup() {
	require_docker
	APPLY_SAVE="$OUT/apply-saved"
	mkdir -p "$APPLY_SAVE"
	local k
	for k in $SYSCTL_KEYS; do
		sysctl -n "$k" >"$APPLY_SAVE/$k"
	done
	if sudo test -e "$DAEMON"; then
		sudo cat "$DAEMON" >"$APPLY_SAVE/daemon.json"
	fi
	sudo sysctl -w kernel.kptr_restrict=0 net.ipv4.conf.all.accept_redirects=1 >/dev/null
	# daemon.json without log settings, every other key kept.
	local base='{}'
	[ -f "$APPLY_SAVE/daemon.json" ] && base="$(cat "$APPLY_SAVE/daemon.json")"
	printf '%s\n' "$base" | jq 'del(."log-driver", ."log-opts")' | sudo tee "$DAEMON" >/dev/null
	sudo chmod 0640 "$DAEMON"
	# A persistent journal, so journald-cap applies.
	sudo mkdir -p /var/log/journal
	sudo systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
	sudo systemctl restart systemd-journald
}

# etc_hashes prints "sha256  path" for every regular file under /etc.
etc_hashes() {
	sudo find /etc -xdev -type f -print0 | sudo xargs -0 -r sha256sum | LC_ALL=C sort -k2
}

# planned FIELD PATH prints old_sha256 or new_sha256 of PATH in the plan.
planned() {
	sudo jq -r --arg p "$2" ".steps[].edits[] | select(.path == \$p) | .$1" "$OUT/plan.json"
}

file_sha() { sudo sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# yn CMD...: print yes when CMD succeeds, no otherwise.
yn() {
	if "$@"; then echo yes; else echo no; fi
}

scenario_verify() {
	local plan="$OUT/plan.json" code out id steps paths
	log "sudo stackward plan --out $plan"
	sudo "$STACKWARD" plan --out "$plan" >"$OUT/plan.txt"
	# --out is created 0600 by root; the artifact upload reads it as the runner.
	sudo chmod 0644 "$plan"
	steps="$(sudo jq -r '[.steps[].id] | join(",")' "$plan")"
	note "$(yn grep -Eq '(^|,)sysctl-hardening,(.*,)?docker-log-rotation(,|$)' <<<"$steps")" \
		"plan holds sysctl-hardening and docker-log-rotation" "both" "$steps"
	# The steps this scenario applies: access-critical ones (the sshd
	# drop-in on a runner with password login) run only in a transaction.
	paths="$(sudo jq -r '.steps[] | select(.risk != "access-critical") | .edits[].path' "$plan")"

	etc_hashes >"$OUT/etc.before"

	# 2. No root, no change.
	code=0
	out="$("$STACKWARD" apply --all-safe --yes "$plan" 2>&1)" || code=$?
	note "$(yn [ "$code" -eq 2 ])" "apply without root exit code" 2 "$code"
	note "$(yn grep -q 'needs root' <<<"$out")" "apply without root says why" "needs root" "$(printf '%s' "$out" | head -1)"

	# 3. Apply.
	local docker_mode_before
	docker_mode_before="$(sudo stat -c %a "$DAEMON")"
	code=0
	log "sudo stackward apply --all-safe --step docker-log-rotation --yes $plan"
	sudo "$STACKWARD" apply --all-safe --step docker-log-rotation --yes "$plan" >"$OUT/apply-1.txt" 2>&1 || code=$?
	cat "$OUT/apply-1.txt"
	note "$(yn [ "$code" -eq 0 ])" "apply exit code" 0 "$code"
	id="$(sed -n 's/^run: *\([0-9TZ]*-[0-9a-f]*\) .*/\1/p' "$OUT/apply-1.txt")"
	note "$(yn [ -n "$id" ])" "apply prints the run id" "a run id" "${id:-none}"
	local journal="/var/backups/stackward/$id/journal.json"
	sudo cp "$journal" "$OUT/journal-1.json" 2>/dev/null || true
	sudo chmod a+r "$OUT/journal-1.json" 2>/dev/null || true
	note "$(yn [ "$(sudo jq -r .status "$journal")" = ok ])" "journal status" ok "$(sudo jq -r .status "$journal" 2>/dev/null)"
	note "$(yn [ "$(sudo stat -c %a "$journal")" = 600 ])" "journal mode" 600 "$(sudo stat -c %a "$journal")"
	local p
	for p in $paths; do
		note "$(yn [ "$(file_sha "$p")" = "$(planned new_sha256 "$p")" ])" "$p holds the planned content" "$(planned new_sha256 "$p" | cut -c1-12)" "$(file_sha "$p" | cut -c1-12)"
	done
	local old
	old="$(planned old_sha256 "$DAEMON")"
	note "$(yn [ "$(file_sha "$DAEMON.orig")" = "$old" ])" "daemon.json.orig holds the old content" "${old:0:12}" "$(file_sha "$DAEMON.orig" | cut -c1-12)"
	note "$(yn [ "$(file_sha "/var/backups/stackward/$id$DAEMON")" = "$old" ])" "the run backup holds the old daemon.json" "${old:0:12}" "$(file_sha "/var/backups/stackward/$id$DAEMON" | cut -c1-12)"
	note "$(yn [ "$(sudo stat -c %a "$DAEMON")" = "$docker_mode_before" ])" "daemon.json keeps its mode" "$docker_mode_before" "$(sudo stat -c %a "$DAEMON")"
	note "$(yn [ "$(sysctl -n kernel.kptr_restrict)" = 1 ])" "running kptr_restrict" 1 "$(sysctl -n kernel.kptr_restrict)"
	note "$(yn sudo systemctl is-active --quiet docker)" "docker is active after the restart" active "$(sudo systemctl is-active docker)"
	note "$(yn [ "$(sudo docker info --format '{{.LoggingDriver}}')" = json-file ])" "docker logging driver" json-file "$(sudo docker info --format '{{.LoggingDriver}}')"

	etc_hashes >"$OUT/etc.after"
	# Only the planned files and daemon.json.orig may differ.
	local allowed stray
	# shellcheck disable=SC2086 # one path per word
	allowed="$(printf '%s\n' $paths "$DAEMON.orig" | LC_ALL=C sort -u)"
	stray="$({ diff "$OUT/etc.before" "$OUT/etc.after" || true; } | sed -n 's/^[<>] [0-9a-f]*  //p' | LC_ALL=C sort -u | comm -23 - <(printf '%s\n' "$allowed"))"
	note "$(yn [ -z "$stray" ])" "apply changed nothing under /etc outside the plan" "none" "${stray:-none}"

	# 4. Second run: nothing to do.
	local runs_before runs_after restarted_before restarted_after
	runs_before="$(sudo ls /var/backups/stackward | wc -l)"
	restarted_before="$(sudo systemctl show docker -p ActiveEnterTimestampMonotonic --value)"
	code=0
	sudo "$STACKWARD" apply --all-safe --step docker-log-rotation --yes "$plan" >"$OUT/apply-2.txt" 2>&1 || code=$?
	cat "$OUT/apply-2.txt"
	note "$(yn [ "$code" -eq 0 ])" "second apply exit code" 0 "$code"
	note "$(yn grep -q 'nothing to do' "$OUT/apply-2.txt")" "second apply says nothing to do" "nothing to do" "$(tail -1 "$OUT/apply-2.txt")"
	runs_after="$(sudo ls /var/backups/stackward | wc -l)"
	note "$(yn [ "$runs_before" = "$runs_after" ])" "second apply writes no new run" "$runs_before" "$runs_after"
	restarted_after="$(sudo systemctl show docker -p ActiveEnterTimestampMonotonic --value)"
	note "$(yn [ "$restarted_before" = "$restarted_after" ])" "second apply does not restart docker" "$restarted_before" "$restarted_after"
	etc_hashes >"$OUT/etc.after2"
	note "$(yn cmp -s "$OUT/etc.after" "$OUT/etc.after2")" "second apply changes nothing under /etc" "no diff" "$(diff "$OUT/etc.after" "$OUT/etc.after2" | head -3 | tr '\n' ' ')"

	# 5. The fixed checks pass now.
	audit apply-after
	expect none "$REPORT" 'warn|fail' DKR-031 KRN-004

	# 6. Undo.
	code=0
	log "sudo stackward undo --run $id --yes"
	sudo "$STACKWARD" undo --run "$id" --yes >"$OUT/undo.txt" 2>&1 || code=$?
	cat "$OUT/undo.txt"
	note "$(yn [ "$code" -eq 0 ])" "undo exit code" 0 "$code"
	note "$(yn [ "$(sudo jq -r .status "$journal")" = undone ])" "journal status after undo" undone "$(sudo jq -r .status "$journal")"
	etc_hashes | grep -v "  $DAEMON.orig\$" >"$OUT/etc.undone"
	note "$(yn cmp -s "$OUT/etc.before" "$OUT/etc.undone")" "undo restores /etc (FILE.orig kept)" "no diff" "$(diff "$OUT/etc.before" "$OUT/etc.undone" | head -3 | tr '\n' ' ')"
	note "$(yn sudo test -e "$DAEMON.orig")" "undo keeps daemon.json.orig" kept "$(sudo test -e "$DAEMON.orig" && echo kept || echo gone)"
	note "$(yn [ "$(sysctl -n kernel.kptr_restrict)" = 0 ])" "undo restores the running kptr_restrict" 0 "$(sysctl -n kernel.kptr_restrict)"
	note "$(yn sudo systemctl is-active --quiet docker)" "docker is active after undo" active "$(sudo systemctl is-active docker)"
}

scenario_cleanup() {
	[ -n "$APPLY_SAVE" ] || return 0
	local k
	for k in $SYSCTL_KEYS; do
		if [ -f "$APPLY_SAVE/$k" ]; then
			sudo sysctl -w "$k=$(cat "$APPLY_SAVE/$k")" >/dev/null || true
		fi
	done
	sudo rm -f /etc/systemd/journald.conf.d/90-stackward-journal-cap.conf /etc/sysctl.d/90-stackward-hardening.conf "$DAEMON.orig"
	if [ -f "$APPLY_SAVE/daemon.json" ]; then
		sudo cp "$APPLY_SAVE/daemon.json" "$DAEMON"
	else
		sudo rm -f "$DAEMON"
	fi
	sudo systemctl restart docker || true
	sudo systemctl restart systemd-journald || true
}
